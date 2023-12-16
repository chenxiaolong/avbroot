/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef DEBUG_PREFIX
#define DEBUG_PREFIX        ""
#endif

#define AVBROOT_DIR         DEBUG_PREFIX "/avbroot"
#define DEV_DIR             DEBUG_PREFIX "/dev"
#define SAFE_DIR            DEBUG_PREFIX "/acct"
#define STAGE1_DIR          DEBUG_PREFIX "/first_stage_ramdisk"

#define DEV_KMSG            DEV_DIR "/kmsg"
#define DEV_NULL            DEV_DIR "/null"

#define INIT                DEBUG_PREFIX "/init"
#define INIT_ORIG           AVBROOT_DIR "/init.orig"

#define OTACERTS            DEBUG_PREFIX "/system/etc/security/otacerts.zip"
#define OTACERTS_AVBROOT    AVBROOT_DIR "/otacerts.zip"
#define OTACERTS_TMPFS      SAFE_DIR "/otacerts.zip"

#define LOG(level, fmt, ...) \
    fprintf(stderr, "<%d>[%d] " fmt, level, getpid(), ##__VA_ARGS__)
#define LOGE(...)      LOG(3, __VA_ARGS__)
#define LOGI(...)      LOG(6, __VA_ARGS__)

// Best effort attempt to output to the kernel log.
static void prepare_output()
{
    mknod(DEV_NULL, S_IFCHR | 0666, makedev(1, 3));
    mknod(DEV_KMSG, S_IFCHR | 0600, makedev(1, 11));

    int fd = open(DEV_NULL, O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        close(fd);
    }

    fd = open(DEV_KMSG, O_WRONLY);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    unlink(DEV_NULL);
    unlink(DEV_KMSG);

    setlinebuf(stdout);
}

static void auto_close(int *fd)
{
    if (*fd >= 0) {
        int saved_errno = errno;
        close(*fd);
        errno = saved_errno;
    }
}

static int copy_file(const char *source, const char *target)
{
    __attribute__((cleanup(auto_close))) int fd_source =
        open(source, O_RDONLY | O_CLOEXEC);
    if (fd_source < 0) {
        LOGE("%s: Failed to open file: %s\n", source, strerror(errno));
        return -1;
    }

    struct stat sb;
    if (fstat(fd_source, &sb) < 0) {
        LOGE("%s: Failed to stat file: %s\n", source, strerror(errno));
        return -1;
    }

    __attribute__((cleanup(auto_close))) int fd_target =
        open(target, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
             sb.st_mode & ~S_IFMT);
    if (fd_target < 0) {
        LOGE("%s: Failed to open file: %s\n", target, strerror(errno));
        return -1;
    }

    uint64_t remain = sb.st_size;

    while (remain > 0) {
        size_t to_copy = remain > 0x7ffff000 ? 0x7ffff000 : remain;

        ssize_t n = sendfile(fd_target, fd_source, NULL, to_copy);
        if (n < 0) {
            LOGE("%s -> %s: Failed to copy data: %s\n",
                 source, target, strerror(errno));
            return -1;
        }

        remain -= n;
    }

    return 0;
}

// Mount a tmpfs at SAFE_DIR and copy the files we need to it. AOSP init will
// preserve mount points when switching roots (first /first_stage_ramdisk and
// then the system partition), so we'll be able to access the files during the
// stage 1 -> stage 2 transition. The safe directory must be a directory that
// exists in the system partition and is unused for stage 1 init.
static int prepare_safe_dir()
{
    int flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;

    if (mount("avbroot", SAFE_DIR, "tmpfs", flags, "mode=755") < 0) {
        LOGE("%s: Failed to mount tmpfs: %s\n", SAFE_DIR, strerror(errno));
        return -1;
    }

    if (copy_file(OTACERTS_AVBROOT, OTACERTS_TMPFS) < 0) {
        return -1;
    }

    if (mount(NULL, SAFE_DIR, NULL, MS_REMOUNT | MS_RDONLY | flags, NULL) < 0) {
        LOGE("%s: Failed to remount read-only: %s\n",
             SAFE_DIR, strerror(errno));
        return -1;
    }

    return 0;
}

// Trace the parent process across execve() calls until otacerts.zip exists.
// Then, bind mount the replacement and detach. Only the parent (TID 1) needs to
// be traced. All other threads and child processes are irrelevant since we only
// care about the transition point between stage 1 and stage 2 init.
static int trace_parent()
{
    bool first_group_stop = true;

    pid_t parent_pid = getppid();
    LOGI("Tracing parent PID: %d\n", parent_pid);

    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;

    if (ptrace(PTRACE_SEIZE, parent_pid, NULL, options) < 0) {
        LOGE("Failed to trace process: %s\n", strerror(errno));
        return -1;
    }

    while (1) {
        int status;
        if (waitpid(parent_pid, &status, __WALL | __WNOTHREAD) == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                LOGE("waitpid failed: %s\n", strerror(errno));
                return -1;
            }
        }

#ifdef __GLIBC__
        enum __ptrace_request
#else
        int
#endif
        action = PTRACE_CONT;
        int forward_signal = 0;

        if (WIFEXITED(status)) {
            LOGE("%d exited with status %d\n", parent_pid, WEXITSTATUS(status));
            break;
        } else if (WIFSIGNALED(status)) {
            LOGE("%d killed by signal %d\n", parent_pid, WTERMSIG(status));
            break;
        } else if (WIFSTOPPED(status)) {
            int ptrace_event = status >> 16;
            int signal = WSTOPSIG(status);

            switch (ptrace_event) {
                case PTRACE_EVENT_EXEC: {
                    LOGI("Tracee is about to exec\n");

                    // If /first_stage_ramdisk exists, then init hasn't switched
                    // roots yet. otacerts.zip may still exist on devices that
                    // use shared ramdisks for normal and recovery boot.
                    if ((access(STAGE1_DIR, F_OK) != 0 && errno == ENOENT)
                            && access(OTACERTS, F_OK) == 0) {
                        LOGI("Conditions satisfied; applying override\n");

                        action = PTRACE_DETACH;

                        if (mount(OTACERTS_TMPFS, OTACERTS, NULL,
                                  MS_BIND | MS_RDONLY, "") < 0) {
                            LOGE("Failed to bind mount %s -> %s: %s\n",
                                 OTACERTS_TMPFS, OTACERTS, strerror(errno));
                            return -1;
                        }

                        if (umount2(SAFE_DIR, MNT_DETACH) < 0) {
                            LOGE("Failed to detach mount %s: %s\n",
                                 SAFE_DIR, strerror(errno));
                            return -1;
                        }
                    } else {
                        LOGE("Conditions not yet satisfied\n");
                    }

                    break;
                }

                case PTRACE_EVENT_STOP: {
                    if (signal == SIGSTOP || signal == SIGTSTP
                            || signal == SIGTTIN || signal == SIGTTOU) {
                        if (first_group_stop) {
                            LOGI("Resuming tracee\n");
                            kill(parent_pid, SIGCONT);
                            first_group_stop = false;
                        } else {
                            action = PTRACE_LISTEN;
                        }
                    } else {
                        // We get spurious SIGTRAP signals when SIGCONT'ing a
                        // process. rr seem to be running into this as well:
                        // https://github.com/mozilla/rr/issues/2095
                        // strace handles PTRACE_EVENT_STOP + non-group-stop signal
                        // by restarting the process with PTRACE_SYSCALL:
                        // https://github.com/strace/strace/blob/b1e1eb7731e50900bb4591a3a71b96ab37e106a8/strace.c#L2360
                        // https://github.com/strace/strace/blob/b1e1eb7731e50900bb4591a3a71b96ab37e106a8/strace.c#L2408-L2409
                    }

                    break;
                }

                default: {
                    if (signal == (SIGTRAP | 0x80)) {
                        // Syscall enter/exit stop
                    } else {
                        // Signal delivery stop
                        forward_signal = signal;
                    }

                    break;
                }
            }

            if (ptrace(action, parent_pid, NULL, forward_signal) < 0) {
                LOGE("Failed to perform action %d (signal %d): %s\n",
                     action, forward_signal, strerror(errno));
                return -1;
            }

            if (action == PTRACE_DETACH) {
                LOGI("Detaching tracee\n");
                break;
            }
        } else {
            LOGE("Invalid waitpid status: 0x%x\n", status);
        }
    }

    return 0;
}

static int prepare_tracing()
{
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("Failed to fork: %s\n", strerror(errno));
        return -1;
    } else if (pid == 0) {
        int ret = trace_parent();
        if (ret < 0) {
            // Make sure parent doesn't hang forever.
            kill(getppid(), SIGCONT);
            _exit(EXIT_FAILURE);
        }

        _exit(EXIT_SUCCESS);
    } else {
        LOGI("Waiting for tracer to be ready\n");
        kill(getpid(), SIGSTOP);
        LOGI("Tracer is ready\n");
    }

    return 0;
}

int main(int argc, char *argv[], char *envp[])
{
    (void) argc;

    prepare_output();

    if (rename(INIT_ORIG, INIT) < 0) {
        LOGE("Failed to restore original init: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (prepare_safe_dir() < 0) {
        LOGE("Failed to set up safe directory %s\n", SAFE_DIR);
    } else if (prepare_tracing() < 0) {
        LOGE("Failed to set up tracer child process\n");
    } else {
        LOGI("Exec hook is ready\n");
    }

    LOGI("Executing %s\n", INIT);

    execve(INIT, argv, envp);
    LOGE("Failed to exec %s: %s\n", INIT, strerror(errno));
    return EXIT_FAILURE;
}
