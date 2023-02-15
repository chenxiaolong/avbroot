#!/usr/bin/env python3

import argparse
import collections
import os
import queue
import subprocess
import sys
import threading


def build_cmd(image_name, tag, container_file, rebuild=False):
    full_image = f'{image_name}:{tag}'

    if not rebuild and \
            subprocess.call(['podman', 'image', 'exists', full_image]) == 0:
        return None

    return [
        'podman',
        'build',
        '--pull',
        '-t', full_image,
        '-f', container_file,
        os.path.dirname(container_file),
    ]


def test_cmd(image_name, tag, extra_args=[], default_args=True, network=False):
    full_image = f'{image_name}:{tag}'
    project_dir = os.path.realpath(os.path.join(sys.path[0], '..'))

    network_args = ['--network', 'none'] if network else []
    test_args = extra_args.copy()
    if default_args:
        test_args.append('--delete-on-success')
        test_args.append('--output-file-suffix')
        test_args.append(f'.{tag}')

    return [
        'podman',
        'run',
        '--rm',
        '-e', 'PYTHONUNBUFFERED=1',
        # Only make the files directory writable so the multiple Python
        # versions running concurrently won't clobber each other's compiled
        # bytecode files
        '-v', f'{project_dir}:/mnt:ro,z',
        '-v', f'{project_dir}/tests/files:/mnt/tests/files:z',
        *network_args,
        full_image,
        '/mnt/tests/tests.py',
        *test_args,
    ]


class PrefixedOutputThread(threading.Thread):
    def __init__(self, input, name, is_error):
        super().__init__()

        out_type = 'err' if is_error else 'out'

        self.input = input
        self.prefix = f'[{name}::{out_type}] '.encode('UTF-8')
        self.output = sys.stderr.buffer if is_error else sys.stdout.buffer

    def run(self):
        for line in self.input:
            self.output.write(self.prefix)
            self.output.write(line)
            if not line or line[-1] != ord(b'\n'):
                self.output.write(b'\n')
            self.output.flush()


class CompletionThread(threading.Thread):
    def __init__(self, process, name, queue):
        super().__init__()

        self.process = process
        self.name = name
        self.queue = queue

    def run(self):
        try:
            self.process.wait()
        finally:
            self.queue.put(self.name)


class Job:
    def __init__(self, cmd, name, completion_queue):
        print(f'Running job {name!r} with command {cmd!r}')

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.stdout_thread = PrefixedOutputThread(
            self.process.stdout, name, False)
        self.stderr_thread = PrefixedOutputThread(
            self.process.stderr, name, True)
        self.completion_thread = CompletionThread(
            self.process, name, completion_queue)

        self.stdout_thread.start()
        self.stderr_thread.start()
        self.completion_thread.start()

    def kill(self):
        self.process.kill()

    def wait(self):
        self.process.wait()
        self.stdout_thread.join()
        self.stderr_thread.join()
        self.completion_thread.join()

        return self.process.returncode


def run_jobs(name_to_cmd, max_jobs):
    results = {n: None for n in name_to_cmd}
    job_queue = collections.deque(name_to_cmd.items())
    jobs = {}
    completion_queue = queue.Queue()

    try:
        while job_queue or jobs:
            # Dispatch new jobs up to the job limit
            while job_queue and len(jobs) < max_jobs:
                name, cmd = job_queue.popleft()
                job = Job(cmd, name, completion_queue)
                jobs[name] = job

            # Wait for child process to complete
            name = completion_queue.get()
            job = jobs.pop(name)
            results[name] = job.wait()
    except:
        for _, job in jobs.items():
            job.kill()
        raise
    finally:
        for name, job in jobs.items():
            results[name] = job.wait()

        failed = 0

        if name_to_cmd:
            max_name_len = max(len(n) for n in name_to_cmd)

            print('Results:')
            for name, status in sorted(results.items()):
                print(f'- {name:<{max_name_len}}: ', end='')

                if status is None:
                    failed += 1
                    print('Not started')
                elif status != 0:
                    failed += 1
                    print(f'Failed with status: {status}')
                else:
                    print('Succeeded')

    if failed != 0:
        raise Exception(f'{failed} job(s) failed')


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('test_arg', nargs='*',
                        help='Argument to pass to tests.py')
    parser.add_argument('-d', '--distro', default=[], action='append',
                        help='Distro container image to run tests in')
    parser.add_argument('-j', '--jobs', type=int, default=os.cpu_count() or 1,
                        help='Number of jobs to run concurrently')
    parser.add_argument('--image-prefix', default='avbroot-tests',
                        help='Image name prefix (without tag)')
    parser.add_argument('--rebuild', action='store_true',
                        help='Rebuild images even if they exist')

    args = parser.parse_args()

    if args.image_prefix and ':' in args.image_prefix:
        parser.error('--image-prefix should not contain a tag')

    return args


def main():
    args = parse_args()

    distros_dir = os.path.join(sys.path[0], 'distros')
    distros = set(f.removeprefix('Containerfile.')
                  for f in os.listdir(distros_dir)
                  if f.startswith('Containerfile.'))

    if args.distro:
        selected_distros = set(args.distro)
        invalid = selected_distros - distros
        if invalid:
            raise ValueError(f'Invalid distros: {sorted(invalid)}')

        distros = selected_distros

    # Podman image build jobs
    build_cmds = {}
    for d in distros:
        cmd = build_cmd(
            args.image_prefix,
            d,
            os.path.join(distros_dir, f'Containerfile.{d}'),
            rebuild=args.rebuild,
        )
        if cmd:
            build_cmds[d] = cmd

    # Job to pre-download OTAs
    download_cmds = {
        'download': test_cmd(
            args.image_prefix,
            # Doesn't matter which distro image we use to download
            next(iter(distros)),
            extra_args=['--download-only'],
            default_args=False,
            network=True,
        ),
    }

    # Test runner jobs
    test_cmds = {}
    for d in distros:
        test_cmds[d] = test_cmd(
            args.image_prefix,
            d,
            extra_args=args.test_arg,
        )

    # Let it rip!
    run_jobs(build_cmds, args.jobs)
    run_jobs(download_cmds, 1)
    run_jobs(test_cmds, args.jobs)


if __name__ == '__main__':
    main()
