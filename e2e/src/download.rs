/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::{HashMap, VecDeque},
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc,
    },
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::stream::PSeekFile;
use serde::{Deserialize, Serialize};

/// Minimum download chunk size per task.
const MIN_CHUNK_SIZE: u64 = 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(5);

pub trait ProgressDisplay {
    fn progress(&mut self, current: u64, total: u64);

    fn error(&mut self, msg: &str);

    fn finish(&mut self);
}

pub struct BasicProgressDisplay {
    current: u64,
    total: u64,
    interval: Duration,
    last_render: Instant,
    avg: VecDeque<(Instant, u64)>,
}

// Speed is a simple moving average over 5 seconds.
static AVG_INTERVAL: Duration = Duration::from_millis(100);
static AVG_WINDOW_SIZE: usize = 5000 / AVG_INTERVAL.as_millis() as usize;

impl BasicProgressDisplay {
    pub fn new(interval: Duration) -> Self {
        Self {
            current: 0,
            total: 0,
            interval,
            last_render: Instant::now() - interval,
            avg: VecDeque::new(),
        }
    }

    fn clear_line(&self) {
        eprint!("\x1b[2K\r");
    }
}

impl ProgressDisplay for BasicProgressDisplay {
    fn progress(&mut self, current: u64, total: u64) {
        self.current = current;
        self.total = total;

        let now = Instant::now();

        if self.avg.is_empty() || (now - self.avg.back().unwrap().0) > AVG_INTERVAL {
            if self.avg.len() == AVG_WINDOW_SIZE {
                self.avg.pop_front();
            }

            self.avg.push_back((now, current));
        }

        if now - self.last_render > self.interval {
            let current_mib = current as f64 / 1024.0 / 1024.0;
            let total_mib = total as f64 / 1024.0 / 1024.0;

            let front = self.avg.front().unwrap();
            let back = self.avg.back().unwrap();

            let avg_window_mib = (back.1 - front.1) as f64 / 1024.0 / 1024.0;
            let avg_window_duration = back.0 - front.0;

            let speed_mib_s = if avg_window_duration.is_zero() {
                0.0
            } else {
                avg_window_mib / avg_window_duration.as_secs_f64()
            };

            self.clear_line();
            eprint!("{current_mib:.1} / {total_mib:.1} MiB ({speed_mib_s:.1} MiB/s)");

            self.last_render = now;
        }
    }

    fn error(&mut self, msg: &str) {
        self.clear_line();
        eprintln!("{msg}");
    }

    fn finish(&mut self) {
        self.clear_line();
    }
}

#[derive(Debug)]
enum MessageData {
    Progress {
        bytes: u64,
        // Controller replies with a new ending offset.
        resp: Sender<u64>,
    },
    Completion {
        result: Result<()>,
    },
}

#[derive(Debug)]
struct Message {
    id: ThreadId,
    data: MessageData,
}

/// Download a contiguous byte range. The number of bytes downloaded per loop
/// iteration will be sent to the specified channel via a `ProgressMessage`. The
/// receiver of the message must reply with the new ending offset for this
/// download via the oneshot channel in the `resp` field. An appropriate error
/// will be returned if the full range (subject to modification) cannot be fully
/// downloaded (eg. premature EOF is an error).
fn download_range(
    url: &str,
    mut file: PSeekFile,
    initial_range: Range<u64>,
    channel: Sender<Message>,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    assert!(initial_range.start < initial_range.end);

    let mut response = attohttpc::get(url)
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .header(
            "Range",
            &format!("bytes={}-{}", initial_range.start, initial_range.end - 1),
        )
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("Failed to start download for range: {initial_range:?}"))?;

    let mut range = initial_range.clone();
    let mut buf = [0u8; 65536];

    while range.start < range.end {
        if cancel_signal.load(Ordering::SeqCst) {
            bail!("Received cancel signal");
        }

        let to_read = (range.end - range.start).min(buf.len() as u64) as usize;
        let n = response.read(&mut buf[..to_read]).with_context(|| {
            format!(
                "Failed to download {to_read} bytes at offset {}",
                range.start,
            )
        })?;
        if n == 0 {
            bail!("Unexpected EOF from server");
        }

        // This may overlap with another task's write when a range split occurs,
        // but the same data will be written anyway, so it's not a huge deal.
        file.seek(SeekFrom::Start(range.start))?;
        file.write_all(&buf[..n]).with_context(|| {
            format!(
                "Failed to write {n} bytes to output file at offset {}",
                range.start,
            )
        })?;

        range.start += n as u64;

        // Report progress to the controller.
        let (tx, rx) = mpsc::channel();
        let msg = Message {
            id: thread::current().id(),
            data: MessageData::Progress {
                bytes: n as u64,
                resp: tx,
            },
        };
        channel.send(msg)?;

        // Get new ending offset from controller.
        let new_end = rx.recv()?;
        if new_end != range.end {
            debug_assert!(new_end <= range.end);
            range.end = new_end;
        }
    }

    Ok(())
}

/// This just calls [`download_range()`] and sends a completion message to the
/// channel with the result.
fn download_thread(
    url: &str,
    file: PSeekFile,
    initial_range: Range<u64>,
    channel: mpsc::Sender<Message>,
    cancel_signal: &Arc<AtomicBool>,
) {
    let result = download_range(url, file, initial_range, channel.clone(), cancel_signal);

    channel
        .send(Message {
            id: thread::current().id(),
            data: MessageData::Completion { result },
        })
        .unwrap();
}

/// Send a HEAD request to get the value of the Content-Length header.
fn get_content_length(url: &str) -> Result<u64> {
    let response = attohttpc::head(url)
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .send()
        .and_then(|r| r.error_for_status())
        .context("Failed to send HEAD request to get Content-Length")?;

    response
        .headers()
        .get("Content-Length")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| anyhow!("HEAD request did not return a valid Content-Length"))
}

/// Download a set of file chunks in parallel. Only unrecoverable errors are
/// returned as an Err. Normal/expected errors and download progress info are
/// reported via `display`. Returns the remaining ranges that need to be
/// downloaded.
fn download_ranges(
    url: &str,
    output: &Path,
    initial_ranges: Option<&[Range<u64>]>,
    display: &mut dyn ProgressDisplay,
    max_threads: usize,
    max_errors: u8,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<Vec<Range<u64>>> {
    let file_size = get_content_length(url)?;

    // Open for writing, but without truncation.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for writing: {output:?}"))?;

    file.set_len(file_size)
        .with_context(|| format!("Failed to set file size: {output:?}"))?;

    // Queue of ranges that need to be downloaded.
    let mut remaining = VecDeque::from(match initial_ranges {
        Some(r) => r.to_vec(),
        #[allow(clippy::single_range_in_vec_init)]
        None => vec![0..file_size],
    });
    // Ranges that have failed.
    let mut failed = Vec::<Range<u64>>::new();
    // Ranges for currently running threads.
    let mut thread_ranges = HashMap::<ThreadId, Range<u64>>::new();

    // Overall progress.
    let mut progress = file_size - remaining.iter().map(|r| r.end - r.start).sum::<u64>();
    display.progress(progress, file_size);

    thread::scope(|scope| {
        let mut threads = HashMap::new();
        let mut error_count = 0u8;
        // Progress messages from threads.
        let (tx, rx) = mpsc::channel();

        loop {
            // Spawn new threads.
            while !cancel_signal.load(Ordering::SeqCst) && threads.len() < max_threads {
                if remaining.is_empty() && !threads.is_empty() {
                    // No more ranges to download. Split another thread's range.
                    let (_, old_range) = thread_ranges
                        .iter_mut()
                        .max_by_key(|(_, r)| r.end - r.start)
                        .unwrap();
                    let size = old_range.end - old_range.start;

                    if size >= MIN_CHUNK_SIZE {
                        let new_range = old_range.start + size / 2..old_range.end;
                        old_range.end = new_range.start;
                        remaining.push_back(new_range);
                    }
                }

                if let Some(thread_range) = remaining.pop_front() {
                    let file_cloned = file.clone();
                    let thread_range_cloned = thread_range.clone();
                    let tx_cloned = tx.clone();

                    let join_handle = scope.spawn(|| {
                        download_thread(
                            url,
                            file_cloned,
                            thread_range_cloned,
                            tx_cloned,
                            cancel_signal,
                        )
                    });

                    thread_ranges.insert(join_handle.thread().id(), thread_range);
                    threads.insert(join_handle.thread().id(), join_handle);
                } else {
                    // No pending ranges and no running threads can be split.
                    break;
                }
            }

            if threads.is_empty() {
                // Nothing left to do.
                break;
            }

            let Message { id, data } = rx.recv().unwrap();

            match data {
                MessageData::Progress { bytes, resp } => {
                    progress += bytes;
                    display.progress(progress, file_size);

                    let thread_range = thread_ranges.get_mut(&id).unwrap();
                    thread_range.start += bytes;

                    resp.send(thread_range.end).unwrap();
                }
                MessageData::Completion { result } => {
                    threads.remove(&id).unwrap().join().unwrap();

                    let thread_range = thread_ranges.remove(&id).unwrap();

                    if let Err(e) = result {
                        display.error(&format!("[{id:?}] {e:?}"));
                        error_count += 1;

                        if error_count < max_errors {
                            remaining.push_back(thread_range);
                        } else {
                            failed.push(thread_range);
                        }
                    }
                }
            }
        }
    });

    display.finish();

    failed.extend(remaining);
    failed.extend(thread_ranges.into_values());

    Ok(failed)
}

#[derive(Serialize, Deserialize)]
struct State {
    ranges: Vec<Range<u64>>,
}

fn read_state(path: &Path) -> Result<Option<State>> {
    let data = match fs::read_to_string(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read download state: {path:?}"))?,
    };

    let state = toml_edit::de::from_str(&data)
        .with_context(|| format!("Failed to parse download state: {path:?}"))?;

    Ok(Some(state))
}

fn write_state(path: &Path, state: &State) -> Result<()> {
    let data = toml_edit::ser::to_string(state).unwrap();

    fs::write(path, data).with_context(|| format!("Failed to write download state: {path:?}"))?;

    Ok(())
}

fn delete_if_exists(path: &Path) -> Result<()> {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e).context(format!("Failed to delete file: {path:?}"));
        }
    }

    Ok(())
}

pub fn state_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".state");
    PathBuf::from(s)
}

/// Download `url` to `output` with parallel threads.
///
/// If `initial_ranges` is specified, only those sections of the file will be
/// downloaded. The empty regions are left untouched (i.e. filled with zeroes).
/// A `.state` file is written if the download is interrupted. If the state
/// file exists when this function is called, `initial_ranges` is ignored and
/// the ranges from the state file are used to resume the download.
pub fn download(
    url: &str,
    output: &Path,
    initial_ranges: Option<&[Range<u64>]>,
    display: &mut dyn ProgressDisplay,
    max_tasks: usize,
    max_errors: u8,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let state_path = state_path(output);
    let ranges = match read_state(&state_path)? {
        Some(r) => Some(r.ranges),
        None => initial_ranges.map(|r| r.to_vec()),
    };

    let remaining = download_ranges(
        url,
        output,
        ranges.as_deref(),
        display,
        max_tasks,
        max_errors,
        cancel_signal,
    )?;

    if remaining.is_empty() {
        delete_if_exists(&state_path)?;
    } else {
        write_state(&state_path, &State { ranges: remaining })?;
        bail!("Download was interrupted");
    }

    Ok(())
}
