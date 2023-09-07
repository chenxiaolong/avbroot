/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    cmp,
    collections::{HashMap, VecDeque},
    fs::{self, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::stream::PSeekFile;
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::Runtime,
    signal::ctrl_c,
    sync::{mpsc, oneshot},
    task::{self, JoinSet},
};
use tokio_stream::StreamExt;

/// Minimum download chunk size per task.
const MIN_CHUNK_SIZE: u64 = 1024 * 1024;

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
struct ProgressMessage {
    task_id: u64,
    bytes: u64,
    // Controller replies with new ending offset
    resp: oneshot::Sender<u64>,
}

/// Download a contiguous byte range. The number of bytes downloaded per loop
/// iteration will be sent to the specified channel via a `ProgressMessage`. The
/// receiver of the message must reply with the new ending offset for this
/// download via the oneshot channel in the `resp` field. An appropriate error
/// will be returned if the full range (subject to modification) cannot be fully
/// downloaded (eg. premature EOF is an error).
async fn download_range(
    task_id: u64,
    url: &str,
    mut file: PSeekFile,
    initial_range: Range<u64>,
    channel: mpsc::Sender<ProgressMessage>,
) -> Result<()> {
    assert!(initial_range.start < initial_range.end);

    let client = reqwest::ClientBuilder::new().build()?;

    let response = client
        .get(url)
        .header(
            reqwest::header::RANGE,
            format!("bytes={}-{}", initial_range.start, initial_range.end - 1),
        )
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("Failed to start download for range: {initial_range:?}"))?;
    let mut stream = response.bytes_stream();
    let mut range = initial_range.clone();

    while range.start < range.end {
        let data = if let Some(x) = stream.next().await {
            x?
        } else {
            return Err(anyhow!("Unexpected EOF from server"));
        };

        // This may overlap with another task's write when a range split occurs,
        // but the same data will be written anyway, so it's not a huge deal.
        task::block_in_place(|| {
            file.seek(SeekFrom::Start(range.start))?;
            file.write_all(&data)
        })
        .with_context(|| {
            format!(
                "Failed to write {} bytes to output file at offset {}",
                data.len(),
                range.start,
            )
        })?;

        let consumed = cmp::min(range.end - range.start, data.len() as u64);
        range.start += consumed;

        // Report progress to the controller.
        let (tx, rx) = oneshot::channel();
        let msg = ProgressMessage {
            task_id,
            bytes: consumed,
            resp: tx,
        };
        channel.send(msg).await?;

        // Get new ending offset from controller.
        let new_end = rx.await?;
        if new_end != range.end {
            debug_assert!(new_end <= range.end);
            range.end = new_end;
        }
    }

    Ok(())
}

/// Create download task for a byte range. This just calls [`download_range()`]
/// and returns a tuple containing the task ID and the result.
async fn download_task(
    task_id: u64,
    url: String,
    file: PSeekFile,
    initial_range: Range<u64>,
    channel: mpsc::Sender<ProgressMessage>,
) -> (u64, Result<()>) {
    (
        task_id,
        download_range(task_id, &url, file, initial_range, channel).await,
    )
}

/// Send a HEAD request to get the value of the Content-Length header.
async fn get_content_length(url: &str) -> Result<u64> {
    let response = reqwest::Client::new()
        .head(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("Failed to send HEAD request to get Content-Length")?;

    response
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| anyhow!("HEAD request did not return a valid Content-Length"))
}

/// Download a set of file chunks in parallel. Only unrecoverable errors are
/// returned as an Err. Normal/expected errors and download progress info are
/// reported via `display`. Returns the remaining ranges that need to be
/// downloaded.
async fn download_ranges(
    url: &str,
    output: &Path,
    initial_ranges: Option<&[Range<u64>]>,
    display: &mut dyn ProgressDisplay,
    max_tasks: usize,
    max_errors: u8,
) -> Result<Vec<Range<u64>>> {
    let file_size = get_content_length(url).await?;

    // Open for writing, but without truncation.
    let file = task::block_in_place(|| {
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(output)
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to open for writing: {output:?}"))
    })?;

    task::block_in_place(|| file.set_len(file_size))
        .with_context(|| format!("Failed to set file size: {output:?}"))?;

    // Queue of ranges that need to be downloaded.
    let mut remaining = VecDeque::from(match initial_ranges {
        Some(r) => r.to_vec(),
        #[allow(clippy::single_range_in_vec_init)]
        None => vec![0..file_size],
    });
    // Ranges that have failed.
    let mut failed = Vec::<Range<u64>>::new();
    // Ranges for currently running tasks.
    let mut task_ranges = HashMap::<u64, Range<u64>>::new();

    // Overall progress.
    let mut progress = file_size - remaining.iter().map(|r| r.end - r.start).sum::<u64>();
    display.progress(progress, file_size);

    let mut tasks = JoinSet::new();
    let mut next_task_id = 0;
    let mut error_count = 0u8;
    // Progress messages from tasks.
    let (tx, mut rx) = mpsc::channel(max_tasks);

    loop {
        // Spawn new tasks.
        while tasks.len() < max_tasks {
            if remaining.is_empty() && !tasks.is_empty() {
                // No more ranges to download. Split another task's range.
                let (_, old_range) = task_ranges
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

            if let Some(task_range) = remaining.pop_front() {
                tasks.spawn(download_task(
                    next_task_id,
                    url.to_owned(),
                    file.clone(),
                    task_range.clone(),
                    tx.clone(),
                ));

                task_ranges.insert(next_task_id, task_range);
                next_task_id += 1;
            } else {
                // No pending ranges and no running tasks can be split.
                break;
            }
        }

        tokio::select! {
            // Interrupted by user.
            c = ctrl_c() => {
                c?;
                break;
            }

            // Received progress notification.
            msg = rx.recv() => {
                let msg = msg.unwrap();

                progress += msg.bytes;
                display.progress(progress, file_size);

                let task_range = task_ranges.get_mut(&msg.task_id).unwrap();
                task_range.start += msg.bytes;

                msg.resp.send(task_range.end).unwrap();
            }

            // Received completion message.
            r = tasks.join_next() => {
                match r {
                    // All tasks exited.
                    None => {
                        break;
                    },

                    // Download task panicked.
                    Some(Err(e)) => {
                        return Err(e).context("Unexpected panic in download task");
                    }

                    // Task completed successfully.
                    Some(Ok((task_id, Ok(_)))) => {
                        task_ranges.remove(&task_id).unwrap();
                    }

                    // Task failed.
                    Some(Ok((task_id, Err(e)))) => {
                        display.error(&format!("[Task#{task_id}] {e}"));
                        error_count += 1;

                        let range = task_ranges.remove(&task_id).unwrap();

                        if error_count < max_errors {
                            remaining.push_back(range);
                        } else {
                            failed.push(range);
                        }
                    }
                }
            }
        }
    }

    display.finish();

    failed.extend(remaining.into_iter());
    failed.extend(task_ranges.into_values());

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
) -> Result<()> {
    let state_path = state_path(output);
    let ranges = match read_state(&state_path)? {
        Some(r) => Some(r.ranges),
        None => initial_ranges.map(|r| r.to_vec()),
    };

    let runtime = Runtime::new()?;
    let remaining = runtime.block_on(download_ranges(
        url,
        output,
        ranges.as_deref(),
        display,
        max_tasks,
        max_errors,
    ))?;

    if remaining.is_empty() {
        delete_if_exists(&state_path)?;
    } else {
        write_state(&state_path, &State { ranges: remaining })?;
        bail!("Download was interrupted");
    }

    Ok(())
}
