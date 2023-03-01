import argparse
import collections
import copy
import dataclasses
import functools
import json
import os
import queue
import sys
import threading
import time
import typing
import urllib.request

# This is a Python adaptation of the parallel downloader written for samfusdl.

MIN_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB

DEFAULT_BUF_SIZE = 16384
DEFAULT_RETRIES = 3
DEFAULT_THREADS = 4
DEFAULT_TIMEOUT = 30


@dataclasses.dataclass
@functools.total_ordering
class Range:
    start: int
    end: int

    def __lt__(self, other) -> bool:
        return (self.start, self.end) < (other.start, other.end)

    def __eq__(self, other) -> bool:
        return (self.start, self.end) == (other.start, other.end)

    def __bool__(self) -> bool:
        return self.start < self.end

    def size(self) -> int:
        return self.end - self.start


class DownloadWorker(threading.Thread):
    '''
    Thread to download a contiguous range from <url>.

    After each buffer read, the buffer is submitted to <output_queue>. The
    download continues only after reading a new range end offset from
    <input_queue>. The controller uses this to interrupt this thread sooner
    than expected in order to split the work for better resource utilization.
    '''

    def __init__(self, url: str, range: Range, output_queue: queue.Queue,
                 buf_size: typing.Optional[int] = None,
                 timeout: typing.Optional[int] = None):
        super().__init__()

        self.url = url
        self.range = copy.copy(range)
        self.input_queue = queue.Queue()
        self.output_queue = output_queue
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        self.buf_size = DEFAULT_BUF_SIZE if buf_size is None else buf_size

    def run(self):
        try:
            self._download()
            self.output_queue.put((self.ident, None))
        except BaseException as e:
            self.output_queue.put((self.ident, e))

    def _download(self):
        req = urllib.request.Request(self.url)
        req.add_header('Range', f'bytes={self.range.start}-{self.range.end}')

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            buf = bytearray(self.buf_size)
            buf_view = memoryview(buf)

            while self.range:
                to_read = min(self.buf_size, self.range.size())
                n = resp.readinto(buf_view[:to_read])

                if n != to_read:
                    raise EOFError(f'Expected {n} bytes, but downloaded '
                                   f'{to_read} bytes in {self.range}')

                self.output_queue.put((self.ident, buf_view[:n]))

                new_end = self.input_queue.get()
                self.range.start += n
                self.range.end = new_end


class DisplayCallback:
    def progress(self, current, total):
        raise NotImplementedError()

    def error(self, msg):
        raise NotImplementedError()

    def finish(self):
        raise NotImplementedError()


class DefaultDisplayCallback(DisplayCallback):
    def __init__(self, delay_ms=50):
        self.current = 0
        self.total = 0
        self.delay_ms = delay_ms
        self.last_render = None

    def progress(self, current, total):
        self.current = current
        self.total = total

        now = time.perf_counter_ns()

        if self.last_render is None or \
                (now - self.last_render) / 1_000_000 > self.delay_ms:
            self._clear_line()
            self._print(f'{current / 1024 / 1024:.1f} / '
                        f'{total / 1024 / 1024:.1f} MiB')
            self.last_render = now

    def error(self, msg):
        self._clear_line()
        self._print(msg, end='\n')

    def finish(self):
        self._clear_line()

    def _print(self, *args, **kwargs):
        kwargs.setdefault('end', '')
        kwargs.setdefault('file', sys.stderr)
        kwargs.setdefault('flush', True)
        print(*args, **kwargs)

    def _clear_line(self):
        self._print('\033[2K\r')


def _get_content_length(url: str, timeout: typing.Optional[int] = None) -> int:
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    req = urllib.request.Request(url, method='HEAD')

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.headers['content-length'])


def _download_ranges(f: typing.BinaryIO, url: str, ranges: list[Range],
                     display: DisplayCallback,
                     buf_size: typing.Optional[int] = None,
                     retries: typing.Optional[int] = None,
                     threads: typing.Optional[int] = None,
                     timeout: typing.Optional[int] = None):
    retries = DEFAULT_RETRIES if retries is None else retries
    threads = DEFAULT_THREADS if threads is None else threads

    workers = {}
    # This is our own world view of the ranges that each worker should operate
    # on. The worker's own view of its range will lag behind this until the
    # next buffer loop cycle. It's fine for some workers' ranges to temporarily
    # overlap since all file writes happen on the main thread. The worst case
    # is that two workers download an overlapped range and the same file region
    # is written twice.
    worker_ranges = {}
    output_queue = queue.Queue()
    error_count = 0

    file_size = _get_content_length(url, timeout=timeout)
    f.truncate(file_size)

    if not ranges:
        ranges.append(Range(0, file_size))

    progress = file_size - sum(r.size() for r in ranges)

    remaining = collections.deque(ranges)
    failed = []

    try:
        while True:
            # Spawn new workers
            while len(workers) < threads:
                if not remaining and workers:
                    # No more ranges to download. Split another worker's range.
                    ident = max(worker_ranges,
                                key=lambda i: worker_ranges[i].size())
                    old_range = worker_ranges[ident]
                    size = old_range.size()

                    if size >= MIN_CHUNK_SIZE:
                        new_range = Range(old_range.start + size // 2,
                                          old_range.end)
                        old_range.end = new_range.start

                        remaining.appendleft(new_range)

                if not remaining:
                    break

                worker_range = remaining.popleft()
                worker = DownloadWorker(url, worker_range, output_queue,
                                        buf_size=buf_size, timeout=timeout)
                worker.start()

                workers[worker.ident] = worker
                worker_ranges[worker.ident] = worker_range

            if not workers:
                # Everything is done
                break

            ident, result = output_queue.get()

            # Worker completed successfully
            if result is None:
                workers[ident].join()
                del workers[ident]
                del worker_ranges[ident]

            # Worker failed
            elif isinstance(result, BaseException):
                display.error(f'[Worker#{ident}] {result}')
                error_count += 1

                # Retry range if we haven't failed too many times
                if error_count < retries:
                    remaining.appendleft(worker_ranges[ident])
                else:
                    failed.append(worker_ranges[ident])

                workers[ident].join()
                del workers[ident]
                del worker_ranges[ident]

            # Got a buffer, write it to the file
            else:
                f.seek(worker_ranges[ident].start)
                f.write(result)

                progress += len(result)
                worker_ranges[ident].start += len(result)
                workers[ident].input_queue.put(worker_ranges[ident].end)

                display.progress(progress, file_size)

        display.finish()

    except BaseException:
        # Cancel remaining threads
        for ident, worker in workers.items():
            worker.input_queue.put(worker_ranges[ident].start)

        for worker in workers.values():
            worker.join()

        display.finish()

        raise

    finally:
        # Mutate the original ranges parameter so that the caller knows which
        # ranges are still remaining. This includes the not-yet-started,
        # failed, and previously-in-progress ranges.
        remaining.extend(failed)
        remaining.extend(worker_ranges.values())

        ranges.clear()
        ranges.extend(sorted(remaining))

    if remaining:
        raise Exception(f'Download failed with {len(remaining)} chunks left '
                        f'({file_size - progress} bytes)')


def _open_or_create(path: os.PathLike[str]) -> typing.BinaryIO():
    # Python's open() function has no way to open or create a file for both
    # reading and writing without truncating without TOCTOU issues.
    return os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT, 0o644), 'r+b')


def download_ranges(out: os.PathLike[str], url: str,
                    initial_ranges: typing.Optional[list[Range]],
                    display: DisplayCallback,
                    buf_size: typing.Optional[int] = None,
                    retries: typing.Optional[int] = None,
                    threads: typing.Optional[int] = None,
                    timeout: typing.Optional[int] = None):
    '''
    Download <url> to <out> with <threads> parallel threads.

    If <initial_ranges> is specified, only those sections of the file will be
    downloaded. The empty regions are left untouched (i.e. filled with zeroes).
    A `.state` file is written if the download is interrupted. If the state
    file exists when this function is called, <initial_ranges> is ignored and
    the ranges from the state file are used to resume the download.
    '''

    state_file = f'{out}.state'

    try:
        with open(state_file, 'r') as f:
            ranges_json = json.load(f)
            ranges = [Range(r['start'], r['end']) for r in ranges_json]
    except FileNotFoundError:
        ranges = list(initial_ranges) if initial_ranges else []

    try:
        with _open_or_create(out) as f:
            _download_ranges(
                f,
                url,
                ranges,
                display,
                buf_size=buf_size,
                retries=retries,
                threads=threads,
                timeout=timeout,
            )
    finally:
        if ranges:
            with open(state_file, 'w') as f:
                ranges_json = [{'start': r.start, 'end': r.end}
                               for r in ranges]
                json.dump(ranges_json, f, indent=4)
        else:
            try:
                os.unlink(state_file)
            except FileNotFoundError:
                pass


def parse_range(arg: str):
    start, delim, end = arg.partition('-')
    if not delim:
        raise ValueError('Range should be in the form: <start>-<end>')

    start = int(start)
    end = int(end)

    return Range(start, end)


def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True,
                        help='URL to download')
    parser.add_argument('-o', '--output', required=True,
                        help='Output path')
    parser.add_argument('-r', '--range', action='append', type=parse_range,
                        help='Half-open range to download ("<start>-<end>")')
    parser.add_argument('-t', '--threads', default=4, type=int,
                        help='Number of parallel threads for downloading')
    parser.add_argument('--buf-size', default=DEFAULT_BUF_SIZE, type=int,
                        help='Buffer size per download thread')
    parser.add_argument('--retries', default=DEFAULT_RETRIES, type=int,
                        help='Maximum retries during download')
    parser.add_argument('--timeout', default=DEFAULT_THREADS, type=int,
                        help='Connection timeout in seconds')

    return parser.parse_args()


def main():
    args = parse_args()

    download_ranges(
        args.output,
        args.url,
        args.range,
        DefaultDisplayCallback(),
        buf_size=args.buf_size,
        retries=args.retries,
        threads=args.threads,
        timeout=args.timeout,
    )


if __name__ == '__main__':
    main()
