import contextlib
import dataclasses
import functools
import os
import tempfile


_ZERO_BLOCK = memoryview(b'\0' * 16384)

umask = None


def load_umask_unsafe():
    # POSIX provides no way to query the umask without changing it. Parsing
    # /proc/self/status can work, but it's Linux only. Instead, we'll just do it
    # once when the program is initially started.
    global umask

    if os.name != 'nt' and umask is None:
        current_umask = os.umask(0o777)
        os.umask(current_umask)

        umask = current_umask


@dataclasses.dataclass
@functools.total_ordering
class Range:
    '''
    Simple class to represent a half-open interval.
    '''

    start: int
    end: int

    def __repr__(self) -> str:
        return f'[{self.start}, {self.end})'

    def __str__(self) -> str:
        return f'>={self.start}, <{self.end}'

    def __lt__(self, other) -> bool:
        return (self.start, self.end) < (other.start, other.end)

    def __eq__(self, other) -> bool:
        return (self.start, self.end) == (other.start, other.end)

    def __contains__(self, item) -> bool:
        return item >= self.start and item < self.end

    def __bool__(self) -> bool:
        return self.start < self.end

    def size(self) -> int:
        return self.end - self.start


@contextlib.contextmanager
def open_output_file(path):
    '''
    Create a temporary file in the same directory as the specified path and
    replace it if the function succeeds. On non-Windows, the file replacement
    is atomic. On Windows, it is not.
    '''

    directory = os.path.dirname(path)

    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
        try:
            yield f

            if os.name == 'nt':
                # Windows does not allow renaming a file with handles open
                f.close()

                # Windows only supports atomic renames by calling
                # SetFileInformationByHandle() with the FileRenameInfoEx
                # operation and the FILE_RENAME_FLAG_REPLACE_IF_EXISTS and
                # FILE_RENAME_FLAG_POSIX_SEMANTICS flags. This is not exposed
                # in Python and it's not worth adding a new dependency for
                # doing low-level win32 API calls.
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            else:
                # NamedTemporaryFile always uses 600 permissions with no way to
                # override it. We'll do our own umask-respecting chmod.
                os.fchmod(f.fileno(), 0o666 & ~umask)

            os.rename(f.name, path)
        except BaseException:
            if os.name == 'nt':
                # Windows does not allow deleting a file with handles open
                f.close()

            os.unlink(f.name)
            raise


def hash_file(f, hasher, buf_size=16384):
    '''
    Update <hasher> when the data from <f> until EOF.
    '''

    buf = bytearray(buf_size)
    buf_view = memoryview(buf)

    while True:
        n = f.readinto(buf_view)
        if not n:
            break

        hasher.update(buf_view[:n])

    return hasher


def copyfileobj_n(f_in, f_out, size, buf_size=16384, hasher=None):
    '''
    Copy <size> bytes from <f_in> to <f_out>.

    Raises IOError if EOF is reached in <f_in> before <size> bytes are read.
    '''

    buf = bytearray(buf_size)
    buf_view = memoryview(buf)

    while size:
        to_read = min(len(buf_view), size)
        n = f_in.readinto(buf_view[:to_read])
        if not n:
            break

        if hasher:
            hasher.update(buf_view[:n])

        f_out.write(buf_view[:n])
        size -= n

    if size:
        raise IOError(f'Unexpected EOF; expected {size} more bytes')


def decompress_n(decompressor, f_in, f_out, size, buf_size=16384, hasher=None):
    '''
    Read <size> bytes from <f_in> and decompress them to <f_out>.

    Raises IOError if EOF is reached in <f_in> before <size> bytes are read.
    '''

    buf = bytearray(buf_size)
    buf_view = memoryview(buf)

    while size:
        to_read = min(len(buf_view), size)
        n = f_in.readinto(buf_view[:to_read])
        if not n:
            break

        if hasher:
            hasher.update(buf_view[:n])

        data = decompressor.decompress(buf_view[:n])

        f_out.write(data)
        size -= n

    if size:
        raise IOError(f'Unexpected EOF; expected {size} more bytes')
    elif not decompressor.eof:
        raise IOError('Did not reach end of compressed input')


def zero_n(f_out, size, buf_size=16384):
    '''
    Write <size> zeroes to <f_out>.
    '''

    buf = bytearray(buf_size)
    buf_view = memoryview(buf)

    while size:
        to_write = min(len(buf_view), size)
        f_out.write(buf_view[:to_write])
        size -= to_write


def read_exact(f, size: int) -> bytes:
    '''
    Read exactly <size> bytes from <f> or raise an EOFError.
    '''

    data = f.read(size)
    if len(data) != size:
        raise EOFError(f'Unexpected EOF: expected {size} bytes, '
                       f'but only read {len(data)} bytes')

    if not isinstance(data, bytes):
        # io.BytesIO returns a bytearray
        return bytes(data)
    else:
        return data


def is_zero(data):
    '''
    Check if all bytes in the bytes-like object are null bytes.
    '''

    view = memoryview(data)

    while view:
        n = min(len(view), len(_ZERO_BLOCK))

        if view[:n] != _ZERO_BLOCK[:n]:
            return False

        view = view[n:]

    return True
