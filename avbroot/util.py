import contextlib
import os
import tempfile


@contextlib.contextmanager
def open_output_file(path):
    '''
    Create a temporary file in the same directory as the specified path and
    atomically replace it if the function succeeds.
    '''

    directory = os.path.dirname(path)

    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
        try:
            yield f
            os.rename(f.name, path)
        except Exception:
            os.unlink(f.name)
            raise


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
        raise IOError(f'Did not reach end of compressed input')


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
