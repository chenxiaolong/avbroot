import contextlib
import ctypes
import os
import struct
import sys
import tempfile


TMPFS_MAGIC = 0x01021994


def statfs_type(path):
    '''
    On Linux, call statfs on the given path and return the f_type value.
    '''

    if sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(120)

        ret = libc.statfs(ctypes.c_char_p(path.encode()), buf)
        if ret < 0:
            errno = ctypes.get_errno()
            os_error = OSError(errno, os.strerror(errno), path)
            raise Exception('Failed to statfs') from os_error

        return struct.unpack('@l', buf.raw[0:struct.calcsize('@l')])[0]

    else:
        raise NotImplementedError('statfs only supported on Linux')


def tmpfs_path():
    '''
    Try to find a tmpfs path on Linux. Returns None if no usable tmpfs is found
    or if running on non-Linux.
    '''

    if sys.platform.startswith('linux'):
        candidates = []

        # Gather tmpfs candidates. This alone isn't sufficient because another
        # filesystem might be mounted on top of a tmpfs, shadowing it.
        with open('/proc/self/mountinfo', 'r') as f:
            for line in f:
                pieces = line.split()

                if pieces[8] == 'tmpfs':
                    candidates.append(pieces[4])

        # Verify that the mount point is actually a tmpfs and is writable.
        for candidate in candidates:
            if statfs_type(candidate) == TMPFS_MAGIC and \
                    os.access(candidate, os.W_OK):
                return candidate

    return None


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
        except:
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
