import enum
import gzip
import typing

import lz4.block

from .. import util


GZIP_MAGIC = b'\x1f\x8b'


class Lz4Legacy:
    MAGIC = b'\x02\x21\x4c\x18'
    MAX_BLOCK_SIZE = 8 * 1024 * 1024

    def __init__(self, fp: typing.BinaryIO,
                 mode: typing.Literal['rb', 'wb'] = 'rb'):
        if mode not in ('rb', 'wb'):
            raise ValueError(f'Invalid mode: {mode}')

        self.fp = fp
        self.mode = mode

        if mode == 'rb':
            magic = util.read_exact(self.fp, len(self.MAGIC))
            if magic != self.MAGIC:
                raise ValueError(f'Invalid magic: {magic!r}')

            self.rblock = b''
            self.rblock_offset = 0
        else:
            self.fp.write(self.MAGIC)

            self.wblock = bytearray()

        self.file_offset = 0

    def __enter__(self) -> 'Lz4Legacy':
        return self

    def __exit__(self, *exc_args) -> None:
        self.close()

    def _read_block(self) -> None:
        if self.rblock_offset < len(self.rblock):
            # Haven't finished reading block yet
            return

        size_raw = self.fp.read(4)
        if not size_raw or size_raw == self.MAGIC:
            self.rblock = b''
            self.rblock_offset = 0
            return
        elif len(size_raw) != 4:
            raise EOFError('Failed to read block size')

        size_compressed = int.from_bytes(size_raw, 'little')

        compressed = util.read_exact(self.fp, size_compressed)
        self.rblock = lz4.block.decompress(compressed, self.MAX_BLOCK_SIZE)
        self.rblock_offset = 0

    def _write_block(self, force=False) -> None:
        if not force and len(self.wblock) < self.MAX_BLOCK_SIZE:
            # Block not fully filled yet
            return

        compressed = lz4.block.compress(
            self.wblock,
            mode='high_compression',
            compression=12,
            store_size=False,
        )

        self.fp.write(len(compressed).to_bytes(4, 'little'))
        self.fp.write(compressed)

        self.wblock.clear()

    def read(self, size=None) -> bytes:
        assert self.mode == 'rb'

        result = bytearray()

        while size is None or size > 0:
            self._read_block()

            to_read = len(self.rblock) - self.rblock_offset
            if to_read == 0:
                # EOF
                break
            elif size is not None:
                to_read = min(to_read, size)

            result.extend(self.rblock[self.rblock_offset:
                                      self.rblock_offset + to_read])

            self.rblock_offset += to_read
            self.file_offset += to_read

            if size is not None:
                size -= to_read

        return result

    def write(self, data: bytes) -> int:
        assert self.mode == 'wb'

        offset = 0

        while offset < len(data):
            self._write_block()

            to_write = min(
                self.MAX_BLOCK_SIZE - len(self.wblock),
                len(data) - offset,
            )

            self.wblock.extend(data[offset:offset + to_write])

            self.file_offset += to_write
            offset += to_write

        return len(data)

    def flush(self) -> None:
        assert self.mode == 'wb'

        self._write_block(force=True)

    def close(self) -> None:
        try:
            if self.mode == 'wb':
                self.flush()
        finally:
            self.mode = 'closed'

    def tell(self) -> int:
        return self.file_offset


Format = enum.Enum('Format', ['GZIP', 'LZ4_LEGACY'])


_MAGIC_TO_FORMAT = {
    GZIP_MAGIC: Format.GZIP,
    Lz4Legacy.MAGIC: Format.LZ4_LEGACY,
}
_MAGIC_MAX_SIZE = max(len(m) for m in _MAGIC_TO_FORMAT)


class CompressedFile:
    def __init__(
        self,
        fp: typing.BinaryIO,
        mode: typing.Literal['rb', 'wb'] = 'rb',
        format: typing.Optional[Format] = None,
        raw_if_unknown = False,
    ):
        if mode == 'rb' and not format:
            magic = fp.read(_MAGIC_MAX_SIZE)
            fp.seek(0)

            for m, f in _MAGIC_TO_FORMAT.items():
                if magic.startswith(m):
                    format = f
                    break

        if format == Format.GZIP:
            format_fp = gzip.GzipFile(fileobj=fp, mode=mode, mtime=0)
        elif format == Format.LZ4_LEGACY:
            format_fp = Lz4Legacy(fp, mode)
        elif raw_if_unknown:
            format_fp = fp
        else:
            raise ValueError('Unknown compression format')

        self.fp = format_fp
        self.format = format

    def __enter__(self):
        self.fp.__enter__()
        return self

    def __exit__(self, *exc_args):
        self.fp.__exit__(*exc_args)
