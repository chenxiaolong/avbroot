# This is a miniature implementation of cpio, originally written for
# DualBootPatcher, supporting only enough of the file format for messing with
# boot image ramdisks. Only the "new format" for cpio entries are supported.

import stat
import typing

from . import padding
from .. import util

MAGIC_NEW = b'070701'      # new format
MAGIC_NEW_CRC = b'070702'  # new format w/crc

# Constants from cpio.h

# A header with a filename "TRAILER!!!" indicates the end of the archive.
CPIO_TRAILER = b'TRAILER!!!'

C_ISCTG = 0o0110000

IO_BLOCK_SIZE = 512


def _read_int(f: typing.BinaryIO) -> int:
    return int(util.read_exact(f, 8), 16)


def _write_int(f: typing.BinaryIO, value: int) -> int:
    if value < 0 or value > 0xffffffff:
        raise ValueError(f'{value} out of range for 32-bit integer')

    return f.write(b'%08x' % value)


class CpioEntryNew:
    # c_magic     - "070701" for "new" portable format
    #               "070702" for CRC format
    # c_ino
    # c_mode
    # c_uid
    # c_gid
    # c_nlink
    # c_mtime
    # c_filesize  - must be 0 for FIFOs and directories
    # c_dev_maj
    # c_dev_min
    # c_rdev_maj  - only valid for chr and blk special files
    # c_rdev_min  - only valid for chr and blk special files
    # c_namesize  - count includes terminating NUL in pathname
    # c_chksum    - 0 for "new" portable format; for CRC format
    #               the sum of all the bytes in the file

    @staticmethod
    def new_trailer() -> 'CpioEntryNew':
        entry = CpioEntryNew()
        entry.nlink = 1  # Must be 1 for crc format
        entry.name = CPIO_TRAILER

        return entry

    @staticmethod
    def new_symlink(link_target: bytes, name: bytes) -> 'CpioEntryNew':
        if not link_target:
            raise ValueError('Symlink target is empty')
        elif not name:
            raise ValueError('Symlink name is empty')

        entry = CpioEntryNew()
        entry.mode = stat.S_IFLNK | 0o777
        entry.nlink = 1
        entry.name = name
        entry.content = link_target

        return entry

    @staticmethod
    def new_directory(name: bytes, perms: int = 0o755) -> 'CpioEntryNew':
        if not name:
            raise ValueError('Directory name is empty')

        entry = CpioEntryNew()
        entry.mode = stat.S_IFDIR | stat.S_IMODE(perms)
        entry.nlink = 1
        entry.name = name

        return entry

    @staticmethod
    def new_file(name: bytes, perms: int = 0o644,
                 data: bytes = b'') -> 'CpioEntryNew':
        if not name:
            raise ValueError('File name is empty')

        entry = CpioEntryNew()
        entry.mode = stat.S_IFREG | stat.S_IMODE(perms)
        entry.nlink = 1
        entry.name = name
        entry.content = data

        return entry

    def __init__(self, f: typing.Optional[typing.BinaryIO] = None) -> None:
        super(CpioEntryNew, self).__init__()

        if f is None:
            self.magic = MAGIC_NEW
            self.ino = 0
            self.mode = 0
            self.uid = 0
            self.gid = 0
            self.nlink = 0
            self.mtime = 0
            self.filesize = 0
            self.dev_maj = 0
            self.dev_min = 0
            self.rdev_maj = 0
            self.rdev_min = 0
            self.namesize = 0
            self.chksum = 0

            self._name = b''
            self._content = b''
        else:
            self.magic = util.read_exact(f, 6)
            if self.magic != MAGIC_NEW and self.magic != MAGIC_NEW_CRC:
                raise Exception(f'Unknown magic: {self.magic!r}')

            self.ino = _read_int(f)
            self.mode = _read_int(f)
            self.uid = _read_int(f)
            self.gid = _read_int(f)
            self.nlink = _read_int(f)
            self.mtime = _read_int(f)
            self.filesize = _read_int(f)
            self.dev_maj = _read_int(f)
            self.dev_min = _read_int(f)
            self.rdev_maj = _read_int(f)
            self.rdev_min = _read_int(f)
            self.namesize = _read_int(f)
            self.chksum = _read_int(f)

            # Filename
            self._name = bytes(util.read_exact(f, self.namesize - 1))
            # Discard NULL terminator
            util.read_exact(f, 1)
            padding.read_skip(f, 4)

            # File contents
            self._content = util.read_exact(f, self.filesize)
            padding.read_skip(f, 4)

    def write(self, f: typing.BinaryIO):
        if len(self.magic) != 6:
            raise ValueError(f'Magic is not 6 bytes: {self.magic!r}')

        f.write(self.magic)

        _write_int(f, self.ino)
        _write_int(f, self.mode)
        _write_int(f, self.uid)
        _write_int(f, self.gid)
        _write_int(f, self.nlink)
        _write_int(f, self.mtime)
        _write_int(f, self.filesize)
        _write_int(f, self.dev_maj)
        _write_int(f, self.dev_min)
        _write_int(f, self.rdev_maj)
        _write_int(f, self.rdev_min)
        _write_int(f, self.namesize)
        _write_int(f, self.chksum)

        # Filename
        f.write(self._name)
        f.write(b'\x00')
        padding.write(f, 4)

        # File contents
        f.write(self._content)
        padding.write(f, 4)

    @property
    def name(self) -> bytes:
        return self._name

    @name.setter
    def name(self, value: bytes):
        self._name = value
        self.namesize = len(value) + 1

    @property
    def content(self) -> bytes:
        return self._content

    @content.setter
    def content(self, value: bytes):
        self._content = value
        self.filesize = len(value)

    def __str__(self) -> str:
        filetype = stat.S_IFMT(self.mode)

        if stat.S_ISDIR(self.mode):
            ftypestr = 'directory'
        elif stat.S_ISLNK(self.mode):
            ftypestr = 'symbolic link'
        elif stat.S_ISREG(self.mode):
            ftypestr = 'regular file'
        elif stat.S_ISFIFO(self.mode):
            ftypestr = 'pipe'
        elif stat.S_ISCHR(self.mode):
            ftypestr = 'character device'
        elif stat.S_ISBLK(self.mode):
            ftypestr = 'block device'
        elif stat.S_ISSOCK(self.mode):
            ftypestr = 'socket'
        elif filetype == C_ISCTG:
            ftypestr = 'reserved'
        else:
            ftypestr = 'unknown (%o)' % filetype

        return \
            f'Filename:        {self.name!r}\n' \
            f'Filetype:        {ftypestr}\n' \
            f'Magic:           {self.magic!r}\n' \
            f'Inode:           {self.ino}\n' \
            f'Mode:            {self.mode:o}\n' \
            f'Permissions:     {self.mode - filetype:o}\n' \
            f'UID:             {self.uid}\n' \
            f'GID:             {self.gid}\n' \
            f'Links:           {self.nlink}\n' \
            f'Modified:        {self.mtime}\n' \
            f'File size:       {self.filesize}\n' \
            f'dev_maj:         {self.dev_maj:x}\n' \
            f'dev_min:         {self.dev_min:x}\n' \
            f'rdev_maj:        {self.rdev_maj:x}\n' \
            f'rdev_min:        {self.rdev_min:x}\n' \
            f'Filename length: {self.namesize}\n' \
            f'Checksum:        {self.chksum:x}\n'


def load(f: typing.BinaryIO) -> list[CpioEntryNew]:
    entries = []

    while True:
        entry = CpioEntryNew(f)

        if entry.name == CPIO_TRAILER:
            break

        if stat.S_IFMT(entry.mode) != stat.S_IFDIR and entry.nlink > 1:
            raise ValueError(f'Hard links are not supported: {entry.name!r}')

        # Inodes are reassigned on save
        entry.ino = 0

        entries.append(entry)

    return entries


def save(f: typing.BinaryIO, entries: list[CpioEntryNew], sort=True,
         pad_to_block_size=False):
    inode = 300000

    if sort:
        entries = sorted(entries, key=lambda e: e.name)

    for entry in entries:
        entry.ino = inode
        inode += 1

        entry.write(f)

    trailer = CpioEntryNew.new_trailer()
    trailer.ino = inode
    trailer.write(f)

    # Pad until end of block
    if pad_to_block_size:
        padding.write(f, IO_BLOCK_SIZE)
