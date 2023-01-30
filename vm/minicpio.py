# This is a miniature implementation of cpio, originally written for
# DualBootPatcher, supporting only enough of the file format for messing with
# boot image ramdisks. Only the "new format" for cpio entries are supported.

# Supported files
# - Regular files
# - Directories
# - Symlinks
# - Hardlinks (very rudimentary)


import os
import stat
import typing

MAGIC_NEW = b'070701'      # new format
MAGIC_NEW_CRC = b'070702'  # new format w/crc

# Constants from cpio.h

# A header with a filename "TRAILER!!!" indicates the end of the archive.
CPIO_TRAILER = b'TRAILER!!!'

C_ISCTG = 0o0110000

IO_BLOCK_SIZE = 512


def _read_exact(f: typing.BinaryIO, size: int) -> bytes:
    data = f.read(size)
    if len(data) != size:
        raise Exception(f'Expected {size}, but only read {len(data)} bytes')

    return data


def _write_exact(f: typing.BinaryIO, data: bytes) -> int:
    size = f.write(data)
    if size != len(data):
        raise Exception(f'Expected {len(data)}, but only wrote {size} bytes')

    return size


def _read_int(f: typing.BinaryIO) -> int:
    return int(_read_exact(f, 8), 16)


def _write_int(f: typing.BinaryIO, value: int) -> int:
    if value < 0 or value > 0xffffffff:
        raise ValueError(f'{value} out of range for 32-bit integer')

    return _write_exact(f, b'%08x' % value)


def _padding(offset: int, page_size: int) -> int:
    return (page_size - (offset & (page_size - 1))) & (page_size - 1)


def _skip_padding(f: typing.BinaryIO, page_size: int) -> int:
    pos = f.tell()
    return f.seek(_padding(pos, page_size), os.SEEK_CUR) - pos


def _write_padding(f: typing.BinaryIO, page_size: int) -> int:
    return _write_exact(f, _padding(f.tell(), page_size) * b'\x00')


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
        entry.nlink = 2
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

    @staticmethod
    def new_char_device(name: bytes, major: int, minor: int,
                        perms: int = 0o644) -> 'CpioEntryNew':
        if not name:
            raise ValueError('Device name is empty')

        entry = CpioEntryNew()
        entry.mode = stat.S_IFCHR | stat.S_IMODE(perms)
        entry.nlink = 1
        entry.rdev_maj = major
        entry.rdev_min = minor
        entry.name = name

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
            self.magic = _read_exact(f, 6)
            if self.magic != MAGIC_NEW and self.magic != MAGIC_NEW_CRC:
                raise Exception(f'Unknown magic: {self.magic}')

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
            self._name = _read_exact(f, self.namesize - 1)
            f.seek(1, os.SEEK_CUR)
            _skip_padding(f, 4)

            # File contents
            self._content = _read_exact(f, self.filesize)
            _skip_padding(f, 4)

    def write(self, f: typing.BinaryIO):
        if len(self.magic) != 6:
            raise ValueError(f'Magic is not 6 bytes: {self.magic}')

        _write_exact(f, self.magic)

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
        _write_exact(f, self._name)
        _write_exact(f, b'\x00')
        _write_padding(f, 4)

        # File contents
        _write_exact(f, self._content)
        _write_padding(f, 4)

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
            'Filename:        %s\n' % self.name + \
            'Filetype:        %s\n' % ftypestr + \
            'Magic:           %s\n' % self.magic + \
            'Inode:           %i\n' % self.ino + \
            'Mode:            %o\n' % self.mode + \
            'Permissions:     %o\n' % (self.mode - filetype) + \
            'UID:             %i\n' % self.uid + \
            'GID:             %i\n' % self.gid + \
            'Links:           %i\n' % self.nlink + \
            'Modified:        %i\n' % self.mtime + \
            'File size:       %i\n' % self.filesize + \
            'dev_maj:         %x\n' % self.dev_maj + \
            'dev_min:         %x\n' % self.dev_min + \
            'rdev_maj:        %x\n' % self.rdev_maj + \
            'rdev_min:        %x\n' % self.rdev_min + \
            'Filename length: %i\n' % self.namesize + \
            'Checksum:        %i\n' % self.chksum


class CpioFile:
    def __init__(self) -> None:
        self.entries = []
        self._cur_inode = 300000

    def load(self, f: typing.BinaryIO):
        while True:
            member = CpioEntryNew(f)

            if member.name == CPIO_TRAILER:
                break

            # Make sure the existing inodes won't conflict with ones from newly
            # added files, so make them negative for now
            member.ino *= -1

            self.entries.append(member)

    def write(self, f: typing.BinaryIO):
        inodes = {}
        old_inodes = {}
        unassigned = []

        for entry in self.entries:
            if entry.ino == 0:
                unassigned.append(entry)
            elif entry.ino < 0:
                old_inodes.setdefault(entry.ino, []).append(entry)
            else:
                inodes.setdefault(entry.ino, []).append(entry)

        # Assign unique inodes entries imported from an existing file
        for inode, entries in old_inodes.items():
            while self._cur_inode in inodes:
                self._cur_inode += 1

            for e in entries:
                e.ino = self._cur_inode

            inodes[self._cur_inode] = entries

        # Assign unique inodes to entries with no assigned inode
        for e in unassigned:
            while self._cur_inode in inodes:
                self._cur_inode += 1

            e.ino = self._cur_inode

            inodes[self._cur_inode] = [e]

        # Update nlinks
        for entries in inodes.values():
            for e in entries:
                e.nlink = len(entries)

        # Sort the entries by name. This is a crude way to satisfy the kernel
        # requiring directories to come before child paths in the ramdisk.
        sorted = []
        for _, entries in inodes.items():
            sorted.extend(entries)

        sorted.sort(key=lambda e: e.name)

        # Add trailer
        while self._cur_inode in inodes:
            self._cur_inode += 1

        trailer = CpioEntryNew.new_trailer()
        trailer.ino = self._cur_inode
        sorted.append(trailer)

        for entry in sorted:
            entry.write(f)

        # Pad until end of block
        _write_padding(f, IO_BLOCK_SIZE)
