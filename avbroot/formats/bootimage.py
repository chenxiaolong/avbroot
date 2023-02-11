import collections
import os
import struct
import typing

from . import padding
from .. import util


BOOT_MAGIC = b'ANDROID!'
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024

VENDOR_BOOT_MAGIC = b'VNDRBOOT'
VENDOR_BOOT_ARGS_SIZE = 2048
VENDOR_BOOT_NAME_SIZE = 16

VENDOR_RAMDISK_TYPE_NONE = 0
VENDOR_RAMDISK_TYPE_PLATFORM = 1
VENDOR_RAMDISK_TYPE_RECOVERY = 2
VENDOR_RAMDISK_TYPE_DLKM = 3
VENDOR_RAMDISK_NAME_SIZE = 32
VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE = 16

PAGE_SIZE = 4096

BOOT_IMG_HDR_V0 = struct.Struct(
    '<'
    f'{len(BOOT_MAGIC)}s'  # magic
    'I'  # kernel_size
    'I'  # kernel_addr
    'I'  # ramdisk_size
    'I'  # ramdisk_addr
    'I'  # second_size
    'I'  # second_addr
    'I'  # tags_addr
    'I'  # page_size
    'I'  # header_version
    'I'  # os_version
    f'{BOOT_NAME_SIZE}s'  # name
    f'{BOOT_ARGS_SIZE}s'  # cmdline
    f'{8 * 4}s'  # id (uint32_t[8])
    f'{BOOT_EXTRA_ARGS_SIZE}s'  # extra_cmdline
)

BOOT_IMG_HDR_V1_EXTRA = struct.Struct(
    '<'
    'I'  # recovery_dtbo_size
    'Q'  # recovery_dtbo_offset
    'I'  # header_size
)

BOOT_IMG_HDR_V2_EXTRA = struct.Struct(
    '<'
    'I'  # dtb_size
    'Q'  # dtb_addr
)

BOOT_IMG_HDR_V3 = struct.Struct(
    '<'
    f'{len(BOOT_MAGIC)}s'  # magic
    'I'  # kernel_size
    'I'  # ramdisk_size
    'I'  # os_version
    'I'  # header_size
    '16s'  # reserved (uint32_t[4])
    'I'  # header_version
    f'{BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE}s'  # cmdline
)

VENDOR_BOOT_IMG_HDR_V3 = struct.Struct(
    '<'
    f'{len(VENDOR_BOOT_MAGIC)}s'  # magic
    'I'  # header_version
    'I'  # page_size
    'I'  # kernel_addr
    'I'  # ramdisk_addr
    'I'  # vendor_ramdisk_size
    f'{VENDOR_BOOT_ARGS_SIZE}s'  # cmdline
    'I'  # tags_addr
    f'{VENDOR_BOOT_NAME_SIZE}s'  # name
    'I'  # header_size
    'I'  # dtb_size
    'Q'  # dtb_addr
)

BOOT_IMG_HDR_V4_EXTRA = struct.Struct(
    '<'
    'I'  # signature_size
)

VENDOR_BOOT_IMG_HDR_V4_EXTRA = struct.Struct(
    '<'
    'I'  # vendor_ramdisk_table_size
    'I'  # vendor_ramdisk_table_entry_num
    'I'  # vendor_ramdisk_table_entry_size
    'I'  # bootconfig_size
)

VENDOR_RAMDISK_TABLE_ENTRY_V4 = struct.Struct(
    '<'
    'I'  # ramdisk_size
    'I'  # ramdisk_offset
    'I'  # ramdisk_type
    f'{VENDOR_RAMDISK_NAME_SIZE}s'  # ramdisk_name
    f'{VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE * 4}s'  # board_id (uint32_t[])
)


class WrongFormat(ValueError):
    pass


class BootImage:
    def __init__(self) -> None:
        self.kernel: None | bytes = None
        self.ramdisks: list[bytes] = []
        self.second: None | bytes = None
        self.recovery_dtbo: None | bytes = None
        self.dtb: None | bytes = None
        self.bootconfig: None | bytes = None

    def generate(self, f: typing.BinaryIO) -> None:
        raise NotImplementedError()


class _BootImageV0Through2(BootImage):
    def __init__(self, f: typing.BinaryIO) -> None:
        super().__init__()

        # Common fields for v0 through v2
        magic, kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, \
            second_size, second_addr, tags_addr, page_size, header_version, \
            os_version, name, cmdline, id, extra_cmdline = \
            BOOT_IMG_HDR_V0.unpack(util.read_exact(f, BOOT_IMG_HDR_V0.size))

        if magic != BOOT_MAGIC:
            raise WrongFormat(f'Unknown magic: {magic}')
        elif header_version not in (0, 1, 2):
            raise WrongFormat(f'Unknown header version: {header_version}')

        self.kernel_addr = kernel_addr
        self.ramdisk_addr = ramdisk_addr
        self.second_addr = second_addr
        self.tags_addr = tags_addr
        self.page_size = page_size
        self.header_version = header_version
        self.os_version = os_version
        self.name = name.rstrip(b'\0')
        self.cmdline = cmdline.rstrip(b'\0')
        self.id = id
        self.extra_cmdline = extra_cmdline.rstrip(b'\0')

        # Parse v1 fields
        if header_version >= 1:
            recovery_dtbo_size, recovery_dtbo_offset, header_size = \
                BOOT_IMG_HDR_V1_EXTRA.unpack(
                    util.read_exact(f, BOOT_IMG_HDR_V1_EXTRA.size))

            self.recovery_dtbo_offset = recovery_dtbo_offset

        # Parse v2 fields
        if header_version == 2:
            dtb_size, dtb_addr = BOOT_IMG_HDR_V2_EXTRA.unpack(
                util.read_exact(f, BOOT_IMG_HDR_V2_EXTRA.size))

            self.dtb_addr = dtb_addr

        if header_version >= 1 and f.tell() != header_size:
            raise ValueError(f'Invalid header size: {header_size}')

        padding.read_skip(f, page_size)

        if kernel_size > 0:
            self.kernel = util.read_exact(f, kernel_size)
            padding.read_skip(f, page_size)

        if ramdisk_size > 0:
            self.ramdisks.append(util.read_exact(f, ramdisk_size))
            padding.read_skip(f, page_size)

        if second_size > 0:
            self.second = util.read_exact(f, second_size)
            padding.read_skip(f, page_size)

        if header_version >= 1 and recovery_dtbo_size > 0:
            self.recovery_dtbo = util.read_exact(f, recovery_dtbo_size)
            padding.read_skip(f, page_size)

        if header_version == 2 and dtb_size > 0:
            self.dtb = util.read_exact(f, dtb_size)
            padding.read_skip(f, page_size)

    def generate(self, f: typing.BinaryIO) -> None:
        if len(self.ramdisks) > 1:
            raise ValueError('Only one ramdisk is supported')
        elif self.bootconfig is not None:
            raise ValueError('Boot config is not supported')
        elif self.header_version < 1 and self.recovery_dtbo is not None:
            raise ValueError('Recovery dtbo/acpio is not supported')
        elif self.header_version < 2 and self.dtb is not None:
            raise ValueError('Device tree is not supported')

        f.write(BOOT_IMG_HDR_V0.pack(
            BOOT_MAGIC,
            len(self.kernel) if self.kernel else 0,
            self.kernel_addr,
            len(self.ramdisks[0]) if self.ramdisks else 0,
            self.ramdisk_addr,
            len(self.second) if self.second else 0,
            self.second_addr,
            self.tags_addr,
            self.page_size,
            self.header_version,
            self.os_version,
            self.name,
            self.cmdline,
            self.id,
            self.extra_cmdline,
        ))

        if self.header_version >= 1:
            header_size = BOOT_IMG_HDR_V0.size
            if self.header_version >= 1:
                header_size += BOOT_IMG_HDR_V1_EXTRA.size
            if self.header_version == 2:
                header_size += BOOT_IMG_HDR_V2_EXTRA.size

            f.write(BOOT_IMG_HDR_V1_EXTRA.pack(
                len(self.recovery_dtbo) if self.recovery_dtbo else 0,
                self.recovery_dtbo_offset,
                header_size,
            ))

        if self.header_version == 2:
            f.write(BOOT_IMG_HDR_V2_EXTRA.pack(
                len(self.dtb) if self.dtb else 0,
                self.dtb_addr,
            ))

        padding.write(f, self.page_size)

        if self.kernel:
            f.write(self.kernel)
            padding.write(f, self.page_size)

        if self.ramdisks:
            f.write(self.ramdisks[0])
            padding.write(f, self.page_size)

        if self.second:
            f.write(self.second)
            padding.write(f, self.page_size)

        if self.header_version >= 1 and self.recovery_dtbo:
            f.write(self.recovery_dtbo)
            padding.write(f, self.page_size)

        if self.header_version == 2 and self.dtb:
            f.write(self.dtb)
            padding.write(f, self.page_size)

    def __str__(self) -> str:
        kernel_size = len(self.kernel) if self.kernel else 0
        ramdisk_size = len(self.ramdisks[0]) if self.ramdisks else 0
        second_size = len(self.second) if self.second else 0

        result = \
            f'Boot image v{self.header_version} header:\n' \
            f'- Kernel size:          {kernel_size}\n' \
            f'- Kernel address:       0x{self.kernel_addr:x}\n' \
            f'- Ramdisk size:         {ramdisk_size}\n' \
            f'- Ramdisk address:      0x{self.ramdisk_addr:x}\n' \
            f'- Second stage size:    {second_size}\n' \
            f'- Second stage address: 0x{self.second_addr:x}\n' \
            f'- Kernel tags address:  0x{self.tags_addr:x}\n' \
            f'- Page size:            {self.page_size}\n' \
            f'- OS version:           0x{self.os_version:x}\n' \
            f'- Name:                 {self.name!r}\n' \
            f'- Kernel cmdline:       {self.cmdline!r}\n' \
            f'- ID:                   {self.id.hex()}\n' \
            f'- Extra kernel cmdline: {self.extra_cmdline!r}\n'

        if self.header_version >= 1:
            recovery_dtbo_size = len(self.recovery_dtbo) \
                if self.recovery_dtbo else 0

            result += \
                f'- Recovery dtbo size:   {recovery_dtbo_size}\n' \
                f'- Recovery dtbo offset: {self.recovery_dtbo_offset}\n'

        if self.header_version == 2:
            dtb_size = len(self.dtb) if self.dtb else 0

            result += \
                f'- Device tree size:     {dtb_size}\n' \
                f'- Device tree address:  {self.dtb_addr}\n'

        return result


class _BootImageV3Through4(BootImage):
    def __init__(self, f: typing.BinaryIO) -> None:
        super().__init__()

        # Common fields for both v3 and v4
        magic, kernel_size, ramdisk_size, os_version, header_size, reserved, \
            header_version, cmdline = BOOT_IMG_HDR_V3.unpack(
                util.read_exact(f, BOOT_IMG_HDR_V3.size))

        if magic != BOOT_MAGIC:
            raise WrongFormat(f'Unknown magic: {magic}')
        elif header_version not in (3, 4):
            raise WrongFormat(f'Unknown header version: {header_version}')

        # Parse v4 fields
        if header_version == 4:
            signature_size, = BOOT_IMG_HDR_V4_EXTRA.unpack(
                util.read_exact(f, BOOT_IMG_HDR_V4_EXTRA.size))

        if f.tell() != header_size:
            raise ValueError(f'Invalid header size: {header_size}')

        self.header_version = header_version
        self.os_version = os_version
        self.reserved = reserved
        self.cmdline = cmdline.rstrip(b'\0')

        padding.read_skip(f, PAGE_SIZE)

        if kernel_size > 0:
            self.kernel = util.read_exact(f, kernel_size)
            padding.read_skip(f, PAGE_SIZE)

        if ramdisk_size > 0:
            self.ramdisks.append(util.read_exact(f, ramdisk_size))
            padding.read_skip(f, PAGE_SIZE)

        if header_version == 4:
            # Don't preserve the signature. It is only used for VTS tests and
            # is not relevant for booting
            f.seek(signature_size, os.SEEK_CUR)
            padding.read_skip(f, PAGE_SIZE)

    def generate(self, f: typing.BinaryIO) -> None:
        if len(self.ramdisks) > 1:
            raise ValueError('Only one ramdisk is supported')
        elif self.second is not None:
            raise ValueError('Second stage bootloader is not supported')
        elif self.recovery_dtbo is not None:
            raise ValueError('Recovery dtbo/acpio is not supported')
        elif self.dtb is not None:
            raise ValueError('Device tree is not supported')
        elif self.bootconfig is not None:
            raise ValueError('Boot config is not supported')

        f.write(BOOT_IMG_HDR_V3.pack(
            BOOT_MAGIC,
            len(self.kernel) if self.kernel else 0,
            len(self.ramdisks[0]) if self.ramdisks else 0,
            self.os_version,
            BOOT_IMG_HDR_V3.size + (BOOT_IMG_HDR_V4_EXTRA.size
                                    if self.header_version == 4 else 0),
            self.reserved,
            self.header_version,
            self.cmdline,
        ))

        if self.header_version == 4:
            f.write(BOOT_IMG_HDR_V4_EXTRA.pack(
                # We don't care about the VTS signature
                0
            ))

        padding.write(f, PAGE_SIZE)

        if self.kernel:
            f.write(self.kernel)
            padding.write(f, PAGE_SIZE)

        if self.ramdisks:
            f.write(self.ramdisks[0])
            padding.write(f, PAGE_SIZE)

    def __str__(self) -> str:
        kernel_size = len(self.kernel) if self.kernel else 0
        ramdisk_size = len(self.ramdisks[0]) if self.ramdisks else 0

        return \
            f'Boot image v{self.header_version} header:\n' \
            f'- Kernel size:    {kernel_size}\n' \
            f'- Ramdisk size:   {ramdisk_size}\n' \
            f'- OS version:     0x{self.os_version:x}\n' \
            f'- Reserved:       {self.reserved.hex()}\n' \
            f'- Kernel cmdline: {self.cmdline!r}\n'


_RamdiskMeta = collections.namedtuple(
    '_RamdiskMeta', ['type', 'name', 'board_id'])


class _VendorBootImageV3Through4(BootImage):
    def __init__(self, f: typing.BinaryIO) -> None:
        super().__init__()

        # Common fields for both v3 and v4
        magic, header_version, page_size, kernel_addr, ramdisk_addr, \
            vendor_ramdisk_size, cmdline, tags_addr, name, header_size, \
            dtb_size, dtb_addr = VENDOR_BOOT_IMG_HDR_V3.unpack(
                util.read_exact(f, VENDOR_BOOT_IMG_HDR_V3.size))

        if magic != VENDOR_BOOT_MAGIC:
            raise WrongFormat(f'Unknown magic: {magic}')
        elif header_version not in (3, 4):
            raise WrongFormat(f'Unknown header version: {header_version}')

        # Parse v4 fields
        if header_version == 4:
            vendor_ramdisk_table_size, vendor_ramdisk_table_entry_num, \
                vendor_ramdisk_table_entry_size, bootconfig_size = \
                VENDOR_BOOT_IMG_HDR_V4_EXTRA.unpack(
                    util.read_exact(f, VENDOR_BOOT_IMG_HDR_V4_EXTRA.size))

            if vendor_ramdisk_table_entry_size != \
                    VENDOR_RAMDISK_TABLE_ENTRY_V4.size:
                raise ValueError('Invalid ramdisk table entry size: '
                                 f'{vendor_ramdisk_table_entry_size}')
            elif vendor_ramdisk_table_size != vendor_ramdisk_table_entry_num \
                    * vendor_ramdisk_table_entry_size:
                raise ValueError('Invalid ramdisk table size: '
                                 f'{vendor_ramdisk_table_size}')

        if f.tell() != header_size:
            raise ValueError(f'Invalid header size: {header_size}')

        self.page_size = page_size
        self.header_version = header_version
        self.kernel_addr = kernel_addr
        self.ramdisk_addr = ramdisk_addr
        self.cmdline = cmdline.rstrip(b'\0')
        self.tags_addr = tags_addr
        self.name = name.rstrip(b'\0')
        self.dtb_addr = dtb_addr

        padding.read_skip(f, page_size)

        vendor_ramdisk_offset = f.tell()

        if header_version == 3:
            # v3 has one big ramdisk
            self.ramdisks.append(util.read_exact(f, vendor_ramdisk_size))
        else:
            # v4 has multiple ramdisks, processed later
            f.seek(vendor_ramdisk_size, os.SEEK_CUR)

        padding.read_skip(f, page_size)

        if dtb_size > 0:
            self.dtb = util.read_exact(f, dtb_size)
            padding.read_skip(f, page_size)

        if header_version == 4:
            self.ramdisks_meta = []

            total_ramdisk_size = 0

            for _ in range(0, vendor_ramdisk_table_entry_num):
                ramdisk_size, ramdisk_offset, ramdisk_type, ramdisk_name, \
                    board_id = VENDOR_RAMDISK_TABLE_ENTRY_V4.unpack(
                        util.read_exact(f, VENDOR_RAMDISK_TABLE_ENTRY_V4.size))

                table_offset = f.tell()
                f.seek(vendor_ramdisk_offset + ramdisk_offset)

                self.ramdisks.append(util.read_exact(f, ramdisk_size))
                self.ramdisks_meta.append(_RamdiskMeta(
                    ramdisk_type,
                    ramdisk_name.rstrip(b'\0'),
                    board_id,
                ))

                f.seek(table_offset)

                total_ramdisk_size += ramdisk_size

            if total_ramdisk_size != vendor_ramdisk_size:
                raise ValueError('Invalid vendor ramdisk size: '
                                 f'{vendor_ramdisk_size}')

            padding.read_skip(f, page_size)

            if bootconfig_size > 0:
                self.bootconfig = util.read_exact(f, bootconfig_size)
                padding.read_skip(f, page_size)

    def generate(self, f: typing.BinaryIO) -> None:
        if self.header_version == 3:
            if len(self.ramdisks) > 1:
                raise ValueError('Only one ramdisk is supported')
            elif self.bootconfig is not None:
                raise ValueError('Boot config is not supported')
        else:
            if len(self.ramdisks) != len(self.ramdisks_meta):
                raise ValueError('Mismatched ramdisk and ramdisk_meta')

        if self.second is not None:
            raise ValueError('Second stage bootloader is not supported')
        elif self.recovery_dtbo is not None:
            raise ValueError('Recovery dtbo/acpio is not supported')

        vendor_ramdisk_size = sum(len(r) for r in self.ramdisks)

        f.write(VENDOR_BOOT_IMG_HDR_V3.pack(
            VENDOR_BOOT_MAGIC,
            self.header_version,
            self.page_size,
            self.kernel_addr,
            self.ramdisk_addr,
            vendor_ramdisk_size,
            self.cmdline,
            self.tags_addr,
            self.name,
            VENDOR_BOOT_IMG_HDR_V3.size + (
                VENDOR_BOOT_IMG_HDR_V4_EXTRA.size
                if self.header_version == 4 else 0),
            len(self.dtb) if self.dtb else 0,
            self.dtb_addr,
        ))

        if self.header_version == 4:
            f.write(VENDOR_BOOT_IMG_HDR_V4_EXTRA.pack(
                len(self.ramdisks) * VENDOR_RAMDISK_TABLE_ENTRY_V4.size,
                len(self.ramdisks),
                VENDOR_RAMDISK_TABLE_ENTRY_V4.size,
                len(self.bootconfig) if self.bootconfig else 0,
            ))

        padding.write(f, self.page_size)

        for ramdisk in self.ramdisks:
            f.write(ramdisk)

        padding.write(f, self.page_size)

        if self.dtb:
            f.write(self.dtb)
            padding.write(f, self.page_size)

        if self.header_version == 4:
            ramdisk_offset = 0

            for ramdisk, meta in zip(self.ramdisks, self.ramdisks_meta):
                f.write(VENDOR_RAMDISK_TABLE_ENTRY_V4.pack(
                    len(ramdisk),
                    ramdisk_offset,
                    meta.type,
                    meta.name,
                    meta.board_id,
                ))

                ramdisk_offset += len(ramdisk)

            padding.write(f, self.page_size)

            if self.bootconfig:
                f.write(self.bootconfig)
                padding.write(f, self.page_size)

    def __str__(self) -> str:
        dtb_size = len(self.dtb) if self.dtb else 0

        result = \
            f'Vendor boot image v{self.header_version} header:\n' \
            f'- Page size:           {self.page_size}\n' \
            f'- Kernel address:      0x{self.kernel_addr:x}\n' \
            f'- Ramdisk address:     0x{self.ramdisk_addr:x}\n' \
            f'- Kernel cmdline:      {self.cmdline!r}\n' \
            f'- Kernel tags address: 0x{self.tags_addr:x}\n' \
            f'- Name:                {self.name!r}\n' \
            f'- Device tree size:    {dtb_size}\n' \
            f'- Device tree address: {self.dtb_addr}\n'

        if self.header_version == 4:
            for ramdisk, meta in zip(self.ramdisks, self.ramdisks_meta):
                result += \
                    '- Ramdisk:\n' \
                    f'  - Size:     {len(ramdisk)}\n' \
                    f'  - Type:     {meta.type}\n' \
                    f'  - Name:     {meta.name}\n' \
                    f'  - Board ID: {meta.board_id.hex()}\n'

            bootconfig_size = len(self.bootconfig) if self.bootconfig else 0

            result += f'- Bootconfig size:     {bootconfig_size}\n'

        return result


def load_autodetect(f: typing.BinaryIO) -> BootImage:
    for cls in (
        _BootImageV0Through2,
        _BootImageV3Through4,
        _VendorBootImageV3Through4,
    ):
        try:
            f.seek(0)
            return cls(f)
        except WrongFormat:
            continue

    raise ValueError('Unknown boot image format')
