// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    io::{self, Cursor, Read, Seek, Write},
    mem,
    str::{self, Utf8Error},
};

use bstr::ByteSlice;
use num_traits::ToPrimitive;
use ring::digest::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zerocopy::{little_endian, FromBytes, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    crypto::RsaSigningKey,
    format::{
        avb::{self, Descriptor, Header},
        padding::{self, ZeroPadding},
    },
    stream::{
        CountingReader, CountingWriter, FromReader, HashingWriter, ReadFixedSizeExt, ToWriter,
    },
    util::{self, NumBytes, OutOfBoundsError},
};

pub const BOOT_MAGIC: [u8; 8] = *b"ANDROID!";
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;

pub const VENDOR_BOOT_MAGIC: [u8; 8] = *b"VNDRBOOT";
pub const VENDOR_BOOT_ARGS_SIZE: usize = 2048;
pub const VENDOR_BOOT_NAME_SIZE: usize = 16;

pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;
pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: usize = 16;

pub const PAGE_SIZE: u32 = 4096;

const HDR_V4_SIGNATURE_SIZE: u64 = 4096;

/// Maximum size of any individual boot image component, like the kernel. This
/// limit is currently 64 MiB, which should be sufficient since there is no
/// known device where the entire boot image exceeds this size.
const COMPONENT_MAX_SIZE: u32 = 64 * 1024 * 1024;
/// Maximum size of the bootconfig component in vendor v4 images. This limit is
/// currently 1 KiB, which is ~25x the size of the Pixel 7 Pro stock image's
/// bootconfig.
const BOOTCONFIG_MAX_SIZE: u32 = 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown boot image format")]
    UnknownFormat,
    #[error("Unknown magic: {0:?}")]
    UnknownMagic([u8; 8]),
    #[error("Unknown header version: {0}")]
    UnknownHeaderVersion(u32),
    #[error("{0:?} field is not UTF-8 encoded: {data:?}", data = .2.as_bstr())]
    StringNotUtf8(&'static str, #[source] Utf8Error, Vec<u8>),
    #[error("{0:?} field is too long (>{1}): {2:?}")]
    StringTooLong(&'static str, usize, String),
    #[error("{0:?} field is out of bounds")]
    IntOutOfBounds(&'static str, #[source] OutOfBoundsError),
    #[error("{0:?} overflowed integer bounds during calculations")]
    IntOverflow(&'static str),
    #[error("Page size must not be zero")]
    PageSizeZero,
    #[error("Invalid header size for boot image type: {0}")]
    InvalidHeaderSize(u32),
    #[error("Mismatched ramdisk ({ramdisks}) and metadata ({metas}) counts")]
    MismatchedRamdiskCounts { ramdisks: usize, metas: usize },
    #[error("Vendor V3 only supports a single ramdisk (count: {0})")]
    VendorV3TooManyRamdisks(usize),
    #[error("Invalid vendor v4 total ramdisk size: {field_value} != {total_size}")]
    VendorV4InvalidRamdiskSize { field_value: u32, total_size: u32 },
    #[error("Invalid vendor v4 ramdisk table size: {actual} != {expected}")]
    VendorV4InvalidRamdiskTableSize { actual: u32, expected: u32 },
    #[error("Invalid vendor v4 ramdisk entry size: {0}")]
    VendorV4InvalidRamdiskEntrySize(u32),
    #[error("Invalid vendor v4 ramdisk entry [{index}] offset: {field_value} != {reader_pos}")]
    VendorV4InvalidRamdiskEntryOffset {
        index: u32,
        field_value: u32,
        reader_pos: u64,
    },
    #[error("VTS signature is missing hash descriptor")]
    MissingHashDescriptor,
    #[error("Failed to load VTS AVB signature")]
    VtsAvbLoad(#[source] avb::Error),
    #[error("Failed to save VTS AVB signature")]
    VtsAvbSave(#[source] avb::Error),
    #[error("Failed to generate VTS AVB signature")]
    VtsAvbSign(#[source] avb::Error),
    #[error("Failed to read boot image data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write boot image data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub trait BootImageExt {
    fn header_version(&self) -> u32;

    fn header_size(&self) -> u32;
}

/// Raw on-disk layout for the v0 image header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawV0 {
    /// Magic value. This should be equal to [`BOOT_MAGIC`].
    magic: [u8; 8],
    kernel_size: little_endian::U32,
    kernel_addr: little_endian::U32,
    ramdisk_size: little_endian::U32,
    ramdisk_addr: little_endian::U32,
    second_size: little_endian::U32,
    second_addr: little_endian::U32,
    tags_addr: little_endian::U32,
    page_size: little_endian::U32,
    header_version: little_endian::U32,
    os_version: little_endian::U32,
    name: [u8; BOOT_NAME_SIZE],
    cmdline: [u8; BOOT_ARGS_SIZE],
    id: [little_endian::U32; 8],
    extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],
}

/// Raw on-disk layout for the extra v1 image header fields.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawV1Extra {
    recovery_dtbo_size: little_endian::U32,
    recovery_dtbo_offset: little_endian::U64,
    header_size: little_endian::U32,
}

/// Raw on-disk layout for the extra v2 image header fields.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawV2Extra {
    dtb_size: little_endian::U32,
    dtb_addr: little_endian::U64,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct V1Extra {
    pub recovery_dtbo_offset: u64,
    #[serde(skip)]
    pub recovery_dtbo: Vec<u8>,
}

impl fmt::Debug for V1Extra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V1Extra")
            .field("recovery_dtbo_offset", &self.recovery_dtbo_offset)
            .field("recovery_dtbo", &NumBytes(self.recovery_dtbo.len()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct V2Extra {
    pub dtb_addr: u64,
    #[serde(skip)]
    pub dtb: Vec<u8>,
}

impl fmt::Debug for V2Extra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2Extra")
            .field("dtb_addr", &self.dtb_addr)
            .field("dtb", &NumBytes(self.dtb.len()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct BootImageV0Through2 {
    // v0+ fields.
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    pub os_version: u32,
    pub name: String,
    pub cmdline: String,
    pub id: [u32; 8],
    pub extra_cmdline: String,
    // Images.
    #[serde(skip)]
    pub kernel: Vec<u8>,
    #[serde(skip)]
    pub ramdisk: Vec<u8>,
    #[serde(skip)]
    pub second: Vec<u8>,
    // Extra fields for newer versions.
    pub v1_extra: Option<V1Extra>,
    pub v2_extra: Option<V2Extra>,
}

impl fmt::Debug for BootImageV0Through2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootImageV0Through2")
            .field("kernel_addr", &self.kernel_addr)
            .field("ramdisk_addr", &self.ramdisk_addr)
            .field("second_addr", &self.second_addr)
            .field("tags_addr", &self.tags_addr)
            .field("page_size", &self.page_size)
            .field("header_version", &self.header_version())
            .field("os_version", &self.os_version)
            .field("name", &self.name)
            .field("cmdline", &self.cmdline)
            .field("id", &self.id)
            .field("extra_cmdline", &self.extra_cmdline)
            .field("kernel", &NumBytes(self.kernel.len()))
            .field("ramdisk", &NumBytes(self.ramdisk.len()))
            .field("second", &NumBytes(self.second.len()))
            .field("v1_extra", &self.v1_extra)
            .field("v2_extra", &self.v2_extra)
            .finish()
    }
}

impl fmt::Display for BootImageV0Through2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Boot image v{} header:", self.header_version())?;
        writeln!(f, "- Kernel size:          {}", self.kernel.len())?;
        writeln!(f, "- Kernel address:       {:#x}", self.kernel_addr)?;
        writeln!(f, "- Ramdisk size:         {}", self.ramdisk.len())?;
        writeln!(f, "- Ramdisk address:      {:#x}", self.ramdisk_addr)?;
        writeln!(f, "- Second stage size:    {}", self.second.len())?;
        writeln!(f, "- Second stage address: {:#x}", self.second_addr)?;
        writeln!(f, "- Kernel tags address:  {:#x}", self.tags_addr)?;
        writeln!(f, "- Page size:            {}", self.page_size)?;
        writeln!(f, "- OS version:           {:#x}", self.os_version)?;
        writeln!(f, "- Name:                 {:?}", self.name)?;
        writeln!(f, "- Kernel cmdline:       {:?}", self.cmdline)?;
        writeln!(f, "- ID:                   {:?}", self.id)?;
        write!(f, "- Extra kernel cmdline: {:?}", self.extra_cmdline)?;

        if let Some(v1) = &self.v1_extra {
            writeln!(f)?;
            writeln!(f, "- Recovery dtbo size:   {}", v1.recovery_dtbo.len())?;
            write!(f, "- Recovery dtbo offset: {}", v1.recovery_dtbo_offset)?;
        }

        if let Some(v2) = &self.v2_extra {
            writeln!(f)?;
            writeln!(f, "- Device tree size:     {}", v2.dtb.len())?;
            write!(f, "- Device tree address:  {:#x}", v2.dtb_addr)?;
        }

        Ok(())
    }
}

impl BootImageExt for BootImageV0Through2 {
    fn header_version(&self) -> u32 {
        if self.v2_extra.is_some() {
            2
        } else if self.v1_extra.is_some() {
            1
        } else {
            0
        }
    }

    fn header_size(&self) -> u32 {
        let version = self.header_version();
        let mut size = mem::size_of::<RawV0>();

        if version >= 1 {
            size += mem::size_of::<RawV1Extra>();
        }
        if version == 2 {
            size += mem::size_of::<RawV2Extra>();
        }

        size as u32
    }
}

impl<R: Read> FromReader<R> for BootImageV0Through2 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let raw_v0 =
            RawV0::read_from_io(&mut reader).map_err(|e| Error::DataRead("Boot::V0::header", e))?;

        if raw_v0.magic != BOOT_MAGIC {
            return Err(Error::UnknownMagic(raw_v0.magic));
        }

        let header_version = raw_v0.header_version.get();
        if header_version > 2 {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        let kernel_size = util::check_bounds(raw_v0.kernel_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::kernel_size", e))?;
        let ramdisk_size = util::check_bounds(raw_v0.ramdisk_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::ramdisk_size", e))?;
        let second_size = util::check_bounds(raw_v0.second_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::second_size", e))?;

        let page_size = raw_v0.page_size.get();
        if page_size == 0 {
            return Err(Error::PageSizeZero);
        }

        let name = raw_v0.name.trim_end_padding();
        let name = str::from_utf8(name)
            .map_err(|e| Error::StringNotUtf8("Boot::V0::name", e, name.to_vec()))?;

        let cmdline = raw_v0.cmdline.trim_end_padding();
        let cmdline = str::from_utf8(cmdline)
            .map_err(|e| Error::StringNotUtf8("Boot::V0::cmdline", e, cmdline.to_vec()))?;

        let extra_cmdline = raw_v0.extra_cmdline.trim_end_padding();
        let extra_cmdline = str::from_utf8(extra_cmdline).map_err(|e| {
            Error::StringNotUtf8("Boot::V0::extra_cmdline", e, extra_cmdline.to_vec())
        })?;

        struct V1Data {
            v1_extra: V1Extra,
            recovery_dtbo_size: u32,
            header_size: u32,
        }

        let mut v1_data = if header_version >= 1 {
            let raw_v1 = RawV1Extra::read_from_io(&mut reader)
                .map_err(|e| Error::DataRead("Boot::V1::header", e))?;

            let recovery_dtbo_size =
                util::check_bounds(raw_v1.recovery_dtbo_size.get(), ..=COMPONENT_MAX_SIZE)
                    .map_err(|e| Error::IntOutOfBounds("Boot::V1::recovery_dtbo_size", e))?;

            let v1_extra = V1Extra {
                recovery_dtbo_offset: raw_v1.recovery_dtbo_offset.get(),
                recovery_dtbo: vec![],
            };

            Some(V1Data {
                v1_extra,
                recovery_dtbo_size,
                header_size: raw_v1.header_size.get(),
            })
        } else {
            None
        };

        struct V2Data {
            v2_extra: V2Extra,
            dtb_size: u32,
        }

        let mut v2_data = if header_version == 2 {
            let raw_v2 = RawV2Extra::read_from_io(&mut reader)
                .map_err(|e| Error::DataRead("Boot::V2::header", e))?;

            let dtb_size = util::check_bounds(raw_v2.dtb_size.get(), ..=COMPONENT_MAX_SIZE)
                .map_err(|e| Error::IntOutOfBounds("Boot::V2::dtb_size", e))?;

            let v2_extra = V2Extra {
                dtb_addr: raw_v2.dtb_addr.get(),
                dtb: vec![],
            };

            Some(V2Data { v2_extra, dtb_size })
        } else {
            None
        };

        if let Some(v1) = &v1_data {
            if reader
                .stream_position()
                .map_err(|e| Error::DataRead("Boot::V1::header_size", e))?
                != u64::from(v1.header_size)
            {
                return Err(Error::InvalidHeaderSize(v1.header_size));
            }
        }

        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Boot::V0::header_padding", e))?;

        let kernel = reader
            .read_vec_exact(kernel_size as usize)
            .map_err(|e| Error::DataRead("Boot::V0::kernel", e))?;
        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Boot::V0::kernel_padding", e))?;

        let ramdisk = reader
            .read_vec_exact(ramdisk_size as usize)
            .map_err(|e| Error::DataRead("Boot::V0::ramdisk", e))?;
        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Boot::V0::ramdisk_padding", e))?;

        let second = reader
            .read_vec_exact(second_size as usize)
            .map_err(|e| Error::DataRead("Boot::V0::second", e))?;
        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Boot::V0::second_padding", e))?;

        if let Some(v1) = &mut v1_data {
            v1.v1_extra.recovery_dtbo = reader
                .read_vec_exact(v1.recovery_dtbo_size as usize)
                .map_err(|e| Error::DataRead("Boot::V1::recovery_dtbo", e))?;
            padding::read_discard(&mut reader, page_size.into())
                .map_err(|e| Error::DataRead("Boot::V1::recovery_dtbo_padding", e))?;
        }

        if let Some(v2) = &mut v2_data {
            v2.v2_extra.dtb = reader
                .read_vec_exact(v2.dtb_size as usize)
                .map_err(|e| Error::DataRead("Boot::V2::dtb", e))?;
            padding::read_discard(&mut reader, page_size.into())
                .map_err(|e| Error::DataRead("Boot::V2::dtb_padding", e))?;
        }

        let image = Self {
            kernel_addr: raw_v0.kernel_addr.get(),
            ramdisk_addr: raw_v0.ramdisk_addr.get(),
            second_addr: raw_v0.second_addr.get(),
            tags_addr: raw_v0.tags_addr.get(),
            page_size,
            os_version: raw_v0.os_version.get(),
            name: name.to_owned(),
            cmdline: cmdline.to_owned(),
            id: raw_v0.id.map(|id| id.get()),
            extra_cmdline: extra_cmdline.to_owned(),
            kernel,
            ramdisk,
            second,
            v1_extra: v1_data.map(|d| d.v1_extra),
            v2_extra: v2_data.map(|d| d.v2_extra),
        };

        Ok(image)
    }
}

impl<W: Write> ToWriter<W> for BootImageV0Through2 {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        util::check_bounds(self.kernel.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::kernel_size", e))?;
        util::check_bounds(self.ramdisk.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::ramdisk_size", e))?;
        util::check_bounds(self.second.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Boot::V0::second_size", e))?;

        if self.page_size == 0 {
            return Err(Error::PageSizeZero);
        }

        if let Some(v1) = &self.v1_extra {
            util::check_bounds(v1.recovery_dtbo.len(), ..=COMPONENT_MAX_SIZE as usize)
                .map_err(|e| Error::IntOutOfBounds("Boot::V1::recovery_dtbo_size", e))?;
        }
        if let Some(v2) = &self.v2_extra {
            util::check_bounds(v2.dtb.len(), ..=COMPONENT_MAX_SIZE as usize)
                .map_err(|e| Error::IntOutOfBounds("Boot::V2::dtb_size", e))?;
        }

        let name = self
            .name
            .as_bytes()
            .to_padded_array::<BOOT_NAME_SIZE>()
            .ok_or_else(|| {
                Error::StringTooLong("Boot::V0::name", BOOT_NAME_SIZE, self.name.clone())
            })?;
        let cmdline = self
            .cmdline
            .as_bytes()
            .to_padded_array::<BOOT_ARGS_SIZE>()
            .ok_or_else(|| {
                Error::StringTooLong("Boot::V0::cmdline", BOOT_ARGS_SIZE, self.cmdline.clone())
            })?;
        let extra_cmdline = self
            .extra_cmdline
            .as_bytes()
            .to_padded_array::<BOOT_EXTRA_ARGS_SIZE>()
            .ok_or_else(|| {
                Error::StringTooLong(
                    "Boot::V0::extra_cmdline",
                    BOOT_EXTRA_ARGS_SIZE,
                    self.extra_cmdline.clone(),
                )
            })?;

        let mut writer = CountingWriter::new(writer);

        let raw_v0 = RawV0 {
            magic: BOOT_MAGIC,
            kernel_size: (self.kernel.len() as u32).into(),
            kernel_addr: self.kernel_addr.into(),
            ramdisk_size: (self.ramdisk.len() as u32).into(),
            ramdisk_addr: self.ramdisk_addr.into(),
            second_size: (self.second.len() as u32).into(),
            second_addr: self.second_addr.into(),
            tags_addr: self.tags_addr.into(),
            page_size: self.page_size.into(),
            header_version: self.header_version().into(),
            os_version: self.os_version.into(),
            name,
            cmdline,
            id: self.id.map(|id| id.into()),
            extra_cmdline,
        };

        raw_v0
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Boot::V0::header", e))?;

        if let Some(v1) = &self.v1_extra {
            let raw_v1 = RawV1Extra {
                recovery_dtbo_size: (v1.recovery_dtbo.len() as u32).into(),
                recovery_dtbo_offset: v1.recovery_dtbo_offset.into(),
                header_size: self.header_size().into(),
            };

            raw_v1
                .write_to_io(&mut writer)
                .map_err(|e| Error::DataWrite("Boot::V1::header", e))?;
        }

        if let Some(v2) = &self.v2_extra {
            let raw_v2 = RawV2Extra {
                dtb_size: (v2.dtb.len() as u32).into(),
                dtb_addr: v2.dtb_addr.into(),
            };

            raw_v2
                .write_to_io(&mut writer)
                .map_err(|e| Error::DataWrite("Boot::V2::header", e))?;
        }

        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Boot::V0::header_padding", e))?;

        writer
            .write_all(&self.kernel)
            .map_err(|e| Error::DataWrite("Boot::V0::kernel", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Boot::V0::kernel_padding", e))?;

        writer
            .write_all(&self.ramdisk)
            .map_err(|e| Error::DataWrite("Boot::V0::ramdisk", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Boot::V0::ramdisk_padding", e))?;

        writer
            .write_all(&self.second)
            .map_err(|e| Error::DataWrite("Boot::V0::second", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Boot::V0::second_padding", e))?;

        if let Some(v1) = &self.v1_extra {
            writer
                .write_all(&v1.recovery_dtbo)
                .map_err(|e| Error::DataWrite("Boot::V1::recovery_dtbo", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())
                .map_err(|e| Error::DataWrite("Boot::V1::recovery_dtbo_padding", e))?;
        }

        if let Some(v2) = &self.v2_extra {
            writer
                .write_all(&v2.dtb)
                .map_err(|e| Error::DataWrite("Boot::V2::dtb", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())
                .map_err(|e| Error::DataWrite("Boot::V2::dtb_padding", e))?;
        }

        Ok(())
    }
}

/// Raw on-disk layout for the v3 image header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawV3 {
    /// Magic value. This should be equal to [`BOOT_MAGIC`].
    magic: [u8; 8],
    kernel_size: little_endian::U32,
    ramdisk_size: little_endian::U32,
    os_version: little_endian::U32,
    header_size: little_endian::U32,
    reserved: [little_endian::U32; 4],
    header_version: little_endian::U32,
    cmdline: [u8; BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE],
}

/// Raw on-disk layout for the extra v4 image header fields.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawV4Extra {
    signature_size: little_endian::U32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct V4Extra {
    #[serde(skip)]
    pub signature: Option<Header>,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct BootImageV3Through4 {
    // v3+ fields.
    pub os_version: u32,
    pub reserved: [u32; 4],
    pub cmdline: String,
    pub v4_extra: Option<V4Extra>,
    // Images.
    #[serde(skip)]
    pub kernel: Vec<u8>,
    #[serde(skip)]
    pub ramdisk: Vec<u8>,
}

impl fmt::Debug for BootImageV3Through4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootImageV3Through4")
            .field("os_version", &self.os_version)
            .field("reserved", &self.reserved)
            .field("cmdline", &self.cmdline)
            .field("v4_extra", &self.v4_extra)
            .field("kernel", &NumBytes(self.kernel.len()))
            .field("ramdisk", &NumBytes(self.ramdisk.len()))
            .finish()
    }
}

impl fmt::Display for BootImageV3Through4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Boot image v{} header:", self.header_version())?;
        writeln!(f, "- Kernel size:       {}", self.kernel.len())?;
        writeln!(f, "- Ramdisk size:      {}", self.ramdisk.len())?;
        writeln!(f, "- OS version:        {:#x}", self.os_version)?;
        writeln!(f, "- Reserved:          {:?}", self.reserved)?;
        write!(f, "- Kernel cmdline:    {:?}", self.cmdline)?;

        if let Some(v4) = &self.v4_extra {
            writeln!(f)?;
            write!(f, "- Has VTS signature: {:?}", v4.signature.is_some())?;
        }

        Ok(())
    }
}

impl BootImageExt for BootImageV3Through4 {
    fn header_version(&self) -> u32 {
        if self.v4_extra.is_some() {
            4
        } else {
            3
        }
    }

    fn header_size(&self) -> u32 {
        let version = self.header_version();
        let mut size = mem::size_of::<RawV3>();

        if version >= 4 {
            size += mem::size_of::<RawV4Extra>();
        }

        size as u32
    }
}

impl<R: Read> FromReader<R> for BootImageV3Through4 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let raw_v3 =
            RawV3::read_from_io(&mut reader).map_err(|e| Error::DataRead("Boot::V3::header", e))?;

        if raw_v3.magic != BOOT_MAGIC {
            return Err(Error::UnknownMagic(raw_v3.magic));
        }

        let header_version = raw_v3.header_version.get();
        if !(3..=4).contains(&header_version) {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        let kernel_size = util::check_bounds(raw_v3.kernel_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Boot::V3::kernel_size", e))?;
        let ramdisk_size = util::check_bounds(raw_v3.ramdisk_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Boot::V3::ramdisk_size", e))?;
        let header_size = raw_v3.header_size.get();

        let cmdline = raw_v3.cmdline.trim_end_padding();
        let cmdline = str::from_utf8(cmdline)
            .map_err(|e| Error::StringNotUtf8("Boot::V3::cmdline", e, cmdline.to_vec()))?;

        let signature_size = if header_version == 4 {
            let raw_v4 = RawV4Extra::read_from_io(&mut reader)
                .map_err(|e| Error::DataRead("Boot::V4::header", e))?;

            let size =
                util::check_bounds(raw_v4.signature_size.get(), ..=HDR_V4_SIGNATURE_SIZE as u32)
                    .map_err(|e| Error::IntOutOfBounds("Boot::V4::signature_size", e))?;

            Some(size)
        } else {
            None
        };

        if reader
            .stream_position()
            .map_err(|e| Error::DataRead("Boot::V3::header_size", e))?
            != u64::from(header_size)
        {
            return Err(Error::InvalidHeaderSize(header_size));
        }

        padding::read_discard(&mut reader, PAGE_SIZE.into())
            .map_err(|e| Error::DataRead("Boot::V3::header_padding", e))?;

        let kernel = reader
            .read_vec_exact(kernel_size as usize)
            .map_err(|e| Error::DataRead("Boot::V3::kernel", e))?;
        padding::read_discard(&mut reader, PAGE_SIZE.into())
            .map_err(|e| Error::DataRead("Boot::V3::kernel_padding", e))?;

        let ramdisk = reader
            .read_vec_exact(ramdisk_size as usize)
            .map_err(|e| Error::DataRead("Boot::V3::ramdisk", e))?;
        padding::read_discard(&mut reader, PAGE_SIZE.into())
            .map_err(|e| Error::DataRead("Boot::V3::ramdisk_padding", e))?;

        // Don't preserve the signature. It is only used for VTS tests and is
        // not relevant for booting.
        let v4_extra = if let Some(s) = signature_size {
            // OnePlus images have an invalid signature consisting of all zeros.
            let data = reader
                .read_vec_exact(s as usize)
                .map_err(|e| Error::DataRead("Boot::V4::signature", e))?;

            let signature = if s > 0 && !util::is_zero(&data) {
                let avb_header =
                    Header::from_reader(Cursor::new(data)).map_err(Error::VtsAvbLoad)?;

                Some(avb_header)
            } else {
                None
            };

            padding::read_discard(&mut reader, PAGE_SIZE.into())
                .map_err(|e| Error::DataRead("Boot::V4::signature_padding", e))?;

            Some(V4Extra { signature })
        } else {
            None
        };

        let image = Self {
            os_version: raw_v3.os_version.get(),
            reserved: raw_v3.reserved.map(|r| r.get()),
            cmdline: cmdline.to_owned(),
            v4_extra,
            kernel,
            ramdisk,
        };

        Ok(image)
    }
}

impl BootImageV3Through4 {
    fn to_writer_internal(&self, writer: impl Write, skip_v4_sig: bool) -> Result<()> {
        util::check_bounds(self.kernel.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Boot::V3::kernel_size", e))?;
        util::check_bounds(self.ramdisk.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Boot::V3::ramdisk_size", e))?;

        let cmdline = self
            .cmdline
            .as_bytes()
            .to_padded_array::<{ BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE }>()
            .ok_or_else(|| {
                Error::StringTooLong(
                    "Boot::V3::cmdline",
                    BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE,
                    self.cmdline.clone(),
                )
            })?;

        let mut writer = CountingWriter::new(writer);

        let raw_v3 = RawV3 {
            magic: BOOT_MAGIC,
            kernel_size: (self.kernel.len() as u32).into(),
            ramdisk_size: (self.ramdisk.len() as u32).into(),
            os_version: self.os_version.into(),
            header_size: self.header_size().into(),
            reserved: self.reserved.map(|r| r.into()),
            header_version: self.header_version().into(),
            cmdline,
        };

        raw_v3
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Boot::V3::header", e))?;

        let v4_signature = if let Some(v4) = &self.v4_extra {
            let mut sig_writer = Cursor::new(Vec::new());

            if let Some(s) = &v4.signature {
                s.to_writer(&mut sig_writer).map_err(Error::VtsAvbSave)?;

                let size = sig_writer
                    .stream_position()
                    .map_err(|e| Error::DataWrite("Boot::V4::signature_size", e))?;

                // The VTS signature is always a fixed size.
                util::check_bounds(size, ..=HDR_V4_SIGNATURE_SIZE)
                    .map_err(|e| Error::IntOutOfBounds("Boot::V4::signature_size", e))?;

                padding::write_zeros(&mut sig_writer, HDR_V4_SIGNATURE_SIZE)
                    .map_err(|e| Error::DataWrite("Boot::V4::signature_inner_padding", e))?;
            }

            let sig = sig_writer.into_inner();

            let raw_v4 = RawV4Extra {
                signature_size: (sig.len() as u32).into(),
            };

            raw_v4
                .write_to_io(&mut writer)
                .map_err(|e| Error::DataWrite("Boot::V4::header", e))?;

            Some(sig)
        } else {
            None
        };

        padding::write_zeros(&mut writer, PAGE_SIZE.into())
            .map_err(|e| Error::DataWrite("Boot::V3::header_padding", e))?;

        writer
            .write_all(&self.kernel)
            .map_err(|e| Error::DataWrite("Boot::V3::kernel", e))?;
        padding::write_zeros(&mut writer, PAGE_SIZE.into())
            .map_err(|e| Error::DataWrite("Boot::V3::kernel_padding", e))?;

        writer
            .write_all(&self.ramdisk)
            .map_err(|e| Error::DataWrite("Boot::V3::ramdisk", e))?;
        padding::write_zeros(&mut writer, PAGE_SIZE.into())
            .map_err(|e| Error::DataWrite("Boot::V3::ramdisk_padding", e))?;

        if !skip_v4_sig {
            if let Some(sig) = v4_signature {
                writer
                    .write_all(&sig)
                    .map_err(|e| Error::DataWrite("Boot::V4::signature", e))?;
                padding::write_zeros(&mut writer, PAGE_SIZE.into())
                    .map_err(|e| Error::DataWrite("Boot::V4::signature_padding", e))?;
            }
        }

        Ok(())
    }

    /// Sign the boot image with a legacy VTS signature. Returns true if the
    /// image was successfully signed. Returns false if there's no vbmeta
    /// structure to sign in [`V4Extra::signature`].
    pub fn sign(&mut self, key: &RsaSigningKey) -> Result<bool> {
        let mut context = Context::new(&ring::digest::SHA256);
        let image_size;

        if let Some(v4) = &self.v4_extra {
            if let Some(signature) = &v4.signature {
                // The hash includes everything but the signature at the end.
                let descriptor = signature
                    .descriptors
                    .iter()
                    .find_map(|d| match d {
                        Descriptor::Hash(h) => Some(h),
                        _ => None,
                    })
                    .ok_or(Error::MissingHashDescriptor)?;

                if descriptor.hash_algorithm != "sha256" {
                    return Err(Error::VtsAvbSign(avb::Error::UnsupportedHashAlgorithm(
                        descriptor.hash_algorithm.clone(),
                    )));
                }

                context.update(&descriptor.salt);

                let hashing_writer = HashingWriter::new(io::sink(), context);
                let mut counting_writer = CountingWriter::new(hashing_writer);
                self.to_writer_internal(&mut counting_writer, true)?;

                let (hashing_writer, s) = counting_writer.finish();
                let (_, c) = hashing_writer.finish();

                context = c;
                image_size = s;
            } else {
                // V4 with no signature.
                return Ok(false);
            }
        } else {
            // V3.
            return Ok(false);
        }

        // Reborrow mutably.
        let v4 = self.v4_extra.as_mut().unwrap();
        let signature = v4.signature.as_mut().unwrap();
        let descriptor = signature
            .descriptors
            .iter_mut()
            .find_map(|d| match d {
                Descriptor::Hash(h) => Some(h),
                _ => None,
            })
            .unwrap();

        descriptor.image_size = image_size;
        descriptor.root_digest = context.finish().as_ref().to_vec();
        signature.sign(key).map_err(Error::VtsAvbSign)?;

        Ok(true)
    }
}

impl<W: Write> ToWriter<W> for BootImageV3Through4 {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        self.to_writer_internal(writer, false)
    }
}

/// Raw on-disk layout for the vendor v3 image header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawVendorV3 {
    /// Magic value. This should be equal to [`VENDOR_BOOT_MAGIC`].
    magic: [u8; 8],
    header_version: little_endian::U32,
    page_size: little_endian::U32,
    kernel_addr: little_endian::U32,
    ramdisk_addr: little_endian::U32,
    vendor_ramdisk_size: little_endian::U32,
    cmdline: [u8; VENDOR_BOOT_ARGS_SIZE],
    tags_addr: little_endian::U32,
    name: [u8; VENDOR_BOOT_NAME_SIZE],
    header_size: little_endian::U32,
    dtb_size: little_endian::U32,
    dtb_addr: little_endian::U64,
}

/// Raw on-disk layout for the extra vendor v4 image header fields.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawVendorV4Extra {
    vendor_ramdisk_table_size: little_endian::U32,
    vendor_ramdisk_table_entry_num: little_endian::U32,
    vendor_ramdisk_table_entry_size: little_endian::U32,
    bootconfig_size: little_endian::U32,
}

/// Raw on-disk layout for the vendor v4 ramdisk table entry.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(packed)]
struct RawVendorV4RamdiskTableEntry {
    ramdisk_size: little_endian::U32,
    ramdisk_offset: little_endian::U32,
    ramdisk_type: little_endian::U32,
    ramdisk_name: [u8; VENDOR_RAMDISK_NAME_SIZE],
    board_id: [little_endian::U32; VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE],
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RamdiskMeta {
    pub ramdisk_type: u32,
    pub ramdisk_name: String,
    pub board_id: [u32; VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE],
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct VendorV4Extra {
    pub ramdisk_metas: Vec<RamdiskMeta>,
    #[serde(skip)]
    pub bootconfig: String,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct VendorBootImageV3Through4 {
    pub page_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub cmdline: String,
    pub tags_addr: u32,
    pub name: String,
    #[serde(skip)]
    pub dtb: Vec<u8>,
    pub dtb_addr: u64,
    #[serde(skip)]
    pub ramdisks: Vec<Vec<u8>>,
    pub v4_extra: Option<VendorV4Extra>,
}

impl fmt::Debug for VendorBootImageV3Through4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorBootImageV3Through4")
            .field("page_size", &self.page_size)
            .field("kernel_addr", &self.kernel_addr)
            .field("ramdisk_addr", &self.ramdisk_addr)
            .field("cmdline", &self.cmdline)
            .field("tags_addr", &self.tags_addr)
            .field("name", &self.name)
            .field("dtb", &NumBytes(self.dtb.len()))
            .field("dtb_addr", &self.dtb_addr)
            .field(
                "ramdisks",
                &self
                    .ramdisks
                    .iter()
                    .map(|r| NumBytes(r.len()))
                    .collect::<Vec<_>>(),
            )
            .field("v4_extra", &self.v4_extra)
            .finish()
    }
}

impl fmt::Display for VendorBootImageV3Through4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_version = self.header_version();

        writeln!(f, "Vendor boot image v{header_version} header:")?;
        writeln!(f, "- Page size:           {}", self.page_size)?;
        writeln!(f, "- Kernel address:      {:#x}", self.kernel_addr)?;

        if header_version == 3 {
            let ramdisk_size = self.ramdisks.iter().map(|r| r.len()).sum::<usize>();
            writeln!(f, "- Ramdisk size:        {ramdisk_size}")?;
        }

        writeln!(f, "- Ramdisk address:     {:#x}", self.ramdisk_addr)?;
        writeln!(f, "- Kernel cmdline:      {:?}", self.cmdline)?;
        writeln!(f, "- Kernel tags address: {:#x}", self.tags_addr)?;
        writeln!(f, "- Name:                {:?}", self.name)?;
        writeln!(f, "- Device tree size:    {}", self.dtb.len())?;
        write!(f, "- Device tree address: {:#x}", self.dtb_addr)?;

        if let Some(v4) = &self.v4_extra {
            writeln!(f)?;

            for (ramdisk, meta) in self.ramdisks.iter().zip(&v4.ramdisk_metas) {
                writeln!(f, "- Ramdisk:")?;
                writeln!(f, "  - Size:     {}", ramdisk.len())?;
                writeln!(f, "  - Type:     {}", meta.ramdisk_type)?;
                writeln!(f, "  - Name:     {:?}", meta.ramdisk_name)?;
                writeln!(f, "  - Board ID: {:?}", meta.board_id)?;
            }

            write!(f, "- Bootconfig size:     {}", v4.bootconfig.len())?;
        }

        Ok(())
    }
}

impl BootImageExt for VendorBootImageV3Through4 {
    fn header_version(&self) -> u32 {
        if self.v4_extra.is_some() {
            4
        } else {
            3
        }
    }

    fn header_size(&self) -> u32 {
        let version = self.header_version();
        let mut size = mem::size_of::<RawVendorV3>();

        if version >= 4 {
            size += mem::size_of::<RawVendorV4Extra>();
        }

        size as u32
    }
}

impl<R: Read> FromReader<R> for VendorBootImageV3Through4 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let raw_v3 = RawVendorV3::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Vendor::V3::header", e))?;

        if raw_v3.magic != VENDOR_BOOT_MAGIC {
            return Err(Error::UnknownMagic(raw_v3.magic));
        }

        let header_version = raw_v3.header_version.get();
        if !(3..=4).contains(&header_version) {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        let page_size = raw_v3.page_size.get();
        if page_size == 0 {
            return Err(Error::PageSizeZero);
        }

        let vendor_ramdisk_size =
            util::check_bounds(raw_v3.vendor_ramdisk_size.get(), ..=COMPONENT_MAX_SIZE)
                .map_err(|e| Error::IntOutOfBounds("Vendor::V3::vendor_ramdisk_size", e))?;

        let cmdline = raw_v3.cmdline.trim_end_padding();
        let cmdline = str::from_utf8(cmdline)
            .map_err(|e| Error::StringNotUtf8("Vendor::V3::cmdline", e, cmdline.to_vec()))?;

        let name = raw_v3.name.trim_end_padding();
        let name = str::from_utf8(name)
            .map_err(|e| Error::StringNotUtf8("Vendor::V3::name", e, name.to_vec()))?;

        let header_size = raw_v3.header_size.get();

        let dtb_size = util::check_bounds(raw_v3.dtb_size.get(), ..=COMPONENT_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Vendor::V3::dtb_size", e))?;

        struct V4Data {
            v4_extra: VendorV4Extra,
            vendor_ramdisk_table_entry_num: u32,
            bootconfig_size: u32,
        }

        let mut v4_data = if header_version == 4 {
            let raw_v4 = RawVendorV4Extra::read_from_io(&mut reader)
                .map_err(|e| Error::DataRead("Vendor::V4::header", e))?;

            let table_size = raw_v4.vendor_ramdisk_table_size.get();
            let table_entry_num = raw_v4.vendor_ramdisk_table_entry_num.get();
            let table_entry_size = raw_v4.vendor_ramdisk_table_entry_size.get();

            let bootconfig_size =
                util::check_bounds(raw_v4.bootconfig_size.get(), ..=BOOTCONFIG_MAX_SIZE)
                    .map_err(|e| Error::IntOutOfBounds("Vendor::V4::bootconfig_size", e))?;

            if table_entry_size != mem::size_of::<RawVendorV4RamdiskTableEntry>() as u32 {
                return Err(Error::VendorV4InvalidRamdiskEntrySize(table_entry_size));
            }

            let actual_table_size = table_entry_num
                .checked_mul(table_entry_size)
                .ok_or(Error::IntOverflow("Vendor::V4::actual_table_size"))?;
            if actual_table_size != table_size {
                return Err(Error::VendorV4InvalidRamdiskTableSize {
                    actual: actual_table_size,
                    expected: table_size,
                });
            }

            Some(V4Data {
                v4_extra: VendorV4Extra {
                    ramdisk_metas: vec![],
                    bootconfig: String::new(),
                },
                vendor_ramdisk_table_entry_num: table_entry_num,
                bootconfig_size,
            })
        } else {
            None
        };

        if reader
            .stream_position()
            .map_err(|e| Error::DataRead("Vendor::V3::header_size", e))?
            != u64::from(header_size)
        {
            return Err(Error::InvalidHeaderSize(header_size));
        }

        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Vendor::V3::header_padding", e))?;

        let mut ramdisks = vec![];

        let mut vendor_ramdisk_data = reader
            .read_vec_exact(vendor_ramdisk_size as usize)
            .map_err(|e| Error::DataRead("Vendor::V3::ramdisk", e))?;
        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Vendor::V3::ramdisk_padding", e))?;

        // For v3, this is just one big ramdisk. For v4, we have to wait until
        // later to parse the data because the table of entries shows up later
        // in the file.
        if header_version == 3 {
            ramdisks.push(vendor_ramdisk_data);
            vendor_ramdisk_data = vec![];
        }

        let dtb = reader
            .read_vec_exact(dtb_size as usize)
            .map_err(|e| Error::DataRead("Vendor::V3::dtb", e))?;
        padding::read_discard(&mut reader, page_size.into())
            .map_err(|e| Error::DataRead("Vendor::V3::dtb_padding", e))?;

        if let Some(v4) = &mut v4_data {
            let mut ramdisk_reader = Cursor::new(vendor_ramdisk_data);
            let mut total_ramdisk_size = 0;

            for index in 0..v4.vendor_ramdisk_table_entry_num {
                let raw_entry = RawVendorV4RamdiskTableEntry::read_from_io(&mut reader)
                    .map_err(|e| Error::DataRead("Vendor::V4::table_entry", e))?;

                let ramdisk_size =
                    util::check_bounds(raw_entry.ramdisk_size.get(), ..=vendor_ramdisk_size)
                        .map_err(|e| Error::IntOutOfBounds("Vendor::V4::ramdisk_size", e))?;

                let ramdisk_offset = raw_entry.ramdisk_offset.get();

                let ramdisk_name = raw_entry.ramdisk_name.trim_end_padding();
                let ramdisk_name = str::from_utf8(ramdisk_name).map_err(|e| {
                    Error::StringNotUtf8("Vendor::V4::ramdisk_name", e, ramdisk_name.to_vec())
                })?;

                let table_offset = ramdisk_reader
                    .stream_position()
                    .map_err(|e| Error::DataRead("Vendor::V4::table_offset", e))?;

                if u64::from(ramdisk_offset) != table_offset {
                    return Err(Error::VendorV4InvalidRamdiskEntryOffset {
                        index,
                        field_value: ramdisk_offset,
                        reader_pos: table_offset,
                    });
                }

                let ramdisk = ramdisk_reader
                    .read_vec_exact(ramdisk_size as usize)
                    .map_err(|e| Error::DataRead("Vendor::V4::ramdisk", e))?;
                ramdisks.push(ramdisk);

                v4.v4_extra.ramdisk_metas.push(RamdiskMeta {
                    ramdisk_type: raw_entry.ramdisk_type.get(),
                    ramdisk_name: ramdisk_name.to_owned(),
                    board_id: raw_entry.board_id.map(|id| id.get()),
                });

                total_ramdisk_size += ramdisk_size;
            }

            if total_ramdisk_size != vendor_ramdisk_size {
                return Err(Error::VendorV4InvalidRamdiskSize {
                    field_value: vendor_ramdisk_size,
                    total_size: total_ramdisk_size,
                });
            }

            padding::read_discard(&mut reader, page_size.into())
                .map_err(|e| Error::DataRead("Vendor::V4::table_padding", e))?;

            let bootconfig = reader
                .read_vec_exact(v4.bootconfig_size as usize)
                .map_err(|e| Error::DataRead("Vendor::V4::bootconfig", e))?;
            padding::read_discard(&mut reader, page_size.into())
                .map_err(|e| Error::DataRead("Vendor::V4::bootconfig_padding", e))?;

            v4.v4_extra.bootconfig = String::from_utf8(bootconfig).map_err(|e| {
                Error::StringNotUtf8("Vendor::V4::bootconfig", e.utf8_error(), e.into_bytes())
            })?;
        }

        let image = Self {
            page_size,
            kernel_addr: raw_v3.kernel_addr.get(),
            ramdisk_addr: raw_v3.ramdisk_addr.get(),
            cmdline: cmdline.to_owned(),
            tags_addr: raw_v3.tags_addr.get(),
            name: name.to_owned(),
            dtb,
            dtb_addr: raw_v3.dtb_addr.get(),
            ramdisks,
            v4_extra: v4_data.map(|d| d.v4_extra),
        };

        Ok(image)
    }
}

impl<W: Write> ToWriter<W> for VendorBootImageV3Through4 {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        // These are programmer errors. These states can't exist if this
        // instance was just parsed from a real boot image.
        if let Some(v4) = &self.v4_extra {
            if v4.ramdisk_metas.len() != self.ramdisks.len() {
                return Err(Error::MismatchedRamdiskCounts {
                    ramdisks: self.ramdisks.len(),
                    metas: v4.ramdisk_metas.len(),
                });
            }
        } else if self.ramdisks.len() > 1 {
            return Err(Error::VendorV3TooManyRamdisks(self.ramdisks.len()));
        }

        let vendor_ramdisk_size = self.ramdisks.iter().map(|r| r.len()).sum::<usize>();
        util::check_bounds(vendor_ramdisk_size, ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Vendor::V3::vendor_ramdisk_size", e))?;
        util::check_bounds(self.dtb.len(), ..=COMPONENT_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Vendor::V3::dtb_size", e))?;

        if self.page_size == 0 {
            return Err(Error::PageSizeZero);
        }

        let cmdline = self
            .cmdline
            .as_bytes()
            .to_padded_array::<VENDOR_BOOT_ARGS_SIZE>()
            .ok_or_else(|| {
                Error::StringTooLong(
                    "Vendor::V3::cmdline",
                    VENDOR_BOOT_ARGS_SIZE,
                    self.cmdline.clone(),
                )
            })?;
        let name = self
            .name
            .as_bytes()
            .to_padded_array::<VENDOR_BOOT_NAME_SIZE>()
            .ok_or_else(|| {
                Error::StringTooLong("Vendor::V3::name", VENDOR_BOOT_NAME_SIZE, self.name.clone())
            })?;

        if let Some(v4) = &self.v4_extra {
            util::check_bounds(v4.bootconfig.len(), ..=BOOTCONFIG_MAX_SIZE as usize)
                .map_err(|e| Error::IntOutOfBounds("Vendor::V4::bootconfig_size", e))?;
        }

        let mut writer = CountingWriter::new(writer);

        let raw_v3 = RawVendorV3 {
            magic: VENDOR_BOOT_MAGIC,
            header_version: self.header_version().into(),
            page_size: self.page_size.into(),
            kernel_addr: self.kernel_addr.into(),
            ramdisk_addr: self.ramdisk_addr.into(),
            vendor_ramdisk_size: (vendor_ramdisk_size as u32).into(),
            cmdline,
            tags_addr: self.tags_addr.into(),
            name,
            header_size: self.header_size().into(),
            dtb_size: (self.dtb.len() as u32).into(),
            dtb_addr: self.dtb_addr.into(),
        };

        raw_v3
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Vendor::V3::header", e))?;

        if let Some(v4) = &self.v4_extra {
            let table_entry_num = self.ramdisks.len().to_u32().ok_or(Error::IntOverflow(
                "Vendor::V4::vendor_ramdisk_table_entry_num",
            ))?;
            let table_entry_size = mem::size_of::<RawVendorV4RamdiskTableEntry>() as u32;
            let table_size = table_entry_num
                .checked_mul(table_entry_size)
                .and_then(|v| v.to_u32())
                .ok_or(Error::IntOverflow("Vendor::V4::vendor_ramdisk_table_size"))?;

            let raw_v4 = RawVendorV4Extra {
                vendor_ramdisk_table_size: table_size.into(),
                vendor_ramdisk_table_entry_num: table_entry_num.into(),
                vendor_ramdisk_table_entry_size: table_entry_size.into(),
                bootconfig_size: (v4.bootconfig.len() as u32).into(),
            };

            raw_v4
                .write_to_io(&mut writer)
                .map_err(|e| Error::DataWrite("Vendor::V4::header", e))?;
        }

        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Vendor::V3::header_padding", e))?;

        for ramdisk in &self.ramdisks {
            writer
                .write_all(ramdisk)
                .map_err(|e| Error::DataWrite("Vendor::V3::ramdisk", e))?;
        }
        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Vendor::V3::ramdisk_padding", e))?;

        writer
            .write_all(&self.dtb)
            .map_err(|e| Error::DataWrite("Vendor::V3::dtb", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())
            .map_err(|e| Error::DataWrite("Vendor::V3::dtb_padding", e))?;

        if let Some(v4) = &self.v4_extra {
            let mut ramdisk_offset = 0;

            for (ramdisk, meta) in self.ramdisks.iter().zip(&v4.ramdisk_metas) {
                let ramdisk_size = ramdisk.len() as u32;

                let ramdisk_name = meta
                    .ramdisk_name
                    .as_bytes()
                    .to_padded_array::<VENDOR_RAMDISK_NAME_SIZE>()
                    .ok_or_else(|| {
                        Error::StringTooLong(
                            "Vendor::V4::ramdisk_name",
                            VENDOR_RAMDISK_NAME_SIZE,
                            meta.ramdisk_name.clone(),
                        )
                    })?;

                let raw_entry = RawVendorV4RamdiskTableEntry {
                    ramdisk_size: ramdisk_size.into(),
                    ramdisk_offset: ramdisk_offset.into(),
                    ramdisk_type: meta.ramdisk_type.into(),
                    ramdisk_name,
                    board_id: meta.board_id.map(|id| id.into()),
                };

                raw_entry
                    .write_to_io(&mut writer)
                    .map_err(|e| Error::DataWrite("Vendor::V4::table_entry", e))?;

                ramdisk_offset += ramdisk_size;
            }
            padding::write_zeros(&mut writer, self.page_size.into())
                .map_err(|e| Error::DataWrite("Vendor::V4::table_padding", e))?;

            writer
                .write_all(v4.bootconfig.as_bytes())
                .map_err(|e| Error::DataWrite("Vendor::V4::bootconfig", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())
                .map_err(|e| Error::DataWrite("Vendor::V4::bootconfig_padding", e))?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BootImage {
    V0Through2(BootImageV0Through2),
    V3Through4(BootImageV3Through4),
    VendorV3Through4(VendorBootImageV3Through4),
}

impl fmt::Display for BootImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V0Through2(b) => b.fmt(f),
            Self::V3Through4(b) => b.fmt(f),
            Self::VendorV3Through4(b) => b.fmt(f),
        }
    }
}

impl BootImageExt for BootImage {
    fn header_version(&self) -> u32 {
        match self {
            Self::V0Through2(b) => b.header_version(),
            Self::V3Through4(b) => b.header_version(),
            Self::VendorV3Through4(b) => b.header_version(),
        }
    }

    fn header_size(&self) -> u32 {
        match self {
            Self::V0Through2(b) => b.header_size(),
            Self::V3Through4(b) => b.header_size(),
            Self::VendorV3Through4(b) => b.header_size(),
        }
    }
}

impl<R: Read + Seek> FromReader<R> for BootImage {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        reader
            .rewind()
            .map_err(|e| Error::DataRead("Boot::V0::autodetect", e))?;

        match BootImageV0Through2::from_reader(&mut reader) {
            Ok(b) => return Ok(Self::V0Through2(b)),
            Err(Error::UnknownMagic(_) | Error::UnknownHeaderVersion(_)) => {}
            Err(e) => return Err(e),
        }

        reader
            .rewind()
            .map_err(|e| Error::DataRead("Boot::V3::autodetect", e))?;

        match BootImageV3Through4::from_reader(&mut reader) {
            Ok(b) => return Ok(Self::V3Through4(b)),
            Err(Error::UnknownMagic(_) | Error::UnknownHeaderVersion(_)) => {}
            Err(e) => return Err(e),
        }

        reader
            .rewind()
            .map_err(|e| Error::DataRead("Vendor::V3::autodetect", e))?;

        match VendorBootImageV3Through4::from_reader(&mut reader) {
            Ok(b) => return Ok(Self::VendorV3Through4(b)),
            Err(Error::UnknownMagic(_) | Error::UnknownHeaderVersion(_)) => {}
            Err(e) => return Err(e),
        }

        Err(Error::UnknownFormat)
    }
}

impl<W: Write> ToWriter<W> for BootImage {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        match self {
            Self::V0Through2(b) => b.to_writer(writer),
            Self::V3Through4(b) => b.to_writer(writer),
            Self::VendorV3Through4(b) => b.to_writer(writer),
        }
    }
}
