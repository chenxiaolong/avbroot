/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fmt,
    io::{self, Cursor, Read, Seek, Write},
    str::{self},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::ToPrimitive;
use ring::digest::Context;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    format::{
        avb::{self, Descriptor, Header},
        padding,
    },
    stream::{
        CountingReader, CountingWriter, FromReader, HashingWriter, ReadStringExt, ToWriter,
        WriteStringExt,
    },
    util::{self, NumBytes},
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

const HDR_V0_SIZE: u32 = 1632;
const HDR_V1_EXTRA_SIZE: u32 = 16;
const HDR_V2_EXTRA_SIZE: u32 = 12;
const HDR_V3_SIZE: u32 = 1580;
const HDR_V4_EXTRA_SIZE: u32 = 4;
const HDR_V4_SIGNATURE_SIZE: u64 = 4096;

const VENDOR_HDR_V3_SIZE: u32 = 2112;
const VENDOR_HDR_V4_EXTRA_SIZE: u32 = 16;
const VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE: u32 = 108;

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
    #[error("Failed to read {0:?} field")]
    ReadFieldError(&'static str, #[source] io::Error),
    #[error("Failed to write {0:?} field")]
    WriteFieldError(&'static str, #[source] io::Error),
    #[error("{0:?} field: invalid value: {1}")]
    InvalidFieldValue(&'static str, u32),
    #[error("{0:?} field is out of bounds")]
    FieldOutOfBounds(&'static str),
    #[error("Invalid data: {0}")]
    InvalidData(&'static str),
    #[error("VTS signature is missing hash descriptor")]
    MissingHashDescriptor,
    #[error("AVB error")]
    Avb(#[from] avb::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub trait BootImageExt {
    fn header_version(&self) -> u32;

    fn header_size(&self) -> u32;
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
        let mut size = HDR_V0_SIZE;

        if version >= 1 {
            size += HDR_V1_EXTRA_SIZE;
        }
        if version == 2 {
            size += HDR_V2_EXTRA_SIZE;
        }

        size
    }
}

impl<R: Read> FromReader<R> for BootImageV0Through2 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let mut magic = [0u8; BOOT_MAGIC.len()];
        reader.read_exact(&mut magic)?;

        if magic != BOOT_MAGIC {
            return Err(Error::UnknownMagic(magic));
        }

        let kernel_size = reader.read_u32::<LittleEndian>()?;
        let kernel_addr = reader.read_u32::<LittleEndian>()?;
        let ramdisk_size = reader.read_u32::<LittleEndian>()?;
        let ramdisk_addr = reader.read_u32::<LittleEndian>()?;
        let second_size = reader.read_u32::<LittleEndian>()?;
        let second_addr = reader.read_u32::<LittleEndian>()?;
        let tags_addr = reader.read_u32::<LittleEndian>()?;
        let page_size = reader.read_u32::<LittleEndian>()?;

        let header_version = reader.read_u32::<LittleEndian>()?;
        if header_version > 2 {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        if kernel_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("kernel_size"));
        } else if ramdisk_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("ramdisk_size"));
        } else if second_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("second_size"));
        } else if page_size == 0 {
            return Err(Error::InvalidFieldValue("page_size", 0));
        }

        let os_version = reader.read_u32::<LittleEndian>()?;

        let name = reader
            .read_string_padded(BOOT_NAME_SIZE)
            .map_err(|e| Error::ReadFieldError("name", e))?;
        let cmdline = reader
            .read_string_padded(BOOT_ARGS_SIZE)
            .map_err(|e| Error::ReadFieldError("cmdline", e))?;

        let mut id = [0u32; 8];
        reader.read_u32_into::<LittleEndian>(&mut id)?;

        let extra_cmdline = reader
            .read_string_padded(BOOT_EXTRA_ARGS_SIZE)
            .map_err(|e| Error::ReadFieldError("extra_cmdline", e))?;

        struct V1Data {
            v1_extra: V1Extra,
            recovery_dtbo_size: u32,
            header_size: u32,
        }

        let mut v1_data = if header_version >= 1 {
            let recovery_dtbo_size = reader.read_u32::<LittleEndian>()?;
            if recovery_dtbo_size > COMPONENT_MAX_SIZE {
                return Err(Error::FieldOutOfBounds("recovery_dtbo_size"));
            }

            let recovery_dtbo_offset = reader.read_u64::<LittleEndian>()?;
            let header_size = reader.read_u32::<LittleEndian>()?;

            let v1_extra = V1Extra {
                recovery_dtbo_offset,
                recovery_dtbo: vec![],
            };

            Some(V1Data {
                v1_extra,
                recovery_dtbo_size,
                header_size,
            })
        } else {
            None
        };

        struct V2Data {
            v2_extra: V2Extra,
            dtb_size: u32,
        }

        let mut v2_data = if header_version == 2 {
            let dtb_size = reader.read_u32::<LittleEndian>()?;
            if dtb_size > COMPONENT_MAX_SIZE {
                return Err(Error::FieldOutOfBounds("dtb_size"));
            }

            let dtb_addr = reader.read_u64::<LittleEndian>()?;

            let v2_extra = V2Extra {
                dtb_addr,
                dtb: vec![],
            };

            Some(V2Data { v2_extra, dtb_size })
        } else {
            None
        };

        if let Some(v1) = &v1_data {
            if reader.stream_position()? != u64::from(v1.header_size) {
                return Err(Error::InvalidFieldValue("header_size", v1.header_size));
            }
        }

        padding::read_discard(&mut reader, page_size.into())?;

        let mut kernel = vec![];
        let mut ramdisk = vec![];
        let mut second = vec![];

        kernel.resize(kernel_size as usize, 0);
        reader
            .read_exact(&mut kernel)
            .map_err(|e| Error::ReadFieldError("kernel", e))?;
        padding::read_discard(&mut reader, page_size.into())?;

        ramdisk.resize(ramdisk_size as usize, 0);
        reader
            .read_exact(&mut ramdisk)
            .map_err(|e| Error::ReadFieldError("ramdisk", e))?;
        padding::read_discard(&mut reader, page_size.into())?;

        second.resize(second_size as usize, 0);
        reader
            .read_exact(&mut second)
            .map_err(|e| Error::ReadFieldError("second", e))?;
        padding::read_discard(&mut reader, page_size.into())?;

        if let Some(v1) = &mut v1_data {
            v1.v1_extra
                .recovery_dtbo
                .resize(v1.recovery_dtbo_size as usize, 0);
            reader
                .read_exact(&mut v1.v1_extra.recovery_dtbo)
                .map_err(|e| Error::ReadFieldError("recovery_dtbo", e))?;
            padding::read_discard(&mut reader, page_size.into())?;
        }

        if let Some(v2) = &mut v2_data {
            v2.v2_extra.dtb.resize(v2.dtb_size as usize, 0);
            reader
                .read_exact(&mut v2.v2_extra.dtb)
                .map_err(|e| Error::ReadFieldError("dtb", e))?;
            padding::read_discard(&mut reader, page_size.into())?;
        }

        let image = Self {
            kernel_addr,
            ramdisk_addr,
            second_addr,
            tags_addr,
            page_size,
            os_version,
            name,
            cmdline,
            id,
            extra_cmdline,
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
        if self.kernel.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("kernel_size"));
        } else if self.ramdisk.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("ramdisk_size"));
        } else if self.second.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("second_size"));
        } else if self.page_size == 0 {
            return Err(Error::InvalidFieldValue("page_size", 0));
        }

        if let Some(v1) = &self.v1_extra {
            if v1.recovery_dtbo.len() > COMPONENT_MAX_SIZE as usize {
                return Err(Error::FieldOutOfBounds("recovery_dtbo_size"));
            }
        }
        if let Some(v2) = &self.v2_extra {
            if v2.dtb.len() > COMPONENT_MAX_SIZE as usize {
                return Err(Error::FieldOutOfBounds("dtb_size"));
            }
        }

        let mut writer = CountingWriter::new(writer);

        writer.write_all(&BOOT_MAGIC)?;
        writer.write_u32::<LittleEndian>(self.kernel.len() as u32)?;
        writer.write_u32::<LittleEndian>(self.kernel_addr)?;
        writer.write_u32::<LittleEndian>(self.ramdisk.len() as u32)?;
        writer.write_u32::<LittleEndian>(self.ramdisk_addr)?;
        writer.write_u32::<LittleEndian>(self.second.len() as u32)?;
        writer.write_u32::<LittleEndian>(self.second_addr)?;
        writer.write_u32::<LittleEndian>(self.tags_addr)?;
        writer.write_u32::<LittleEndian>(self.page_size)?;
        writer.write_u32::<LittleEndian>(self.header_version())?;
        writer.write_u32::<LittleEndian>(self.os_version)?;

        writer
            .write_string_padded(&self.name, BOOT_NAME_SIZE)
            .map_err(|e| Error::WriteFieldError("name", e))?;
        writer
            .write_string_padded(&self.cmdline, BOOT_ARGS_SIZE)
            .map_err(|e| Error::WriteFieldError("cmdline", e))?;

        for item in &self.id {
            writer.write_u32::<LittleEndian>(*item)?;
        }

        writer
            .write_string_padded(&self.extra_cmdline, BOOT_EXTRA_ARGS_SIZE)
            .map_err(|e| Error::WriteFieldError("extra_cmdline", e))?;

        if let Some(v1) = &self.v1_extra {
            writer.write_u32::<LittleEndian>(v1.recovery_dtbo.len() as u32)?;
            writer.write_u64::<LittleEndian>(v1.recovery_dtbo_offset)?;
            writer.write_u32::<LittleEndian>(self.header_size())?;
        }

        if let Some(v2) = &self.v2_extra {
            writer.write_u32::<LittleEndian>(v2.dtb.len() as u32)?;
            writer.write_u64::<LittleEndian>(v2.dtb_addr)?;
        }

        padding::write_zeros(&mut writer, self.page_size.into())?;

        writer
            .write_all(&self.kernel)
            .map_err(|e| Error::WriteFieldError("kernel", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())?;

        writer
            .write_all(&self.ramdisk)
            .map_err(|e| Error::WriteFieldError("ramdisk", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())?;

        writer
            .write_all(&self.second)
            .map_err(|e| Error::WriteFieldError("second", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())?;

        if let Some(v1) = &self.v1_extra {
            writer
                .write_all(&v1.recovery_dtbo)
                .map_err(|e| Error::WriteFieldError("recovery_dtbo", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())?;
        }

        if let Some(v2) = &self.v2_extra {
            writer
                .write_all(&v2.dtb)
                .map_err(|e| Error::WriteFieldError("dtb", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())?;
        }

        Ok(())
    }
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
        let mut size = HDR_V3_SIZE;

        if version >= 4 {
            size += HDR_V4_EXTRA_SIZE;
        }

        size
    }
}

impl<R: Read> FromReader<R> for BootImageV3Through4 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let mut magic = [0u8; BOOT_MAGIC.len()];
        reader.read_exact(&mut magic)?;

        if magic != BOOT_MAGIC {
            return Err(Error::UnknownMagic(magic));
        }

        let kernel_size = reader.read_u32::<LittleEndian>()?;
        let ramdisk_size = reader.read_u32::<LittleEndian>()?;
        let os_version = reader.read_u32::<LittleEndian>()?;
        let header_size = reader.read_u32::<LittleEndian>()?;

        let mut reserved = [0u32; 4];
        reader.read_u32_into::<LittleEndian>(&mut reserved)?;

        let header_version = reader.read_u32::<LittleEndian>()?;
        if !(3..=4).contains(&header_version) {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        if kernel_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("kernel_size"));
        } else if ramdisk_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("ramdisk_size"));
        }

        let cmdline = reader
            .read_string_padded(BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE)
            .map_err(|e| Error::ReadFieldError("cmdline", e))?;

        let signature_size = if header_version == 4 {
            let signature_size = reader.read_u32::<LittleEndian>()?;
            if signature_size > HDR_V4_SIGNATURE_SIZE as u32 {
                return Err(Error::FieldOutOfBounds("signature_size"));
            }

            Some(signature_size)
        } else {
            None
        };

        if reader.stream_position()? != u64::from(header_size) {
            return Err(Error::InvalidFieldValue("header_size", header_size));
        }

        padding::read_discard(&mut reader, PAGE_SIZE.into())?;

        let mut kernel = vec![];
        let mut ramdisk = vec![];

        kernel.resize(kernel_size as usize, 0);
        reader
            .read_exact(&mut kernel)
            .map_err(|e| Error::ReadFieldError("kernel", e))?;
        padding::read_discard(&mut reader, PAGE_SIZE.into())?;

        ramdisk.resize(ramdisk_size as usize, 0);
        reader
            .read_exact(&mut ramdisk)
            .map_err(|e| Error::ReadFieldError("ramdisk", e))?;
        padding::read_discard(&mut reader, PAGE_SIZE.into())?;

        // Don't preserve the signature. It is only used for VTS tests and is
        // not relevant for booting.
        let v4_extra = if let Some(s) = signature_size {
            // OnePlus images have an invalid signature consisting of all zeros.
            let mut data = vec![0u8; s as usize];
            reader
                .read_exact(&mut data)
                .map_err(|e| Error::ReadFieldError("signature", e))?;

            let signature = if s > 0 && !util::is_zero(&data) {
                Some(Header::from_reader(Cursor::new(data))?)
            } else {
                None
            };

            padding::read_discard(&mut reader, PAGE_SIZE.into())?;

            Some(V4Extra { signature })
        } else {
            None
        };

        let image = Self {
            os_version,
            reserved,
            cmdline,
            v4_extra,
            kernel,
            ramdisk,
        };

        Ok(image)
    }
}

impl BootImageV3Through4 {
    fn to_writer_internal(&self, writer: impl Write, skip_v4_sig: bool) -> Result<()> {
        if self.kernel.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("kernel_size"));
        } else if self.ramdisk.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("ramdisk_size"));
        }

        let mut writer = CountingWriter::new(writer);

        writer.write_all(&BOOT_MAGIC)?;
        writer.write_u32::<LittleEndian>(self.kernel.len() as u32)?;
        writer.write_u32::<LittleEndian>(self.ramdisk.len() as u32)?;
        writer.write_u32::<LittleEndian>(self.os_version)?;
        writer.write_u32::<LittleEndian>(self.header_size())?;

        for item in &self.reserved {
            writer.write_u32::<LittleEndian>(*item)?;
        }

        writer.write_u32::<LittleEndian>(self.header_version())?;

        writer
            .write_string_padded(&self.cmdline, BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE)
            .map_err(|e| Error::WriteFieldError("cmdline", e))?;

        let v4_signature = if let Some(v4) = &self.v4_extra {
            let mut sig_writer = Cursor::new(Vec::new());

            if let Some(s) = &v4.signature {
                s.to_writer(&mut sig_writer)?;

                let size = sig_writer.stream_position()?;

                // The VTS signature is always a fixed size.
                if size > HDR_V4_SIGNATURE_SIZE {
                    return Err(Error::FieldOutOfBounds("signature_size"));
                }

                padding::write_zeros(&mut sig_writer, HDR_V4_SIGNATURE_SIZE)?;
            }

            let sig = sig_writer.into_inner();
            writer.write_u32::<LittleEndian>(sig.len() as u32)?;
            Some(sig)
        } else {
            None
        };

        padding::write_zeros(&mut writer, PAGE_SIZE.into())?;

        writer
            .write_all(&self.kernel)
            .map_err(|e| Error::WriteFieldError("kernel", e))?;
        padding::write_zeros(&mut writer, PAGE_SIZE.into())?;

        writer
            .write_all(&self.ramdisk)
            .map_err(|e| Error::WriteFieldError("ramdisk", e))?;
        padding::write_zeros(&mut writer, PAGE_SIZE.into())?;

        if !skip_v4_sig {
            if let Some(sig) = v4_signature {
                writer
                    .write_all(&sig)
                    .map_err(|e| Error::WriteFieldError("signature", e))?;
                padding::write_zeros(&mut writer, PAGE_SIZE.into())?;
            }
        }

        Ok(())
    }

    /// Sign the boot image with a legacy VTS signature. Returns true if the
    /// image was successfully signed. Returns false if there's no vbmeta
    /// structure to sign in [`V4Extra::signature`].
    pub fn sign(&mut self, key: &RsaPrivateKey) -> Result<bool> {
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
                    return Err(avb::Error::UnsupportedHashAlgorithm(
                        descriptor.hash_algorithm.clone(),
                    )
                    .into());
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
        signature.sign(key)?;

        Ok(true)
    }
}

impl<W: Write> ToWriter<W> for BootImageV3Through4 {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        self.to_writer_internal(writer, false)
    }
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
        let mut size = VENDOR_HDR_V3_SIZE;

        if version >= 4 {
            size += VENDOR_HDR_V4_EXTRA_SIZE;
        }

        size
    }
}

impl<R: Read> FromReader<R> for VendorBootImageV3Through4 {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let mut magic = [0u8; VENDOR_BOOT_MAGIC.len()];
        reader.read_exact(&mut magic)?;

        if magic != VENDOR_BOOT_MAGIC {
            return Err(Error::UnknownMagic(magic));
        }

        let header_version = reader.read_u32::<LittleEndian>()?;
        if !(3..=4).contains(&header_version) {
            return Err(Error::UnknownHeaderVersion(header_version));
        }

        let page_size = reader.read_u32::<LittleEndian>()?;
        if page_size == 0 {
            return Err(Error::InvalidFieldValue("page_size", 0));
        }

        let kernel_addr = reader.read_u32::<LittleEndian>()?;
        let ramdisk_addr = reader.read_u32::<LittleEndian>()?;

        let vendor_ramdisk_size = reader.read_u32::<LittleEndian>()?;
        if vendor_ramdisk_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("vendor_ramdisk_size"));
        }

        let cmdline = reader
            .read_string_padded(VENDOR_BOOT_ARGS_SIZE)
            .map_err(|e| Error::ReadFieldError("cmdline", e))?;

        let tags_addr = reader.read_u32::<LittleEndian>()?;

        let name = reader
            .read_string_padded(VENDOR_BOOT_NAME_SIZE)
            .map_err(|e| Error::ReadFieldError("name", e))?;

        let header_size = reader.read_u32::<LittleEndian>()?;

        let dtb_size = reader.read_u32::<LittleEndian>()?;
        if dtb_size > COMPONENT_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("dtb_size"));
        }

        let dtb_addr = reader.read_u64::<LittleEndian>()?;

        struct V4Data {
            v4_extra: VendorV4Extra,
            vendor_ramdisk_table_entry_num: u32,
            bootconfig_size: u32,
        }

        let mut v4_data = if header_version == 4 {
            let table_size = reader.read_u32::<LittleEndian>()?;
            let table_entry_num = reader.read_u32::<LittleEndian>()?;
            let table_entry_size = reader.read_u32::<LittleEndian>()?;

            let bootconfig_size = reader.read_u32::<LittleEndian>()?;
            if bootconfig_size > BOOTCONFIG_MAX_SIZE {
                return Err(Error::FieldOutOfBounds("bootconfig_size"));
            }

            if table_entry_size != VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE {
                return Err(Error::InvalidFieldValue(
                    "vendor_ramdisk_table_entry_size",
                    table_entry_size,
                ));
            } else if table_size != table_entry_num * table_entry_size {
                return Err(Error::InvalidFieldValue(
                    "vendor_ramdisk_table_size",
                    table_size,
                ));
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

        if reader.stream_position()? != u64::from(header_size) {
            return Err(Error::InvalidFieldValue("header_size", header_size));
        }

        padding::read_discard(&mut reader, page_size.into())?;

        let mut ramdisks = vec![];

        let mut vendor_ramdisk_data = vec![0u8; vendor_ramdisk_size as usize];
        reader
            .read_exact(&mut vendor_ramdisk_data)
            .map_err(|e| Error::ReadFieldError("vendor_ramdisk_data", e))?;
        padding::read_discard(&mut reader, page_size.into())?;

        // For v3, this is just one big ramdisk. For v4, we have to wait until
        // later to parse the data because the table of entries shows up later
        // in the file.
        if header_version == 3 {
            ramdisks.push(vendor_ramdisk_data);
            vendor_ramdisk_data = vec![];
        }

        let mut dtb = vec![0u8; dtb_size as usize];
        reader
            .read_exact(&mut dtb)
            .map_err(|e| Error::ReadFieldError("dtb", e))?;
        padding::read_discard(&mut reader, page_size.into())?;

        if let Some(v4) = &mut v4_data {
            let mut ramdisk_reader = Cursor::new(vendor_ramdisk_data);
            let mut total_ramdisk_size = 0;

            for _ in 0..v4.vendor_ramdisk_table_entry_num {
                let ramdisk_size = reader.read_u32::<LittleEndian>()?;
                if ramdisk_size > vendor_ramdisk_size {
                    return Err(Error::FieldOutOfBounds("ramdisk_size"));
                }

                let ramdisk_offset = reader.read_u32::<LittleEndian>()?;
                let ramdisk_type = reader.read_u32::<LittleEndian>()?;

                let ramdisk_name = reader
                    .read_string_padded(VENDOR_RAMDISK_NAME_SIZE)
                    .map_err(|e| Error::ReadFieldError("ramdisk_name", e))?;

                let mut board_id = [0u32; VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];
                reader.read_u32_into::<LittleEndian>(&mut board_id)?;

                let table_offset = ramdisk_reader.stream_position()?;

                if u64::from(ramdisk_offset) != table_offset {
                    return Err(Error::InvalidFieldValue("ramdisk_offset", ramdisk_offset));
                }

                let mut ramdisk = vec![0u8; ramdisk_size as usize];
                ramdisk_reader.read_exact(&mut ramdisk)?;
                ramdisks.push(ramdisk);

                v4.v4_extra.ramdisk_metas.push(RamdiskMeta {
                    ramdisk_type,
                    ramdisk_name,
                    board_id,
                });

                total_ramdisk_size += ramdisk_size;
            }

            if total_ramdisk_size != vendor_ramdisk_size {
                return Err(Error::InvalidFieldValue(
                    "vendor_ramdisk_size",
                    vendor_ramdisk_size,
                ));
            }

            padding::read_discard(&mut reader, page_size.into())?;

            v4.v4_extra.bootconfig = reader
                .read_string_padded(v4.bootconfig_size as usize)
                .map_err(|e| Error::ReadFieldError("bootconfig", e))?;
        }

        let image = Self {
            page_size,
            kernel_addr,
            ramdisk_addr,
            cmdline,
            tags_addr,
            name,
            dtb,
            dtb_addr,
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
                return Err(Error::InvalidData(
                    "Mismatched ramdisks and ramdisk_metas count",
                ));
            }
        } else if self.ramdisks.len() > 1 {
            return Err(Error::InvalidData("v3 only supports one ramdisk"));
        }

        let vendor_ramdisk_size = self.ramdisks.iter().map(|r| r.len()).sum::<usize>();
        if vendor_ramdisk_size > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("vendor_ramdisk_size"));
        } else if self.dtb.len() > COMPONENT_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("dtb_size"));
        } else if self.page_size == 0 {
            return Err(Error::InvalidFieldValue("page_size", 0));
        }

        if let Some(v4) = &self.v4_extra {
            if v4.bootconfig.len() > BOOTCONFIG_MAX_SIZE as usize {
                return Err(Error::FieldOutOfBounds("bootconfig_size"));
            }
        }

        let mut writer = CountingWriter::new(writer);

        writer.write_all(&VENDOR_BOOT_MAGIC)?;
        writer.write_u32::<LittleEndian>(self.header_version())?;
        writer.write_u32::<LittleEndian>(self.page_size)?;
        writer.write_u32::<LittleEndian>(self.kernel_addr)?;
        writer.write_u32::<LittleEndian>(self.ramdisk_addr)?;
        writer.write_u32::<LittleEndian>(vendor_ramdisk_size as u32)?;

        writer
            .write_string_padded(&self.cmdline, VENDOR_BOOT_ARGS_SIZE)
            .map_err(|e| Error::WriteFieldError("cmdline", e))?;

        writer.write_u32::<LittleEndian>(self.tags_addr)?;

        writer
            .write_string_padded(&self.name, VENDOR_BOOT_NAME_SIZE)
            .map_err(|e| Error::WriteFieldError("name", e))?;

        writer.write_u32::<LittleEndian>(self.header_size())?;
        writer.write_u32::<LittleEndian>(self.dtb.len() as u32)?;
        writer.write_u64::<LittleEndian>(self.dtb_addr)?;

        if let Some(v4) = &self.v4_extra {
            let vendor_ramdisk_table_entry_num = self
                .ramdisks
                .len()
                .to_u32()
                .ok_or_else(|| Error::FieldOutOfBounds("vendor_ramdisk_table_entry_num"))?;
            let vendor_ramdisk_table_size = vendor_ramdisk_table_entry_num
                .checked_mul(VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE)
                .and_then(|v| v.to_u32())
                .ok_or_else(|| Error::FieldOutOfBounds("vendor_ramdisk_table_size"))?;

            writer.write_u32::<LittleEndian>(vendor_ramdisk_table_size)?;
            writer.write_u32::<LittleEndian>(vendor_ramdisk_table_entry_num)?;
            writer.write_u32::<LittleEndian>(VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE)?;
            writer.write_u32::<LittleEndian>(v4.bootconfig.len() as u32)?;
        }

        padding::write_zeros(&mut writer, self.page_size.into())?;

        for ramdisk in &self.ramdisks {
            writer
                .write_all(ramdisk)
                .map_err(|e| Error::WriteFieldError("vendor_ramdisk_data", e))?;
        }
        padding::write_zeros(&mut writer, self.page_size.into())?;

        writer
            .write_all(&self.dtb)
            .map_err(|e| Error::WriteFieldError("dtb", e))?;
        padding::write_zeros(&mut writer, self.page_size.into())?;

        if let Some(v4) = &self.v4_extra {
            let mut ramdisk_offset = 0;

            for (ramdisk, meta) in self.ramdisks.iter().zip(&v4.ramdisk_metas) {
                let ramdisk_size = ramdisk.len() as u32;

                writer.write_u32::<LittleEndian>(ramdisk_size)?;
                writer.write_u32::<LittleEndian>(ramdisk_offset)?;
                writer.write_u32::<LittleEndian>(meta.ramdisk_type)?;

                writer
                    .write_string_padded(&meta.ramdisk_name, VENDOR_RAMDISK_NAME_SIZE)
                    .map_err(|e| Error::WriteFieldError("ramdisk_name", e))?;

                for item in &meta.board_id {
                    writer.write_u32::<LittleEndian>(*item)?;
                }

                ramdisk_offset += ramdisk_size;
            }
            padding::write_zeros(&mut writer, self.page_size.into())?;

            writer
                .write_all(v4.bootconfig.as_bytes())
                .map_err(|e| Error::WriteFieldError("bootconfig", e))?;
            padding::write_zeros(&mut writer, self.page_size.into())?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
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
        reader.rewind()?;

        match BootImageV0Through2::from_reader(&mut reader) {
            Ok(b) => return Ok(Self::V0Through2(b)),
            Err(Error::UnknownMagic(_) | Error::UnknownHeaderVersion(_)) => {}
            Err(e) => return Err(e),
        }

        reader.rewind()?;

        match BootImageV3Through4::from_reader(&mut reader) {
            Ok(b) => return Ok(Self::V3Through4(b)),
            Err(Error::UnknownMagic(_) | Error::UnknownHeaderVersion(_)) => {}
            Err(e) => return Err(e),
        }

        reader.rewind()?;

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
