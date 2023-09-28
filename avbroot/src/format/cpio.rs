/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    fmt,
    io::{self, Read, Write},
};

use bstr::ByteSlice;
use num_traits::ToPrimitive;
use thiserror::Error;

use crate::{
    format::padding,
    stream::{CountingReader, CountingWriter, FromReader, ToWriter, WriteZerosExt},
    util::NumBytes,
};

const MAGIC_NEW: &[u8; 6] = b"070701";
const MAGIC_NEW_CRC: &[u8; 6] = b"070702";

const CPIO_TRAILER: &[u8; 10] = b"TRAILER!!!";

const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFSOCK: u32 = 0o140000;
const C_ISCTG: u32 = 0o110000;

const IO_BLOCK_SIZE: u64 = 512;

/// The threshold when parsing an entry's filename where memory allocation
/// switches from allocating the exact size to resizing as necessary.
const REALLOC_NAME_THRESHOLD: usize = 1024;
/// The threshold when parsing an entry's contents where memory allocation
/// switches from allocating the exact size to resizing as necessary.
const REALLOC_DATA_THRESHOLD: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown magic: {0:?}")]
    UnknownMagic([u8; 6]),
    #[error("Hard links are not supported: {:?}", .0.as_bstr())]
    HardLinksNotSupported(Vec<u8>),
    #[error("{0:?} field exceeds integer bounds")]
    IntegerTooLarge(&'static str),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Read u32 formatted as an ASCII 8-char wide hex string.
fn read_int(mut reader: impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;

    let mut value = 0;

    for b in buf {
        let c = b as char;
        let digit = c.to_digit(16).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{:?}: Invalid hex char: {c}", buf.as_bstr()),
            )
        })?;

        value <<= 4;
        value |= digit;
    }

    Ok(value)
}

/// Write u32 formatted as an ASCII 8-char wide hex string.
fn write_int(mut writer: impl Write, mut value: u32) -> io::Result<()> {
    let mut buf = [b'0'; 8];
    let mut index = 7;

    while value != 0 {
        buf[index] = char::from_digit(value & 0xf, 16).unwrap() as u8;
        value >>= 4;
        index -= 1;
    }

    writer.write_all(&buf)
}

/// Read a chunk of bytes from the reader. If `size` is less than
/// `realloc_thresh`, then the buffer is allocated with the exact size.
/// Otherwise, the buffer starts with a capacity of `realloc_thresh` and grows
/// as necessary. This avoids allocating excessive memory when the entry
/// specifies an excessively large value that's not backed by actual data.
fn read_data(mut reader: impl Read, size: usize, realloc_thresh: usize) -> io::Result<Vec<u8>> {
    if size < realloc_thresh {
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    } else {
        let mut buf = Vec::with_capacity(realloc_thresh);
        let mut offset = 0;

        while offset < size {
            let n = (size - offset).min(16384);
            buf.resize(offset + n, 0);
            reader.read_exact(&mut buf[offset..][..n])?;
            offset += n;
        }

        Ok(buf)
    }
}

fn file_type(mode: u32) -> u32 {
    mode & 0o170000
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct CpioEntryNew {
    pub ino: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub dev_maj: u32,
    pub dev_min: u32,
    pub rdev_maj: u32,
    pub rdev_min: u32,
    pub chksum: u32,
    pub name: Vec<u8>,
    pub content: Vec<u8>,
}

impl fmt::Debug for CpioEntryNew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpioEntryNew")
            .field("ino", &self.ino)
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("nlink", &self.nlink)
            .field("mtime", &self.mtime)
            .field("dev_maj", &self.dev_maj)
            .field("dev_min", &self.dev_min)
            .field("rdev_maj", &self.rdev_maj)
            .field("rdev_min", &self.rdev_min)
            .field("chksum", &self.chksum)
            .field("name", &self.name.as_bstr())
            .field("content", &NumBytes(self.content.len()))
            .finish()
    }
}

impl fmt::Display for CpioEntryNew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file_type_str = match file_type(self.mode) {
            S_IFIFO => Cow::Borrowed("pipe"),
            S_IFCHR => Cow::Borrowed("character device"),
            S_IFDIR => Cow::Borrowed("directory"),
            S_IFBLK => Cow::Borrowed("block device"),
            S_IFREG => Cow::Borrowed("regular file"),
            S_IFLNK => Cow::Borrowed("symbolic link"),
            S_IFSOCK => Cow::Borrowed("socket"),
            C_ISCTG => Cow::Borrowed("reserved"),
            m => Cow::Owned(format!("unknown ({m:o})")),
        };

        writeln!(f, "Filename:  {:?}", self.name.as_bstr())?;
        writeln!(f, "Filetype:  {file_type_str}")?;
        writeln!(f, "Inode:     {}", self.ino)?;
        writeln!(f, "Mode:      {:o}", self.mode)?;
        writeln!(f, "UID:       {}", self.uid)?;
        writeln!(f, "GID:       {}", self.gid)?;
        writeln!(f, "Links:     {}", self.nlink)?;
        writeln!(f, "Modified:  {}", self.mtime)?;
        writeln!(f, "Device:    {:x},{:x}", self.dev_maj, self.dev_min)?;
        writeln!(f, "Device ID: {:x},{:x}", self.rdev_maj, self.rdev_min)?;
        writeln!(f, "Checksum:  {:x}", self.chksum)?;
        writeln!(f, "Content:   {:?}", NumBytes(self.content.len()))?;

        Ok(())
    }
}

impl CpioEntryNew {
    pub fn new_trailer() -> Self {
        Self {
            // Must be 1 for CRC format.
            nlink: 1,
            name: CPIO_TRAILER.to_vec(),
            ..Default::default()
        }
    }

    pub fn new_symlink(link_target: &[u8], name: &[u8]) -> Self {
        Self {
            mode: S_IFLNK | 0o777,
            nlink: 1,
            name: name.to_owned(),
            content: link_target.to_owned(),
            ..Default::default()
        }
    }

    pub fn new_directory(name: &[u8]) -> Self {
        Self {
            mode: S_IFDIR,
            nlink: 1,
            name: name.to_owned(),
            ..Default::default()
        }
    }

    pub fn new_file(name: &[u8]) -> Self {
        Self {
            mode: S_IFREG,
            nlink: 1,
            name: name.to_owned(),
            ..Default::default()
        }
    }
}

impl<R: Read> FromReader<R> for CpioEntryNew {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let mut magic = [0u8; 6];
        reader.read_exact(&mut magic)?;

        if magic != *MAGIC_NEW && magic != *MAGIC_NEW_CRC {
            return Err(Error::UnknownMagic(magic));
        }

        let ino = read_int(&mut reader)?;
        let mode = read_int(&mut reader)?;
        let uid = read_int(&mut reader)?;
        let gid = read_int(&mut reader)?;
        let nlink = read_int(&mut reader)?;
        let mtime = read_int(&mut reader)?;
        let filesize = read_int(&mut reader)?;
        let dev_maj = read_int(&mut reader)?;
        let dev_min = read_int(&mut reader)?;
        let rdev_maj = read_int(&mut reader)?;
        let rdev_min = read_int(&mut reader)?;
        let namesize = read_int(&mut reader)?;
        let chksum = read_int(&mut reader)?;

        let mut name = read_data(
            &mut reader,
            namesize.to_usize().unwrap(),
            REALLOC_NAME_THRESHOLD,
        )?;
        if name.last() != Some(&b'\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Filename is not NULL-terminated",
            )
            .into());
        }
        name.pop();
        padding::read_discard(&mut reader, 4)?;

        let content = read_data(
            &mut reader,
            filesize.to_usize().unwrap(),
            REALLOC_DATA_THRESHOLD,
        )?;
        padding::read_discard(&mut reader, 4)?;

        Ok(Self {
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            dev_maj,
            dev_min,
            rdev_maj,
            rdev_min,
            chksum,
            name,
            content,
        })
    }
}

impl<W: Write> ToWriter<W> for CpioEntryNew {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        let mut writer = CountingWriter::new(writer);

        let filesize = self
            .content
            .len()
            .to_u32()
            .ok_or_else(|| Error::IntegerTooLarge("filesize"))?;
        let namesize = self
            .name
            .len()
            .checked_add(1)
            .and_then(|s| s.to_u32())
            .ok_or_else(|| Error::IntegerTooLarge("filesize"))?;

        if self.chksum == 0 {
            writer.write_all(MAGIC_NEW)?;
        } else {
            writer.write_all(MAGIC_NEW_CRC)?;
        }

        write_int(&mut writer, self.ino)?;
        write_int(&mut writer, self.mode)?;
        write_int(&mut writer, self.uid)?;
        write_int(&mut writer, self.gid)?;
        write_int(&mut writer, self.nlink)?;
        write_int(&mut writer, self.mtime)?;
        write_int(&mut writer, filesize)?;
        write_int(&mut writer, self.dev_maj)?;
        write_int(&mut writer, self.dev_min)?;
        write_int(&mut writer, self.rdev_maj)?;
        write_int(&mut writer, self.rdev_min)?;
        write_int(&mut writer, namesize)?;
        write_int(&mut writer, self.chksum)?;

        writer.write_all(&self.name)?;
        writer.write_zeros_exact(1)?;
        padding::write_zeros(&mut writer, 4)?;

        writer.write_all(&self.content)?;
        padding::write_zeros(&mut writer, 4)?;

        Ok(())
    }
}

pub fn load(mut reader: impl Read, include_trailer: bool) -> Result<Vec<CpioEntryNew>> {
    let mut entries = vec![];

    loop {
        let entry = CpioEntryNew::from_reader(&mut reader)?;
        if file_type(entry.mode) != S_IFDIR && entry.nlink > 1 {
            return Err(Error::HardLinksNotSupported(entry.name));
        }

        if entry.name == CPIO_TRAILER {
            if include_trailer {
                entries.push(entry);
            }
            break;
        }

        entries.push(entry);
    }

    Ok(entries)
}

pub fn sort(entries: &mut [CpioEntryNew]) {
    entries.sort_by(|a, b| a.name.cmp(&b.name));
}

pub fn reassign_inodes(entries: &mut [CpioEntryNew]) {
    let mut inode = 300000;

    for entry in entries {
        entry.ino = inode;
        inode += 1;
    }
}

pub fn save(writer: impl Write, entries: &[CpioEntryNew], pad_to_block_size: bool) -> Result<()> {
    let mut writer = CountingWriter::new(writer);

    for entry in entries {
        entry.to_writer(&mut writer)?;
    }

    let mut trailer = CpioEntryNew::new_trailer();
    // 1 higher than the highest inode if possible.
    trailer.ino = entries.iter().map(|e| e.ino).max().map_or(0, |i| i + 1);
    trailer.to_writer(&mut writer)?;

    // Pad until the end of the block.
    if pad_to_block_size {
        padding::write_zeros(&mut writer, IO_BLOCK_SIZE)?;
    }

    Ok(())
}
