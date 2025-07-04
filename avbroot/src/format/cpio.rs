// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{self, Cursor, Read, Write},
    ops::Range,
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    escape,
    format::padding,
    octal,
    stream::{
        self, CountingReader, CountingWriter, FromReader, ReadDiscardExt, ToWriter, WriteZerosExt,
    },
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

/// The threshold when reading data where memory allocation switches from
/// allocating the exact size to resizing as necessary.
const VEC_CAP_THRESHOLD: usize = 16384;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown magic: {0:?}")]
    UnknownMagic([u8; 6]),
    #[error("Path is not NULL-terminated: {:?}", .0.as_bstr())]
    PathNotNullTerminated(Vec<u8>),
    #[error("Hard links are not supported: {:?}", .0.as_bstr())]
    HardLinksNotSupported(Vec<u8>),
    #[error("Entry of type {0} should not have data: {path:?}", path = .1.as_bstr())]
    EntryHasData(CpioEntryType, Vec<u8>),
    #[error("No inodes available for device {major:x},{minor:x}")]
    DeviceFull { major: u32, minor: u32 },
    #[error("{0:?} overflowed integer bounds during calculations")]
    IntOverflow(&'static str),
    #[error("{0:?} contains invalid hex integer")]
    InvalidHexInt(&'static str, #[source] InvalidHexCharError),
    #[error("Failed to read cpio data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write cpio data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[error("{0:?}: Invalid hex char: {1:?}")]
pub struct InvalidHexCharError(RawHexU32, char);

/// ASCII-encoded hex integer value used in cpio header fields.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHexU32([u8; 8]);

impl fmt::Debug for RawHexU32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0.as_bstr())
    }
}

#[allow(clippy::fallible_impl_from)]
impl From<u32> for RawHexU32 {
    fn from(mut value: u32) -> Self {
        let mut buf = [b'0'; 8];
        let mut index = 7;

        while value != 0 {
            buf[index] = char::from_digit(value & 0xf, 16).unwrap() as u8;
            value >>= 4;
            index -= 1;
        }

        Self(buf)
    }
}

impl TryFrom<RawHexU32> for u32 {
    type Error = InvalidHexCharError;

    fn try_from(raw_value: RawHexU32) -> std::result::Result<Self, Self::Error> {
        let mut value = 0;

        for b in raw_value.0 {
            let c = b as char;
            let digit = c.to_digit(16).ok_or(InvalidHexCharError(raw_value, c))?;

            value <<= 4;
            value |= digit;
        }

        Ok(value)
    }
}

/// Raw on-disk layout for the cpio header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHeader {
    /// Magic value. This should be equal to [`MAGIC_NEW`] or [`MAGIC_NEW_CRC`].
    magic: [u8; 6],
    inode: RawHexU32,
    mode: RawHexU32,
    uid: RawHexU32,
    gid: RawHexU32,
    nlink: RawHexU32,
    mtime: RawHexU32,
    file_size: RawHexU32,
    dev_maj: RawHexU32,
    dev_min: RawHexU32,
    rdev_maj: RawHexU32,
    rdev_min: RawHexU32,
    path_size: RawHexU32,
    crc32: RawHexU32,
}

/// Read a chunk of bytes from the reader. If `size` is less than
/// [`VEC_CAP_THRESHOLD`], then the buffer is allocated with the exact size.
/// Otherwise, the buffer starts with a capacity of [`VEC_CAP_THRESHOLD`] and
/// grows as necessary. This avoids allocating excessive memory when the entry
/// specifies an excessively large value that's not backed by actual data.
fn read_data(reader: impl Read, size: usize, cancel_signal: &AtomicBool) -> io::Result<Vec<u8>> {
    let buf = Vec::with_capacity(size.min(VEC_CAP_THRESHOLD));
    let mut cursor = Cursor::new(buf);

    stream::copy_n(reader, &mut cursor, size as u64, cancel_signal)?;

    Ok(cursor.into_inner())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum CpioEntryType {
    Pipe,
    Char,
    Directory,
    Block,
    Regular,
    Symlink,
    Socket,
    Reserved,
    Unknown(u16),
}

impl CpioEntryType {
    pub fn from_mode(mode: u32) -> Self {
        match mode & 0o170000 {
            S_IFIFO => Self::Pipe,
            S_IFCHR => Self::Char,
            S_IFDIR => Self::Directory,
            S_IFBLK => Self::Block,
            S_IFREG => Self::Regular,
            S_IFLNK => Self::Symlink,
            S_IFSOCK => Self::Socket,
            C_ISCTG => Self::Reserved,
            m => Self::Unknown(m as u16),
        }
    }

    pub fn to_mode(self) -> u32 {
        match self {
            Self::Pipe => S_IFIFO,
            Self::Char => S_IFCHR,
            Self::Directory => S_IFDIR,
            Self::Block => S_IFBLK,
            Self::Regular => S_IFREG,
            Self::Symlink => S_IFLNK,
            Self::Socket => S_IFSOCK,
            Self::Reserved => C_ISCTG,
            Self::Unknown(m) => m.into(),
        }
    }
}

impl fmt::Display for CpioEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pipe => write!(f, "pipe"),
            Self::Char => write!(f, "character device"),
            Self::Directory => write!(f, "directory"),
            Self::Block => write!(f, "block device"),
            Self::Regular => write!(f, "regular file"),
            Self::Symlink => write!(f, "symbolic link"),
            Self::Socket => write!(f, "socket"),
            Self::Reserved => write!(f, "reserved"),
            Self::Unknown(m) => write!(f, "unknown ({m:o})"),
        }
    }
}

impl Default for CpioEntryType {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CpioEntryData {
    /// Size of entry's data. [`CpioReader`] and [`CpioWriter`] use this for
    /// [`CpioEntryType::Regular`] entries to allow for lazy reads and writes.
    Size(u32),
    /// Entry's data. For [`CpioEntryType::Symlink`] entries, this is the
    /// link target. For [`CpioEntryType::Regular`] entries, this is the file
    /// content. [`CpioReader`] will never use this when reading regular files.
    /// [`CpioWriter`] will write this immediately and lazy writes will not be
    /// allowed.
    Data(#[serde(with = "escape")] Vec<u8>),
}

impl fmt::Debug for CpioEntryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size(s) => f.debug_tuple("Size").field(s).finish(),
            Self::Data(d) => f.debug_tuple("Data").field(&NumBytes(d.len())).finish(),
        }
    }
}

impl Default for CpioEntryData {
    fn default() -> Self {
        Self::Size(0)
    }
}

impl CpioEntryData {
    pub fn size(&self) -> Result<u32> {
        let size = match self {
            Self::Size(s) => *s,
            Self::Data(d) => d.len().to_u32().ok_or(Error::IntOverflow("data_size"))?,
        };

        Ok(size)
    }

    fn is_size(&self) -> bool {
        matches!(self, Self::Size(_))
    }
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpioEntry {
    /// File path.
    #[serde(with = "escape")]
    pub path: Vec<u8>,

    /// File data.
    #[serde(default, skip_serializing_if = "CpioEntryData::is_size")]
    pub data: CpioEntryData,

    /// Inode number.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub inode: u32,

    /// File type portion of the `st_mode`-style mode.
    pub file_type: CpioEntryType,

    /// Permissions portion of the `st_mode`-style mode.
    #[serde(default, skip_serializing_if = "Zero::is_zero", with = "octal")]
    pub file_mode: u16,

    /// Owner user ID.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub uid: u32,

    /// Owner group ID.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub gid: u32,

    /// Number of paths referencing the inode.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub nlink: u32,

    /// Modification timestamp in Unix time.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub mtime: u32,

    /// Major ID (class of device) for the device containing the inode.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub dev_maj: u32,

    /// Minor ID (specific device instance) for the device containing the inode.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub dev_min: u32,

    /// Major ID (class of device) represented by this entry. This is only
    /// relevant for [`CpioEntryType::Char`] and [`CpioEntryType::Block`].
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub rdev_maj: u32,

    /// Minor ID (specific device instance) represented by this entry. This is
    /// only relevant for [`CpioEntryType::Char`] and [`CpioEntryType::Block`].
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub rdev_min: u32,

    /// CRC32 checksum.
    #[serde(default, skip_serializing_if = "Zero::is_zero")]
    pub crc32: u32,
}

impl fmt::Debug for CpioEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpioEntry")
            .field("path", &self.path.as_bstr())
            .field("data", &self.data)
            .field("inode", &self.inode)
            .field("file_type", &self.file_type)
            .field("file_mode", &self.file_mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("nlink", &self.nlink)
            .field("mtime", &self.mtime)
            .field("dev_maj", &self.dev_maj)
            .field("dev_min", &self.dev_min)
            .field("rdev_maj", &self.rdev_maj)
            .field("rdev_min", &self.rdev_min)
            .field("crc32", &self.crc32)
            .finish()
    }
}

impl fmt::Display for CpioEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Path:    {:?}", self.path.as_bstr())?;
        match &self.data {
            CpioEntryData::Size(s) => {
                writeln!(f, "Data:    {:?}", &NumBytes(*s))?;
            }
            CpioEntryData::Data(d) => {
                if self.file_type == CpioEntryType::Symlink {
                    writeln!(f, "Data:    {:?}", d.as_bstr())?;
                } else {
                    writeln!(f, "Data:    {:?}", &NumBytes(d.len()))?;
                }
            }
        }
        writeln!(f, "Inode:   {}", self.inode)?;
        writeln!(f, "Type:    {}", self.file_type)?;
        writeln!(f, "Mode:    {:o}", self.file_mode)?;
        writeln!(f, "UID:     {}", self.uid)?;
        writeln!(f, "GID:     {}", self.gid)?;
        writeln!(f, "Links:   {}", self.nlink)?;
        writeln!(f, "Modtime: {}", self.mtime)?;
        writeln!(f, "Idevice: {:x},{:x}", self.dev_maj, self.dev_min)?;
        writeln!(f, "Rdevice: {:x},{:x}", self.rdev_maj, self.rdev_min)?;
        write!(f, "CRC32:   {:x}", self.crc32)?;

        Ok(())
    }
}

impl CpioEntry {
    pub fn new_trailer() -> Self {
        Self {
            path: CPIO_TRAILER.to_vec(),
            // Must be 1 for CRC format.
            nlink: 1,
            ..Default::default()
        }
    }

    pub fn new_symlink(path: &[u8], link_target: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            data: CpioEntryData::Data(link_target.to_owned()),
            file_type: CpioEntryType::Symlink,
            file_mode: 0o777,
            nlink: 1,
            ..Default::default()
        }
    }

    pub fn new_directory(path: &[u8], mode: u16) -> Self {
        Self {
            path: path.to_owned(),
            file_type: CpioEntryType::Directory,
            file_mode: mode,
            nlink: 1,
            ..Default::default()
        }
    }

    pub fn new_file(path: &[u8], mode: u16, data: CpioEntryData) -> Self {
        Self {
            path: path.to_owned(),
            data,
            file_type: CpioEntryType::Regular,
            file_mode: mode,
            nlink: 1,
            ..Default::default()
        }
    }

    pub fn is_trailer(&self) -> bool {
        self.path == CPIO_TRAILER
    }
}

impl<R: Read> FromReader<R> for CpioEntry {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let header =
            RawHeader::read_from_io(&mut reader).map_err(|e| Error::DataRead("header", e))?;

        if header.magic != *MAGIC_NEW && header.magic != *MAGIC_NEW_CRC {
            return Err(Error::UnknownMagic(header.magic));
        }

        macro_rules! get_field {
            ($name:ident) => {
                let $name = u32::try_from(header.$name)
                    .map_err(|e| Error::InvalidHexInt(stringify!($name), e))?;
            };
        }

        get_field!(inode);
        get_field!(mode);
        get_field!(uid);
        get_field!(gid);
        get_field!(nlink);
        get_field!(mtime);
        get_field!(file_size);
        get_field!(dev_maj);
        get_field!(dev_min);
        get_field!(rdev_maj);
        get_field!(rdev_min);
        get_field!(path_size);
        get_field!(crc32);

        let mut path = read_data(
            &mut reader,
            path_size.to_usize().unwrap(),
            &AtomicBool::new(false),
        )
        .map_err(|e| Error::DataRead("path", e))?;
        if path.last() != Some(&b'\0') {
            return Err(Error::PathNotNullTerminated(path));
        }
        path.pop();
        padding::read_discard(&mut reader, 4).map_err(|e| Error::DataRead("path_padding", e))?;

        let file_type = CpioEntryType::from_mode(mode);
        let data = match file_type {
            // Handled by CpioReader for streaming reads.
            CpioEntryType::Regular => CpioEntryData::Size(file_size),
            // Symlinks store the target in the file data.
            CpioEntryType::Symlink => {
                let content = read_data(
                    &mut reader,
                    file_size.to_usize().unwrap(),
                    &AtomicBool::new(false),
                )
                .map_err(|e| Error::DataRead("content", e))?;
                padding::read_discard(&mut reader, 4)
                    .map_err(|e| Error::DataRead("content_padding", e))?;

                CpioEntryData::Data(content)
            }
            // No other entry type should have data.
            t if file_size != 0 => return Err(Error::EntryHasData(t, path)),
            _ => CpioEntryData::Size(0),
        };

        Ok(Self {
            path,
            data,
            inode,
            file_type,
            file_mode: (mode & 0o7777) as u16,
            uid,
            gid,
            nlink,
            mtime,
            dev_maj,
            dev_min,
            rdev_maj,
            rdev_min,
            crc32,
        })
    }
}

impl<W: Write> ToWriter<W> for CpioEntry {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        let mut writer = CountingWriter::new(writer);

        let path_size = self
            .path
            .len()
            .checked_add(1)
            .and_then(|s| s.to_u32())
            .ok_or(Error::IntOverflow("path_size"))?;

        let file_size = self.data.size()?;
        if file_size != 0
            && self.file_type != CpioEntryType::Regular
            && self.file_type != CpioEntryType::Symlink
        {
            return Err(Error::EntryHasData(self.file_type, self.path.clone()));
        }

        let mode = self.file_type.to_mode() | u32::from(self.file_mode & 0o7777);

        let raw_header = RawHeader {
            magic: if self.crc32 == 0 {
                *MAGIC_NEW
            } else {
                *MAGIC_NEW_CRC
            },
            inode: self.inode.into(),
            mode: mode.into(),
            uid: self.uid.into(),
            gid: self.gid.into(),
            nlink: self.nlink.into(),
            mtime: self.mtime.into(),
            file_size: file_size.into(),
            dev_maj: self.dev_maj.into(),
            dev_min: self.dev_min.into(),
            rdev_maj: self.rdev_maj.into(),
            rdev_min: self.rdev_min.into(),
            path_size: path_size.into(),
            crc32: self.crc32.into(),
        };

        raw_header
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("header", e))?;

        writer
            .write_all(&self.path)
            .map_err(|e| Error::DataWrite("path", e))?;
        writer
            .write_zeros_exact(1)
            .map_err(|e| Error::DataWrite("path", e))?;
        padding::write_zeros(&mut writer, 4).map_err(|e| Error::DataWrite("path_padding", e))?;

        if let CpioEntryData::Data(d) = &self.data {
            writer
                .write_all(d)
                .map_err(|e| Error::DataWrite("content", e))?;
            padding::write_zeros(&mut writer, 4)
                .map_err(|e| Error::DataWrite("content_padding", e))?;
        }

        Ok(())
    }
}

pub struct CpioReader<R: Read> {
    reader: R,
    include_trailer: bool,
    range: Option<Range<u64>>,
    done: bool,
}

impl<R: Read> CpioReader<R> {
    pub fn new(reader: R, include_trailer: bool) -> Self {
        Self {
            reader,
            include_trailer,
            range: None,
            done: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }

    fn skip_data(&mut self) -> io::Result<()> {
        if let Some(range) = &mut self.range {
            // This cannot overflow because cpio file sizes are 32 bit.
            let n = range.end - range.start + padding::calc(range.end, 4);
            self.reader.read_discard_exact(n)?;
            self.range = None;
        }

        Ok(())
    }

    pub fn next_entry(&mut self) -> Result<Option<CpioEntry>> {
        if self.done {
            return Ok(None);
        }

        self.skip_data()
            .map_err(|e| Error::DataRead("content", e))?;

        let entry = CpioEntry::from_reader(&mut self.reader)?;

        if entry.is_trailer() {
            self.done = true;

            if !self.include_trailer {
                return Ok(None);
            }
        } else if let CpioEntryData::Size(s) = entry.data {
            self.range = Some(0..u64::from(s));
        }

        Ok(Some(entry))
    }
}

impl<R: Read> Read for CpioReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(range) = &mut self.range else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No entry opened",
            ));
        };

        let to_read = (range.end - range.start).min(buf.len() as u64) as usize;
        let n = self.reader.read(&mut buf[..to_read])?;

        range.start += n as u64;

        Ok(n)
    }
}

pub struct CpioWriter<W: Write> {
    writer: CountingWriter<W>,
    pad_to_block_size: bool,
    range: Option<Range<u64>>,
    max_inode: u32,
}

impl<W: Write> CpioWriter<W> {
    pub fn new(writer: W, pad_to_block_size: bool) -> Self {
        Self {
            writer: CountingWriter::new(writer),
            pad_to_block_size,
            range: None,
            max_inode: 0,
        }
    }

    fn finish_entry(&mut self) -> io::Result<()> {
        if let Some(range) = &mut self.range {
            // This cannot overflow because cpio file sizes are 32 bit.
            let n = range.end - range.start + padding::calc(range.end, 4);
            self.writer.write_zeros_exact(n)?;
            self.range = None;
        }

        Ok(())
    }

    pub fn start_entry(&mut self, entry: &CpioEntry) -> Result<()> {
        self.finish_entry()
            .map_err(|e| Error::DataWrite("content", e))?;

        entry.to_writer(&mut self.writer)?;

        if let CpioEntryData::Size(s) = entry.data {
            self.range = Some(0..u64::from(s));
        }

        self.max_inode = self.max_inode.max(entry.inode);

        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        self.finish_entry()
            .map_err(|e| Error::DataWrite("content", e))?;

        self.start_entry(&CpioEntry::new_trailer())?;

        // Pad until the end of the block.
        if self.pad_to_block_size {
            padding::write_zeros(&mut self.writer, IO_BLOCK_SIZE)
                .map_err(|e| Error::DataWrite("block_padding", e))?;
        }

        Ok(self.writer.finish().0)
    }
}

impl<W: Write> Write for CpioWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(range) = &mut self.range else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No entry started",
            ));
        };

        let to_write = (range.end - range.start).min(buf.len() as u64) as usize;
        let n = self.writer.write(&buf[..to_write])?;

        range.start += n as u64;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn load(
    reader: impl Read,
    include_trailer: bool,
    cancel_signal: &AtomicBool,
) -> Result<Vec<CpioEntry>> {
    let mut cpio_reader = CpioReader::new(reader, include_trailer);
    let mut entries = vec![];

    while let Some(mut entry) = cpio_reader.next_entry()? {
        stream::check_cancel(cancel_signal).map_err(|e| Error::DataRead("entry", e))?;

        if entry.file_type != CpioEntryType::Directory && entry.nlink > 1 {
            return Err(Error::HardLinksNotSupported(entry.path));
        }

        if let CpioEntryData::Size(s) = entry.data {
            let data = read_data(&mut cpio_reader, s.to_usize().unwrap(), cancel_signal)
                .map_err(|e| Error::DataWrite("data", e))?;
            entry.data = CpioEntryData::Data(data);
        }

        entries.push(entry);
    }

    Ok(entries)
}

pub fn sort(entries: &mut [CpioEntry]) {
    entries.sort_by(|a, b| a.path.cmp(&b.path));
}

/// Assign inodes to entries. If `missing_only` is true, then inodes are only
/// assigned if the inode field in an entry is set to 0.
///
/// New inodes are assigned starting immediately after the highest inode number
/// for a given ([`CpioEntry::dev_maj`], [`CpioEntry::dev_min`]) pair. If there
/// are no existing inodes assigned for a device, then the numbers begin at
/// 300000.
pub fn assign_inodes(entries: &mut [CpioEntry], missing_only: bool) -> Result<()> {
    fn next_non_zero(i: u32) -> u32 {
        if i == u32::MAX { 1 } else { i.wrapping_add(1) }
    }

    // (dev maj, dev min) -> (inode set, last assigned inode)
    let mut inodes: HashMap<(u32, u32), (HashSet<u32>, u32)> = HashMap::new();

    if missing_only {
        for entry in &mut *entries {
            if entry.inode != 0 {
                let key = (entry.dev_maj, entry.dev_min);
                let (set, last) = inodes.entry(key).or_default();

                set.insert(entry.inode);
                *last = (*last).max(entry.inode);
            }
        }
    }

    for entry in entries {
        if entry.inode == 0 {
            let key = (entry.dev_maj, entry.dev_min);
            let (set, last) = inodes
                .entry(key)
                .or_insert_with(|| (HashSet::new(), 299999));

            let mut unused = next_non_zero(*last);

            while set.contains(&unused) {
                if unused == *last {
                    return Err(Error::DeviceFull {
                        major: entry.dev_maj,
                        minor: entry.dev_min,
                    });
                }

                unused = next_non_zero(unused);
            }

            entry.inode = unused;
            set.insert(unused);
            *last = unused;
        }
    }

    Ok(())
}

pub fn save(
    writer: impl Write,
    entries: &[CpioEntry],
    pad_to_block_size: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let mut cpio_writer = CpioWriter::new(writer, pad_to_block_size);

    for entry in entries {
        stream::check_cancel(cancel_signal).map_err(|e| Error::DataWrite("entry", e))?;

        cpio_writer.start_entry(entry)?;
        // CpioEntryData::Data will have already been written.
    }

    cpio_writer.finish()?;

    Ok(())
}
