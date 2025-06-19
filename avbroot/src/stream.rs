// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use num_traits::ToPrimitive;
use ring::digest::Context;

use crate::util;

/// A trait for seekable readers. This is only needed because `dyn Read + Seek`
/// is not a valid construct in Rust yet.
pub trait ReadSeek: Read + Seek {}

impl<R: Read + Seek> ReadSeek for R {}

/// A trait for seekable writers. This is only needed because `dyn Write + Seek`
/// is not a valid construct in Rust yet.
pub trait WriteSeek: Write + Seek {}

impl<W: Write + Seek> WriteSeek for W {}

/// A trait for seekable and reopenable readers.
pub trait ReadSeekReopen: ReadSeek {
    fn reopen_boxed(&self) -> io::Result<Box<dyn ReadSeek>>;
}

impl<R: ReadSeek + Reopen + 'static> ReadSeekReopen for R {
    fn reopen_boxed(&self) -> io::Result<Box<dyn ReadSeek>> {
        Ok(Box::new(self.reopen()?))
    }
}

/// A trait for seekable and reopenable writers.
pub trait WriteSeekReopen: WriteSeek {
    fn reopen_boxed(&self) -> io::Result<Box<dyn WriteSeek>>;
}

impl<W: WriteSeek + Reopen + 'static> WriteSeekReopen for W {
    fn reopen_boxed(&self) -> io::Result<Box<dyn WriteSeek>> {
        Ok(Box::new(self.reopen()?))
    }
}

/// Common function for reading a structure from a reader.
pub trait FromReader<R: Read>: Sized {
    type Error;

    fn from_reader(reader: R) -> Result<Self, Self::Error>;
}

/// Common function for writing a structure to a writer.
pub trait ToWriter<W: Write>: Sized {
    type Error;

    fn to_writer(&self, writer: W) -> Result<(), Self::Error>;
}

/// Extensions for readers to read and discard data (eg. for padding).
pub trait ReadDiscardExt {
    fn read_discard(&mut self, size: u64) -> io::Result<u64>;

    fn read_discard_exact(&mut self, size: u64) -> io::Result<()> {
        let n = self.read_discard(size)?;
        if n != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Expected to read {size} bytes, but reached EOF after {n} bytes"),
            ));
        }
        Ok(())
    }
}

impl<R: Read> ReadDiscardExt for R {
    fn read_discard(&mut self, size: u64) -> io::Result<u64> {
        io::copy(&mut self.take(size), &mut io::sink())
    }
}

/// Extensions for writers to easily write zeros (eg. for padding).
pub trait WriteZerosExt {
    fn write_zeros(&mut self, size: u64) -> io::Result<u64>;

    fn write_zeros_exact(&mut self, size: u64) -> io::Result<()> {
        let n = self.write_zeros(size)?;
        if n != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Expected to write {size} bytes, but reached EOF after {n} bytes"),
            ));
        }
        Ok(())
    }
}

impl<W: Write> WriteZerosExt for W {
    fn write_zeros(&mut self, size: u64) -> io::Result<u64> {
        // We don't use std::io::copy() on std::io::repeat(0) because it fails
        // if the writer hits EOF before all data is written.
        let mut written = 0;

        while written < size {
            let to_write = (size - written).min(util::ZEROS.len() as u64) as usize;
            let n = self.write(&util::ZEROS[..to_write])?;
            written += n as u64;

            if n < to_write {
                break;
            }
        }

        Ok(written)
    }
}

/// Extensions for readers to read fixed-size buffers.
pub trait ReadFixedSizeExt {
    /// Read fixed-size array.
    fn read_array_exact<const N: usize>(&mut self) -> io::Result<[u8; N]>;

    /// Read fixed-sized [`Vec`].
    fn read_vec_exact(&mut self, size: usize) -> io::Result<Vec<u8>>;
}

impl<R: Read> ReadFixedSizeExt for R {
    fn read_array_exact<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut buf = [0u8; N];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_vec_exact(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Extensions for file-like types to reopen themselves.
pub trait Reopen: Sized {
    /// Open a new handle to the same file. The new handle is independently
    /// seekable and the file offset is initially set to 0.
    fn reopen(&self) -> io::Result<Self>;
}

impl<R: Read + Reopen> Reopen for BufReader<R> {
    fn reopen(&self) -> io::Result<Self> {
        Ok(Self::new(self.get_ref().reopen()?))
    }
}

impl<W: Write + Reopen> Reopen for BufWriter<W> {
    fn reopen(&self) -> io::Result<Self> {
        Ok(Self::new(self.get_ref().reopen()?))
    }
}

/// A reader wrapper that implements [`Seek`], but only for reporting the
/// current file position.
pub struct CountingReader<R> {
    inner: R,
    offset: u64,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, offset: 0 }
    }

    pub fn finish(self) -> (R, u64) {
        (self.inner, self.offset)
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.offset += n as u64;
        Ok(n)
    }
}

impl<R: Read> Seek for CountingReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if pos == SeekFrom::Current(0) {
            Ok(self.offset)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Can only report current offset",
            ))
        }
    }
}

/// A writer wrapper that implements [`Seek`], but only for reporting the
/// current file position.
pub struct CountingWriter<W> {
    inner: W,
    offset: u64,
}

impl<W: Write> CountingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, offset: 0 }
    }

    pub fn finish(self) -> (W, u64) {
        (self.inner, self.offset)
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.offset += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Seek for CountingWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if pos == SeekFrom::Current(0) {
            Ok(self.offset)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Can only report current offset",
            ))
        }
    }
}

/// A reader wrapper that hashes data as it's being read.
pub struct HashingReader<R> {
    inner: R,
    context: Context,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R, context: Context) -> Self {
        Self { inner, context }
    }

    pub fn finish(self) -> (R, Context) {
        (self.inner, self.context)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.context.update(&buf[..n]);
        Ok(n)
    }
}

/// A writer wrapper that hashes data as it's being written.
pub struct HashingWriter<W> {
    inner: W,
    context: Context,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W, context: Context) -> Self {
        Self { inner, context }
    }

    pub fn finish(self) -> (W, Context) {
        (self.inner, self.context)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.context.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader wrapper that only allows reading a specific section of a file.
pub struct SectionReader<R> {
    inner: R,
    start: u64,
    size: u64,
    pos: u64,
}

impl<R: Read + Seek> SectionReader<R> {
    pub fn new(mut inner: R, start: u64, size: u64) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(start))?;

        Ok(Self {
            inner,
            start,
            size,
            pos: 0,
        })
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek + Reopen> Reopen for SectionReader<R> {
    fn reopen(&self) -> io::Result<Self> {
        let inner = self.inner.reopen()?;

        Self::new(inner, self.start, self.size)
    }
}

impl<R: Read + Seek> Read for SectionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let to_read = self.size.saturating_sub(self.pos).min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SectionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => self
                .size
                .to_i64()
                .and_then(|s| s.checked_add(o))
                .and_then(|s| s.to_u64())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Offset would be before the start of the file",
                    )
                })?,
            SeekFrom::Current(o) => self
                .pos
                .to_i64()
                .and_then(|s| s.checked_add(o))
                .and_then(|s| s.to_u64())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Offset would be before the start of the file",
                    )
                })?,
        };

        let raw_pos = self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        Ok(raw_pos - self.start)
    }
}

/// A file wrapper that uses a userspace file offset. A reopened instance uses
/// the same underlying kernel file descriptor, but a new userspace file offset,
/// initially set to 0.
#[derive(Debug)]
pub struct PSeekFile {
    // The lock is needed because flush() takes a `&mut self`.
    file: Arc<RwLock<File>>,
    offset: u64,
}

impl PSeekFile {
    pub fn new(file: File) -> Self {
        Self {
            file: Arc::new(RwLock::new(file)),
            offset: 0,
        }
    }

    pub fn set_len(&self, size: u64) -> io::Result<()> {
        let file_locked = self.file.read().unwrap();
        file_locked.set_len(size)
    }

    /// Read data from offset. The kernel's file position *will* be changed.
    #[cfg(windows)]
    fn read_at(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        self.file.read().unwrap().seek_read(buf, self.offset)
    }

    /// Read data from offset. The kernel's file position will *not* be changed.
    #[cfg(unix)]
    fn read_at(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.file.read().unwrap().read_at(buf, self.offset)
    }

    /// Write data to offset. The kernel's file position *will* be changed.
    #[cfg(windows)]
    fn write_at(&self, buf: &[u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        self.file.read().unwrap().seek_write(buf, self.offset)
    }

    /// Write data to offset. The kernel's file position will *not* be changed.
    #[cfg(unix)]
    fn write_at(&self, buf: &[u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.file.read().unwrap().write_at(buf, self.offset)
    }
}

impl Reopen for PSeekFile {
    fn reopen(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.clone(),
            offset: 0,
        })
    }
}

impl Read for PSeekFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf)?;
        self.offset += n as u64;
        Ok(n)
    }
}

impl Write for PSeekFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.write_at(buf)?;
        self.offset += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.write().unwrap().flush()
    }
}

impl Seek for PSeekFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => {
                let file_size = self.file.read().unwrap().metadata()?.len();
                file_size
                    .to_i64()
                    .and_then(|s| s.checked_add(o))
                    .and_then(|s| s.to_u64())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Offset would be before the start of the file",
                        )
                    })?
            }
            SeekFrom::Current(o) => self
                .offset
                .to_i64()
                .and_then(|s| s.checked_add(o))
                .and_then(|s| s.to_u64())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Offset would be before the start of the file",
                    )
                })?,
        };

        Ok(self.offset)
    }
}

/// A small wrapper around a [`Cursor`] that allows multiple instances to share
/// the same underlying file. All reads, writes, and seeks are single-threaded.
/// This is useful for scenarios where data needs to be copied from multiple
/// readers into different parts of the same [`SharedCursor`] writer and the
/// read operation is significantly more expensive than the write operation (eg.
/// due to decompression).
#[derive(Default)]
pub struct SharedCursor {
    inner: Arc<Mutex<Cursor<Vec<u8>>>>,
    offset: u64,
}

impl SharedCursor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Reopen for SharedCursor {
    fn reopen(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.clone(),
            offset: 0,
        })
    }
}

impl Read for SharedCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.seek(SeekFrom::Start(self.offset))?;

        let n = inner.read(buf)?;
        self.offset += n as u64;

        Ok(n)
    }
}

impl Write for SharedCursor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.seek(SeekFrom::Start(self.offset))?;

        let n = inner.write(buf)?;
        self.offset += n as u64;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.flush()
    }
}

impl Seek for SharedCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        self.offset = inner.seek(pos)?;
        Ok(self.offset)
    }
}

/// Returns an I/O error with the [`io::ErrorKind::Interrupted`] type if
/// `cancel_signal` is true. This should be called frequently in I/O loops for
/// cancellation to be responsive.
#[inline]
pub fn check_cancel(cancel_signal: &AtomicBool) -> io::Result<()> {
    if cancel_signal.load(Ordering::SeqCst) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Received cancel signal",
        ));
    }

    Ok(())
}

/// Copy exactly `size` bytes from `reader` to `writer`, invoking `inspect`
/// after every buffer read iteration. If either `reader` or `writer` reaches
/// EOF before `size` bytes are copied, an error is returned. The operation is
/// cancelled on the next loop iteration if `cancel_signal` is set to `true`.
pub fn copy_n_inspect(
    mut reader: impl Read,
    mut writer: impl Write,
    mut size: u64,
    mut inspect: impl FnMut(&[u8]),
    cancel_signal: &AtomicBool,
) -> io::Result<()> {
    let mut buf = [0u8; 16384];

    while size > 0 {
        check_cancel(cancel_signal)?;

        let to_read = size.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..to_read])?;

        inspect(&buf[..to_read]);

        writer.write_all(&buf[..to_read])?;

        size -= to_read as u64;
    }

    Ok(())
}

/// Copy exactly `size` bytes from `reader` to `writer`.
pub fn copy_n(
    reader: impl Read,
    writer: impl Write,
    size: u64,
    cancel_signal: &AtomicBool,
) -> io::Result<()> {
    copy_n_inspect(reader, writer, size, |_| {}, cancel_signal)
}

/// Copy data from `reader` to `writer` until `reader` reaches EOF. If `writer`
/// reaches EOF before `reader` does, an error is returned. The operation is
/// cancelled on the next loop iteration if `cancel_signal` is set to `true`.
pub fn copy(
    mut reader: impl Read,
    mut writer: impl Write,
    cancel_signal: &AtomicBool,
) -> io::Result<u64> {
    let mut buf = [0u8; 16384];
    let mut copied = 0;

    loop {
        check_cancel(cancel_signal)?;

        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n])?;

        copied += n as u64;
    }

    Ok(copied)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Read, Seek, SeekFrom, Write},
        sync::atomic::{AtomicBool, Ordering},
    };

    use ring::digest::Context;

    use super::{
        CountingReader, CountingWriter, HashingReader, HashingWriter, PSeekFile, ReadDiscardExt,
        Reopen, SectionReader, SharedCursor, WriteZerosExt,
    };

    const FOOBAR_SHA256: [u8; 32] = [
        0xc3, 0xab, 0x8f, 0xf1, 0x37, 0x20, 0xe8, 0xad, 0x90, 0x47, 0xdd, 0x39, 0x46, 0x6b, 0x3c,
        0x89, 0x74, 0xe5, 0x92, 0xc2, 0xfa, 0x38, 0x3d, 0x4a, 0x39, 0x60, 0x71, 0x4c, 0xae, 0xf0,
        0xc4, 0xf2,
    ];

    #[test]
    fn read_discard() {
        let mut reader = Cursor::new(b"foobar");
        reader.read_discard_exact(3).unwrap();

        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ba");

        let n = reader.read_discard(2).unwrap();
        assert_eq!(n, 1);

        assert_eq!(reader.stream_position().unwrap(), 6);
    }

    #[test]
    fn write_zeros() {
        let mut writer = Cursor::new([0u8; 6]);

        writer.write_zeros_exact(2).unwrap();
        writer.write_all(b"foo").unwrap();

        let n = writer.write_zeros(2).unwrap();
        assert_eq!(n, 1);

        assert_eq!(&writer.into_inner(), b"\0\0foo\0");
    }

    #[test]
    fn counting_reader() {
        let raw_reader = Cursor::new(b"foobar");
        let mut reader = CountingReader::new(raw_reader);

        let mut buf = [0u8; 6];
        reader.read_exact(&mut buf[..0]).unwrap();
        reader.read_exact(&mut buf[..3]).unwrap();
        reader.read_exact(&mut buf[3..4]).unwrap();
        reader.read_exact(&mut buf[4..6]).unwrap();
        assert_eq!(&buf, b"foobar");

        let (mut raw_reader, size) = reader.finish();
        assert_eq!(raw_reader.stream_position().unwrap(), 6);
        assert_eq!(size, 6);
    }

    #[test]
    fn counting_writer() {
        let raw_writer = Cursor::new([0u8; 6]);
        let mut writer = CountingWriter::new(raw_writer);

        writer.write_all(b"foo").unwrap();
        writer.write_all(b"").unwrap();
        writer.write_all(b"bar").unwrap();

        let (mut raw_writer, size) = writer.finish();
        assert_eq!(raw_writer.stream_position().unwrap(), 6);
        assert_eq!(&raw_writer.into_inner(), b"foobar");
        assert_eq!(size, 6);
    }

    #[test]
    fn hashing_reader() {
        let raw_reader = Cursor::new(b"foobar");
        let mut reader = HashingReader::new(raw_reader, Context::new(&ring::digest::SHA256));

        let mut buf = [0u8; 6];
        reader.read_exact(&mut buf[..0]).unwrap();
        reader.read_exact(&mut buf[..3]).unwrap();
        reader.read_exact(&mut buf[3..4]).unwrap();
        reader.read_exact(&mut buf[4..6]).unwrap();
        assert_eq!(&buf, b"foobar");

        let (mut raw_reader, context) = reader.finish();
        assert_eq!(raw_reader.stream_position().unwrap(), 6);
        assert_eq!(context.finish().as_ref(), FOOBAR_SHA256);
    }

    #[test]
    fn hashing_writer() {
        let raw_writer = Cursor::new([0u8; 6]);
        let mut writer = HashingWriter::new(raw_writer, Context::new(&ring::digest::SHA256));

        writer.write_all(b"").unwrap();
        writer.write_all(b"foo").unwrap();
        writer.write_all(b"bar").unwrap();

        let (mut raw_writer, context) = writer.finish();
        assert_eq!(raw_writer.stream_position().unwrap(), 6);
        assert_eq!(&raw_writer.into_inner(), b"foobar");
        assert_eq!(context.finish().as_ref(), FOOBAR_SHA256);
    }

    #[test]
    fn section_reader() {
        let raw_reader = Cursor::new(b"fooinnerbar");
        let mut reader = SectionReader::new(raw_reader, 3, 5).unwrap();

        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf[..0]).unwrap();
        reader.read_exact(&mut buf[..3]).unwrap();
        reader.read_exact(&mut buf[3..5]).unwrap();
        assert_eq!(&buf, b"inner");

        let n = reader.read_discard(1).unwrap();
        assert_eq!(n, 0);

        buf = *b"\0\0\0\0\0";
        reader.seek(SeekFrom::Start(4)).unwrap();
        reader.read_exact(&mut buf[..1]).unwrap();
        assert_eq!(&buf[..1], b"r");

        buf = *b"\0\0\0\0\0";
        reader.seek(SeekFrom::End(-4)).unwrap();
        reader.read_exact(&mut buf[..4]).unwrap();
        assert_eq!(&buf[..4], b"nner");

        buf = *b"\0\0\0\0\0";
        reader.seek(SeekFrom::Current(-5)).unwrap();
        reader.read_exact(&mut buf[..3]).unwrap();
        assert_eq!(&buf[..3], b"inn");

        let mut raw_reader = reader.into_inner();
        assert_eq!(raw_reader.stream_position().unwrap(), 6);
    }

    #[test]
    fn pseek_file() {
        let raw_file = tempfile::tempfile().unwrap();
        let mut a = PSeekFile::new(raw_file);
        let mut b = a.reopen().unwrap();
        let mut c = b.reopen().unwrap();

        b.write_all(b"foobar").unwrap();
        c.write_all(b"hello").unwrap();
        b.write_all(b"world").unwrap();
        c.seek(SeekFrom::Start(0)).unwrap();
        c.write_all(b"hi").unwrap();

        let mut buf = [0u8; 11];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hillorworld");

        let n = a.read_discard(1).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn shared_cursor() {
        let mut a = SharedCursor::default();
        let mut b = a.reopen().unwrap();
        let mut c = b.reopen().unwrap();

        b.write_all(b"foobar").unwrap();
        c.write_all(b"hello").unwrap();
        b.write_all(b"world").unwrap();
        c.seek(SeekFrom::Start(0)).unwrap();
        c.write_all(b"hi").unwrap();

        let mut buf = [0u8; 11];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hillorworld");

        let n = a.read_discard(1).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn copy() {
        let cancel_signal = AtomicBool::new(false);
        let mut reader = Cursor::new(b"foobar");
        let mut writer = Cursor::new([0u8; 6]);

        super::copy_n_inspect(&mut reader, &mut writer, 6, |_| {}, &cancel_signal).unwrap();
        assert_eq!(writer.get_ref(), b"foobar");

        // Reader early EOF.
        reader.seek(SeekFrom::Start(3)).unwrap();
        writer.rewind().unwrap();
        let err =
            super::copy_n_inspect(&mut reader, &mut writer, 6, |_| {}, &cancel_signal).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // Writer early EOF.
        reader.rewind().unwrap();
        writer.seek(SeekFrom::Start(3)).unwrap();
        let err =
            super::copy_n_inspect(&mut reader, &mut writer, 6, |_| {}, &cancel_signal).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);

        reader.rewind().unwrap();
        writer.rewind().unwrap();
        let n = super::copy(&mut reader, &mut writer, &cancel_signal).unwrap();
        assert_eq!(n, 6);
        assert_eq!(writer.get_ref(), b"foobar");

        // Reader early EOF.
        reader.seek(SeekFrom::Start(3)).unwrap();
        writer.rewind().unwrap();
        let n = super::copy(&mut reader, &mut writer, &cancel_signal).unwrap();
        assert_eq!(n, 3);

        // Writer early EOF.
        reader.rewind().unwrap();
        writer.seek(SeekFrom::Start(3)).unwrap();
        let err = super::copy(&mut reader, &mut writer, &cancel_signal).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);

        reader.rewind().unwrap();
        writer.rewind().unwrap();
        cancel_signal.store(true, Ordering::SeqCst);
        let err =
            super::copy_n_inspect(&mut reader, &mut writer, 6, |_| {}, &cancel_signal).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        let err = super::copy(&mut reader, &mut writer, &cancel_signal).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }
}
