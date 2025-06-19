// SPDX-FileCopyrightText: 2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, Seek, SeekFrom, Write};

use zip::{
    ZipWriter,
    result::ZipResult,
    write::{FileOptionExtension, FileOptions, StreamWriter},
};

/// A wrapper around a seekable writer. `W` must implement [`Seek`], but only
/// during the creation of a new instance. The resulting type can be stored in a
/// parent container where the generic type does not implement [`Seek`].
pub struct SeekWriter<W: Write> {
    inner: W,
    seek_fn: fn(&mut W, SeekFrom) -> io::Result<u64>,
}

impl<W: Write> SeekWriter<W> {
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write + Seek> SeekWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            seek_fn: W::seek,
        }
    }
}

impl<W: Write> Write for SeekWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Seek for SeekWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (self.seek_fn)(&mut self.inner, pos)
    }
}

/// This is an ugly hack to have a single type represent both seekable and
/// streaming [`ZipWriter`]s. `W` only needs to implement [`Seek`] when creating
/// a seekable instance via [`Self::new_seekable`].
pub enum ZipWriterWrapper<W: Write> {
    Streaming(ZipWriter<StreamWriter<W>>),
    Seekable(ZipWriter<SeekWriter<W>>),
}

impl<W: Write + Seek> ZipWriterWrapper<W> {
    pub fn new_seekable(inner: W) -> Self {
        Self::Seekable(ZipWriter::new(SeekWriter::new(inner)))
    }
}

impl<W: Write> ZipWriterWrapper<W> {
    pub fn new_streaming(inner: W) -> Self {
        Self::Streaming(ZipWriter::new_stream(inner))
    }

    pub fn start_file(
        &mut self,
        name: impl ToString,
        options: FileOptions<impl FileOptionExtension>,
    ) -> ZipResult<u64> {
        match self {
            Self::Streaming(z) => z.start_file(name, options),
            Self::Seekable(z) => z.start_file(name, options),
        }
    }

    pub fn finish(self) -> ZipResult<W> {
        match self {
            Self::Streaming(z) => Ok(z.finish()?.into_inner()),
            Self::Seekable(z) => Ok(z.finish()?.into_inner()),
        }
    }
}

impl<W: Write> Write for ZipWriterWrapper<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Streaming(z) => z.write(buf),
            Self::Seekable(z) => z.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Streaming(z) => z.flush(),
            Self::Seekable(z) => z.flush(),
        }
    }
}
