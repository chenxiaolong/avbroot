// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, Read, Seek, Write};

use flate2::{
    Compression,
    read::{DeflateDecoder, GzDecoder},
    write::{DeflateEncoder, GzEncoder},
};
use lz4_flex::frame::FrameDecoder;
use lzma_rust2::{CheckType, XzOptions, XzReader, XzWriter};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::stream::ReadFixedSizeExt;

static GZIP_MAGIC: &[u8; 2] = b"\x1f\x8b";
static LZ4_LEGACY_MAGIC: &[u8; 4] = b"\x02\x21\x4c\x18";
static XZ_MAGIC: &[u8; 6] = b"\xfd\x37\x7a\x58\x5a\x00";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown compression format")]
    UnknownFormat,
    #[error("I/O error when autodetecting compression format")]
    AutoDetect(#[source] io::Error),
    #[error("Failed to initialize legacy LZ4 encoder")]
    Lz4Init(#[source] io::Error),
    #[error("Failed to initialize XZ encoder")]
    XzInit(#[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Lz4LegacyEncoder<W: Write> {
    writer: Option<W>,
    buf: Vec<u8>,
    n_filled: usize,
}

impl<W: Write> Lz4LegacyEncoder<W> {
    pub fn new(mut writer: W) -> io::Result<Self> {
        writer.write_all(LZ4_LEGACY_MAGIC)?;

        Ok(Self {
            writer: Some(writer),
            // We always use the max block size.
            buf: vec![0u8; 8 * 1024 * 1024],
            n_filled: 0,
        })
    }

    pub fn write_block(&mut self, force: bool) -> io::Result<()> {
        if !force && self.n_filled < self.buf.len() {
            // Block not fully filled yet.
            return Ok(());
        }

        // HC is currently not supported:
        // https://github.com/PSeitz/lz4_flex/issues/21
        let compressed = lz4_flex::block::compress(&self.buf[..self.n_filled]);

        let writer = self.writer.as_mut().unwrap();
        writer.write_all(&(compressed.len() as u32).to_le_bytes())?;
        writer.write_all(&compressed)?;

        self.n_filled = 0;

        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.write_block(true)?;
        Ok(self.writer.take().unwrap())
    }
}

impl<W: Write> Drop for Lz4LegacyEncoder<W> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            let _ = self.write_block(true);
        }
    }
}

impl<W: Write> Write for Lz4LegacyEncoder<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let total = buf.len();

        while !buf.is_empty() {
            let to_write = buf.len().min(self.buf.len() - self.n_filled);
            self.buf[self.n_filled..self.n_filled + to_write].copy_from_slice(&buf[..to_write]);

            self.n_filled += to_write;
            self.write_block(false)?;

            buf = &buf[to_write..];
        }

        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_block(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum CompressedFormat {
    None,
    Deflate,
    Gzip,
    Lz4Legacy,
    Xz,
}

pub enum CompressedReader<R: Read> {
    None(R),
    /// Not autodetected.
    Deflate(DeflateDecoder<R>),
    Gzip(GzDecoder<R>),
    Lz4(FrameDecoder<R>),
    /// Boxed because the [`XzReader`] is nearly 4 KiB.
    Xz(Box<XzReader<R>>),
}

impl<R: Read> CompressedReader<R> {
    pub fn with_format(reader: R, format: CompressedFormat) -> Self {
        match format {
            CompressedFormat::None => Self::None(reader),
            CompressedFormat::Deflate => Self::Deflate(DeflateDecoder::new(reader)),
            CompressedFormat::Gzip => Self::Gzip(GzDecoder::new(reader)),
            CompressedFormat::Lz4Legacy => Self::Lz4(FrameDecoder::new(reader)),
            CompressedFormat::Xz => Self::Xz(Box::new(XzReader::new(reader, false))),
        }
    }

    pub fn format(&self) -> CompressedFormat {
        match self {
            Self::None(_) => CompressedFormat::None,
            Self::Deflate(_) => CompressedFormat::Deflate,
            Self::Gzip(_) => CompressedFormat::Gzip,
            Self::Lz4(_) => CompressedFormat::Lz4Legacy,
            Self::Xz(_) => CompressedFormat::Xz,
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::None(r) => r,
            Self::Deflate(r) => r.into_inner(),
            Self::Gzip(r) => r.into_inner(),
            Self::Lz4(r) => r.into_inner(),
            Self::Xz(r) => r.into_inner(),
        }
    }
}

impl<R: Read + Seek> CompressedReader<R> {
    pub fn new(mut reader: R, raw_if_unknown: bool) -> Result<Self> {
        let magic = reader.read_array_exact::<6>().map_err(Error::AutoDetect)?;

        reader.rewind().map_err(Error::AutoDetect)?;

        if &magic[0..2] == GZIP_MAGIC {
            Ok(Self::Gzip(GzDecoder::new(reader)))
        } else if &magic[0..4] == LZ4_LEGACY_MAGIC {
            Ok(Self::Lz4(FrameDecoder::new(reader)))
        } else if &magic == XZ_MAGIC {
            Ok(Self::Xz(Box::new(XzReader::new(reader, false))))
        } else if raw_if_unknown {
            Ok(Self::None(reader))
        } else {
            Err(Error::UnknownFormat)
        }
    }
}

impl<R: Read> Read for CompressedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::None(r) => r.read(buf),
            Self::Deflate(r) => r.read(buf),
            Self::Gzip(r) => r.read(buf),
            Self::Lz4(r) => r.read(buf),
            Self::Xz(r) => r.read(buf),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum CompressedWriter<W: Write> {
    None(W),
    Deflate(DeflateEncoder<W>),
    Gzip(GzEncoder<W>),
    Lz4Legacy(Lz4LegacyEncoder<W>),
    Xz(XzWriter<W>),
}

impl<W: Write> CompressedWriter<W> {
    pub fn new(writer: W, format: CompressedFormat) -> Result<Self> {
        match format {
            CompressedFormat::None => Ok(Self::None(writer)),
            CompressedFormat::Deflate => Ok(Self::Deflate(DeflateEncoder::new(
                writer,
                Compression::default(),
            ))),
            CompressedFormat::Gzip => {
                Ok(Self::Gzip(GzEncoder::new(writer, Compression::default())))
            }
            CompressedFormat::Lz4Legacy => {
                let encoder = Lz4LegacyEncoder::new(writer).map_err(Error::Lz4Init)?;
                Ok(Self::Lz4Legacy(encoder))
            }
            CompressedFormat::Xz => {
                // Some kernels are compiled without support for the default CRC64.
                let mut options = XzOptions::with_preset(6);
                options.set_check_sum_type(CheckType::Crc32);

                let xz_writer = XzWriter::new(writer, options).map_err(Error::XzInit)?;
                Ok(Self::Xz(xz_writer))
            }
        }
    }

    pub fn format(&self) -> CompressedFormat {
        match self {
            Self::None(_) => CompressedFormat::None,
            Self::Deflate(_) => CompressedFormat::Deflate,
            Self::Gzip(_) => CompressedFormat::Gzip,
            Self::Lz4Legacy(_) => CompressedFormat::Lz4Legacy,
            Self::Xz(_) => CompressedFormat::Xz,
        }
    }

    pub fn finish(self) -> io::Result<W> {
        match self {
            Self::None(w) => Ok(w),
            Self::Deflate(w) => w.finish(),
            Self::Gzip(w) => w.finish(),
            Self::Lz4Legacy(w) => w.finish(),
            Self::Xz(w) => w.finish(),
        }
    }
}

impl<W: Write> Write for CompressedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::None(w) => w.write(buf),
            Self::Deflate(w) => w.write(buf),
            Self::Gzip(w) => w.write(buf),
            Self::Lz4Legacy(w) => w.write(buf),
            Self::Xz(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::None(w) => w.flush(),
            Self::Deflate(w) => w.flush(),
            Self::Gzip(w) => w.flush(),
            Self::Lz4Legacy(w) => w.flush(),
            Self::Xz(w) => w.flush(),
        }
    }
}
