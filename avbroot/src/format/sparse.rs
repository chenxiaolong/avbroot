// SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    io::{self, Read, Seek, Write},
    mem,
    ops::Range,
};

use crc32fast::Hasher;
use dlv_list::{Index, VecList};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes, byteorder::little_endian};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::stream::ReadDiscardExt;

/// Magic value for [`RawHeader::magic`].
const HEADER_MAGIC: u32 = 0xed26ff3a;

/// Raw chunk type for [`RawChunk::chunk_type`].
const CHUNK_TYPE_RAW: u16 = 0xcac1;
/// Fill chunk type for [`RawChunk::chunk_type`].
const CHUNK_TYPE_FILL: u16 = 0xcac2;
/// Hole chunk type for [`RawChunk::chunk_type`].
const CHUNK_TYPE_DONT_CARE: u16 = 0xcac3;
/// CRC32 chunk type for [`RawChunk::chunk_type`].
const CHUNK_TYPE_CRC32: u16 = 0xcac4;

/// Supported major version.
pub const MAJOR_VERSION: u16 = 1;
/// Supported minor version.
pub const MINOR_VERSION: u16 = 0;

#[derive(Debug, Error)]
pub enum Error {
    // Header errors.
    #[error("Invalid magic: {0:#010x}")]
    InvalidMagic(u32),
    #[error("Unsupported major version: {0}")]
    UnsupportedMajorVersion(u16),
    #[error("Invalid file header size: {0} < {size}", size = mem::size_of::<RawHeader>())]
    InvalidFileHeaderSize(u16),
    #[error("Invalid chunk header size: {0} < {size}", size = mem::size_of::<RawChunk>())]
    InvalidChunkHeaderSize(u16),
    #[error("Invalid block size (must be a non-zero multiple of 4): {0}")]
    InvalidBlockSize(u32),
    // Chunk errors.
    #[error("Chunk #{index}: Size overflow: {chunk_size} * {block_size}")]
    ChunkSizeOverflow {
        index: u32,
        chunk_size: u32,
        block_size: u32,
    },
    #[error("Chunk #{index}: Invalid type: {chunk_type}")]
    InvalidChunkType { index: u32, chunk_type: u16 },
    #[error("Chunk #{index}: Data size too large: {data_size}")]
    DataSizeTooLarge { index: u32, data_size: u32 },
    #[error("Chunk #{index}: Block count overflow: {start_block} + {chunk_size}")]
    BlockCountOverflow {
        index: u32,
        start_block: u32,
        chunk_size: u32,
    },
    #[error("Chunk #{index}: End block {end_block} exceeds total blocks {total_blocks}")]
    EndBlockExceedsTotal {
        index: u32,
        end_block: u32,
        total_blocks: u32,
    },
    #[error("Chunk #{index}: CRC32 chunk is not empty")]
    Crc32ChunkNotEmpty { index: u32, chunk_size: u32 },
    #[error("Chunk #{index}: Expected total size {expected_size}, but have {total_size}")]
    InvalidChunkSize {
        index: u32,
        expected_size: u32,
        total_size: u32,
    },
    // Reader errors.
    #[error("Must fully consume data when CRC validation is enabled")]
    Crc32RandomRead,
    #[error("Previous chunk still has {0} unread bytes")]
    UnreadChunkData(u32),
    #[error("Expected checkpoint CRC32 {expected:08x}, but have {actual:08x}")]
    MismatchedCrc32Checkpoint { expected: u32, actual: u32 },
    #[error("Expected final CRC32 {expected:08x}, but have {actual:08x}")]
    MismatchedCrc32Final { expected: u32, actual: u32 },
    // Writer errors.
    #[error("Minor version not supported for writing: {0}")]
    UnsupportedMinorVersion(u16),
    #[error("Previous chunk still has {0} unwritten bytes")]
    UnwrittenChunkData(u32),
    #[error("Already wrote all chunk headers")]
    TooManyChunks,
    #[error("Gap between end of last chunk {prev_end} and start of new chunk {cur_start}")]
    GapBetweenChunks { prev_end: u32, cur_start: u32 },
    // Wrapped errors.
    #[error("Failed to read sparse data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write sparse data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Raw on-disk layout for the header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHeader {
    /// Magic value. This should be equal to [`HEADER_MAGIC`].
    magic: little_endian::U32,
    /// Major version. [`MAJOR_VERSION`] is the only version supported. All
    /// other versions cannot be parsed.
    major_version: little_endian::U16,
    /// Minor version. Versions aside from [`MINOR_VERSION`] can be read, but
    /// not written.
    minor_version: little_endian::U16,
    /// Size of this [`RawHeader`].
    file_hdr_sz: little_endian::U16,
    /// Size of a [`RawChunk`].
    chunk_hdr_sz: little_endian::U16,
    /// Block size in bytes. Must be a multiple of 4.
    blk_sz: little_endian::U32,
    /// Number of blocks when unsparsed.
    total_blks: little_endian::U32,
    /// Number of chunks.
    total_chunks: little_endian::U32,
    /// CRC32 checksum of the original data.
    image_checksum: little_endian::U32,
}

impl fmt::Debug for RawHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawHeader")
            .field("magic", &format_args!("{:#010x}", self.magic))
            .field("major_version", &self.major_version.get())
            .field("minor_version", &self.minor_version.get())
            .field("file_hdr_sz", &self.file_hdr_sz.get())
            .field("chunk_hdr_sz", &self.chunk_hdr_sz.get())
            .field("blk_sz", &self.blk_sz.get())
            .field("total_blks", &self.total_blks.get())
            .field("total_chunks", &self.total_chunks.get())
            .field(
                "image_checksum",
                &format_args!("{:#010x}", self.image_checksum.get()),
            )
            .finish()
    }
}

impl RawHeader {
    fn validate(&self) -> Result<()> {
        if self.magic.get() != HEADER_MAGIC {
            return Err(Error::InvalidMagic(self.magic.get()));
        }

        if self.major_version.get() != MAJOR_VERSION {
            return Err(Error::UnsupportedMajorVersion(self.major_version.get()));
        }

        if self.file_hdr_sz.get() < mem::size_of::<Self>() as u16 {
            return Err(Error::InvalidFileHeaderSize(self.file_hdr_sz.get()));
        } else if self.chunk_hdr_sz.get() < mem::size_of::<RawChunk>() as u16 {
            return Err(Error::InvalidChunkHeaderSize(self.chunk_hdr_sz.get()));
        }

        if self.blk_sz.get() == 0 || self.blk_sz.get() % 4 != 0 {
            return Err(Error::InvalidBlockSize(self.blk_sz.get()));
        }

        Ok(())
    }

    fn excess_raw_header_bytes(&self) -> u16 {
        self.file_hdr_sz.get() - mem::size_of::<Self>() as u16
    }

    fn excess_raw_chunk_bytes(&self) -> u16 {
        self.chunk_hdr_sz.get() - mem::size_of::<RawChunk>() as u16
    }
}

/// Raw on-disk layout for the chunk header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawChunk {
    /// Chunk type. Must be [`CHUNK_TYPE_RAW`], [`CHUNK_TYPE_FILL`],
    /// [`CHUNK_TYPE_DONT_CARE`], or [`CHUNK_TYPE_CRC32`].
    chunk_type: little_endian::U16,
    /// Unused.
    reserved1: little_endian::U16,
    /// Number of unsparsed blocks this chunk represents.
    chunk_sz: little_endian::U32,
    /// The size in bytes of this chunk, including this [`RawChunk`].
    total_sz: little_endian::U32,
}

impl fmt::Debug for RawChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawChunk")
            .field("chunk_type", &self.chunk_type.get())
            .field("reserved1", &format_args!("{:#010x}", self.reserved1.get()))
            .field("chunk_sz", &self.chunk_sz.get())
            .field("total_sz", &self.total_sz.get())
            .finish()
    }
}

impl RawChunk {
    fn expected_size(&self, index: u32, header: &RawHeader) -> Result<u32> {
        let data_size = match self.chunk_type.get() {
            CHUNK_TYPE_RAW => self
                .chunk_sz
                .get()
                .checked_mul(header.blk_sz.get())
                .ok_or_else(|| Error::ChunkSizeOverflow {
                    index,
                    chunk_size: self.chunk_sz.get(),
                    block_size: header.blk_sz.get(),
                })?,
            CHUNK_TYPE_FILL | CHUNK_TYPE_CRC32 => 4,
            CHUNK_TYPE_DONT_CARE => 0,
            t => {
                return Err(Error::InvalidChunkType {
                    index,
                    chunk_type: t,
                });
            }
        };

        data_size
            .checked_add(header.chunk_hdr_sz.into())
            .ok_or(Error::DataSizeTooLarge { index, data_size })
    }

    fn validate(&self, index: u32, header: &RawHeader, start_block: u32) -> Result<()> {
        let end_block = start_block
            .checked_add(self.chunk_sz.get())
            .ok_or_else(|| Error::BlockCountOverflow {
                index,
                start_block,
                chunk_size: self.chunk_sz.get(),
            })?;

        if end_block > header.total_blks.get() {
            return Err(Error::EndBlockExceedsTotal {
                index,
                end_block,
                total_blocks: header.total_blks.get(),
            })?;
        }

        if self.chunk_type.get() == CHUNK_TYPE_CRC32 && self.chunk_sz.get() != 0 {
            return Err(Error::Crc32ChunkNotEmpty {
                index,
                chunk_size: self.chunk_sz.get(),
            });
        }

        let expected_size = self.expected_size(index, header)?;

        if expected_size != self.total_sz.get() {
            return Err(Error::InvalidChunkSize {
                index,
                expected_size,
                total_size: self.total_sz.get(),
            });
        }

        Ok(())
    }
}

/// Sparse file header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Major version. [`MAJOR_VERSION`] is the only version supported. All
    /// other versions cannot be parsed.
    pub major_version: u16,
    /// Minor version. Versions aside from [`MINOR_VERSION`] can be read, but
    /// not written.
    pub minor_version: u16,
    /// Block size in bytes. Must be a multiple of 4.
    pub block_size: u32,
    /// Number of blocks when unsparsed.
    pub num_blocks: u32,
    /// Number of chunks.
    pub num_chunks: u32,
    /// CRC32 checksum of the original data.
    pub crc32: u32,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("block_size", &self.block_size)
            .field("num_blocks", &self.num_blocks)
            .field("num_chunks", &self.num_chunks)
            .field("crc32", &format_args!("{:#010x}", self.crc32))
            .finish()
    }
}

/// Half-open range indicating the block range that a chunk covers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChunkBounds {
    /// Starting block (inclusive).
    pub start: u32,
    /// Ending block (exclusive).
    pub end: u32,
}

impl fmt::Debug for ChunkBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl IntoIterator for ChunkBounds {
    type Item = u32;

    type IntoIter = Range<u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.start..self.end
    }
}

impl ChunkBounds {
    /// Length in blocks.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.end - self.start
    }
}

/// The type of data contained in a chunk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChunkData {
    /// The chunk is filled with raw data.
    Data,
    /// The chunk is filled with repeating patterns of the specified integer
    /// encoded in little-endian.
    Fill(u32),
    /// The chunk is a hole and does not represent useful or valid data.
    Hole,
    /// The chunk is a CRC32 checksum. This does not represent actual data but
    /// serves as a checkpoint for validating the current checksum while in the
    /// middle of the sparse file.
    Crc32(u32),
}

impl fmt::Debug for ChunkData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "Data"),
            Self::Fill(value) => f
                .debug_tuple("Fill")
                .field(&format_args!("{value:#010x}"))
                .finish(),
            Self::Hole => write!(f, "Hole"),
            Self::Crc32(checksum) => f
                .debug_tuple("Crc32")
                .field(&format_args!("{checksum:#010x}"))
                .finish(),
        }
    }
}

/// A type that represents a contiguous list of blocks and the type of data or
/// metadata they contain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// When [`Self::data`] is [`ChunkData::Data`], this is guaranteed to not
    /// exceed the bounds of [`u32`] when multiplied by [`Header::block_size`].
    /// For other types of data, a 64-bit signed or unsigned integer is needed.
    pub bounds: ChunkBounds,
    pub data: ChunkData,
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("bounds", &self.bounds)
            .field("data", &format_args!("{:?}", self.data))
            .finish()
    }
}

/// A type for computing the minimal number of chunks for storing some given
/// data. Adding chunks sequentially is most efficient, though chunks can be
/// added in any order. Adding a new chunk that overlaps an existing chunk will
/// remove, truncate, or split the existing chunk accordingly.
#[derive(Clone, Debug, Default)]
pub struct ChunkList {
    chunks: VecList<Chunk>,
    last_used: Option<Index<Chunk>>,
    size: u32,
}

impl ChunkList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Split the previous chunk if its bounds contain the specified chunk.
    fn split_prev(&mut self, index: Index<Chunk>) {
        let Some(prev_index) = self.chunks.get_previous_index(index) else {
            return;
        };

        let cur = *self.chunks.get(index).unwrap();
        let prev = self.chunks.get_mut(prev_index).unwrap();

        debug_assert!(prev.bounds.start <= cur.bounds.start);

        if prev.bounds.end > cur.bounds.end {
            let new_chunk = Chunk {
                bounds: ChunkBounds {
                    start: cur.bounds.end,
                    end: prev.bounds.end,
                },
                data: prev.data,
            };

            prev.bounds.end = cur.bounds.start;
            self.chunks.insert_after(index, new_chunk);
        }
    }

    /// Merge the chunk at the specified index upwards until there are no more
    /// mergeable chunks. Returns the index of the new chunk that contains the
    /// original chunk.
    fn merge_down(&mut self, mut index: Index<Chunk>) -> Index<Chunk> {
        while let Some(prev_index) = self.chunks.get_previous_index(index) {
            let cur = *self.chunks.get(index).unwrap();
            let prev = self.chunks.get_mut(prev_index).unwrap();

            debug_assert!(prev.bounds.start <= cur.bounds.start);

            if prev.bounds.end < cur.bounds.start {
                // There's a gap.
                break;
            } else if cur.bounds.start <= prev.bounds.start {
                // Current chunk completely overlaps the previous chunk, so
                // remove the previous chunk.
                self.chunks.remove(prev_index);
                continue;
            } else if cur.bounds.start < prev.bounds.end {
                // Current chunk partially overlaps the previous chunk, so
                // truncate the previous chunk.
                prev.bounds.end = cur.bounds.start;
            }

            // If the data is compatible, then merge the chunks.
            if cur.data == prev.data {
                prev.bounds.end = cur.bounds.end;
                self.chunks.remove(index);
                index = prev_index;
            }

            break;
        }

        index
    }

    /// Merge the chunk at the specified index downwards until there are no more
    /// mergeable chunks. Returns the index of the new chunk that contains the
    /// original chunk.
    fn merge_up(&mut self, mut index: Index<Chunk>) -> Index<Chunk> {
        while let Some(next_index) = self.chunks.get_next_index(index) {
            let cur = *self.chunks.get(index).unwrap();
            let next = self.chunks.get_mut(next_index).unwrap();

            debug_assert!(cur.bounds.start <= next.bounds.start);

            if cur.bounds.end < next.bounds.start {
                // There's a gap.
                break;
            } else if cur.bounds.end >= next.bounds.end {
                // Current chunk completely overlaps the next chunk, so remove
                // the next chunk.
                self.chunks.remove(next_index);
                continue;
            } else if cur.bounds.end > next.bounds.start {
                // Current chunk partially overlaps the next chunk, so truncate
                // the next chunk.
                next.bounds.start = cur.bounds.end;
            }

            // If the data is compatible, then merge the chunks.
            if cur.data == next.data {
                next.bounds.start = cur.bounds.start;
                self.chunks.remove(index);
                index = next_index;
            }

            break;
        }

        index
    }

    /// Add the specified chunk into the list, removing, truncating, splitting,
    /// or merging chunks as needed. Returns the index of the chunk that
    /// contains the original chunk.
    fn add_chunk(&mut self, chunk: Chunk) -> Index<Chunk> {
        // Trivial case: adding the first chunk.
        if self.chunks.is_empty() {
            let index = self.chunks.push_back(chunk);
            self.last_used = Some(index);
            self.size = self.size.max(chunk.bounds.end);
            return index;
        }

        // Find the chunk to insert before. We save the last used index to
        // optimize for sequential insertion and avoid needing to search the
        // entire list every time.
        let mut insert_before = if let Some(last_used) = self.last_used
            && chunk.bounds.start >= self.chunks.get(last_used).unwrap().bounds.start
        {
            // The new chunk starts after the last used chunk.
            Some(last_used)
        } else {
            self.chunks.front_index()
        };

        while let Some(index) = insert_before {
            if self.chunks.get(index).unwrap().bounds.start >= chunk.bounds.start {
                break;
            }

            insert_before = self.chunks.get_next_index(index);
        }

        let mut chunk_index = if let Some(index) = insert_before {
            self.chunks.insert_before(index, chunk)
        } else {
            self.chunks.push_back(chunk)
        };

        // Split the previous chunk if it fully contains the new chunk.
        self.split_prev(chunk_index);

        // Merge with adjancent chunks if compatible.
        chunk_index = self.merge_up(chunk_index);
        chunk_index = self.merge_down(chunk_index);

        self.last_used = Some(chunk_index);
        self.size = self.size.max(chunk.bounds.end);

        chunk_index
    }

    /// Insert actual data at the specified region.
    pub fn insert_data(&mut self, bounds: ChunkBounds) {
        self.add_chunk(Chunk {
            bounds,
            data: ChunkData::Data,
        });
    }

    /// Insert a fill chunk at the specified region. The fill value is encoded
    /// in little-endian.
    pub fn insert_fill(&mut self, bounds: ChunkBounds, fill_value: u32) {
        self.add_chunk(Chunk {
            bounds,
            data: ChunkData::Fill(fill_value),
        });
    }

    /// Punch a hole at the specified region. If a hole is punched at the end
    /// of the file, the file size does not decrease.
    pub fn insert_hole(&mut self, bounds: ChunkBounds) {
        let index = self.add_chunk(Chunk {
            bounds,
            data: ChunkData::Hole,
        });

        // Special case: we don't actually store holes.
        self.last_used = self.chunks.get_previous_index(index);
        self.chunks.remove(index);
    }

    /// Get the file size in blocks.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.size
    }

    /// Set the file size in blocks. This automatically increases when adding a
    /// new chunk beyond this bound.
    pub fn set_len(&mut self, size: u32) {
        if size < self.size {
            self.insert_hole(ChunkBounds {
                start: size,
                end: self.size,
            });
        }

        self.size = size;
    }

    /// Get the list of chunks, including all holes.
    pub fn to_chunks(&self) -> Vec<Chunk> {
        let mut result = Vec::with_capacity(self.chunks.len());
        let mut block = 0;

        for chunk in &self.chunks {
            if chunk.bounds.start != block {
                result.push(Chunk {
                    bounds: ChunkBounds {
                        start: block,
                        end: chunk.bounds.start,
                    },
                    data: ChunkData::Hole,
                });
            }

            result.push(*chunk);

            block = chunk.bounds.end;
        }

        if block != self.size {
            result.push(Chunk {
                bounds: ChunkBounds {
                    start: block,
                    end: self.size,
                },
                data: ChunkData::Hole,
            });
        }

        result
    }

    /// Iterate through allocated chunks, which excludes holes.
    pub fn iter_allocated(&self) -> impl Iterator<Item = Chunk> + '_ {
        self.chunks.iter().copied()
    }
}

/// Whether to validate CRC32 checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrcMode {
    Validate,
    Ignore,
}

/// Hash what a fill chunk's contents would be if it were unsparsed.
fn hash_fill_chunk(
    raw_chunk: &RawChunk,
    fill_value: little_endian::U32,
    raw_header: &RawHeader,
    hasher: &mut Hasher,
) {
    let buf = [fill_value; 1024];
    let mut remain = u64::from(raw_chunk.chunk_sz) * u64::from(raw_header.blk_sz);

    while remain > 0 {
        let n = remain.min(buf.as_bytes().len() as u64) as usize;
        hasher.update(&buf.as_bytes()[..n]);
        remain -= n as u64;
    }
}

/// A type for reading sparse files.
pub struct SparseReader<R> {
    inner: R,
    seek_relative: Option<fn(&mut R, i64) -> io::Result<()>>,
    header: RawHeader,
    /// Starting block for next chunk.
    block: u32,
    /// Next chunk to read.
    chunk: u32,
    /// Number of bytes left to read for the current chunk if the chunk has
    /// [`ChunkData::Data`].
    data_remain: u32,
    hasher: Option<Hasher>,
}

impl<R: Read + Seek> SparseReader<R> {
    /// Create a new reader from a seekable file. This allows data chunks to be
    /// efficiently skipped without reading them.
    pub fn new_seekable(inner: R, crc_mode: CrcMode) -> Result<Self> {
        let mut result = Self::new(inner, crc_mode)?;
        result.seek_relative = Some(Seek::seek_relative);
        Ok(result)
    }
}

impl<R: Read> SparseReader<R> {
    /// Create a new reader from a stream. This cannot efficiently skip reading
    /// data chunks if they are not needed. If the underlying file is seekable
    /// and skipping chunks is needed, use [`Self::new_seekable`] instead.
    pub fn new(mut inner: R, crc_mode: CrcMode) -> Result<Self> {
        let header =
            RawHeader::read_from_io(&mut inner).map_err(|e| Error::DataRead("header", e))?;

        header.validate()?;

        inner
            .read_discard(header.excess_raw_header_bytes().into())
            .map_err(|e| Error::DataRead("header_excess", e))?;

        Ok(Self {
            inner,
            seek_relative: None,
            header,
            block: 0,
            chunk: 0,
            data_remain: 0,
            hasher: match crc_mode {
                CrcMode::Validate => Some(Hasher::new()),
                CrcMode::Ignore => None,
            },
        })
    }

    /// Get the sparse file header.
    pub fn header(&self) -> Header {
        Header {
            major_version: self.header.major_version.get(),
            minor_version: self.header.minor_version.get(),
            block_size: self.header.blk_sz.get(),
            num_blocks: self.header.total_blks.get(),
            num_chunks: self.header.total_chunks.get(),
            crc32: self.header.image_checksum.get(),
        }
    }

    /// Read the header for the next chunk. If the previous chunk had
    /// [`ChunkData::Data`], the data must be fully read first unless the
    /// reader is seekable and CRC validation is disabled. If the last chunk has
    /// already been read, then [`None`] is returned.
    ///
    /// For chunks with [`ChunkData::Crc32`], if CRC validation is enabled, the
    /// checksum will have already been verified. The caller does not need to
    /// perform its own verification.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>> {
        if self.data_remain != 0 {
            if let Some(seek_relative) = self.seek_relative {
                if self.hasher.is_some() {
                    return Err(Error::Crc32RandomRead);
                }

                seek_relative(&mut self.inner, self.data_remain.into())
                    .map_err(|e| Error::DataRead("data_remain", e))?;
                self.data_remain = 0;
            } else {
                return Err(Error::UnreadChunkData(self.data_remain));
            }
        }

        if self.chunk == self.header.total_chunks.get() {
            return Ok(None);
        }

        let raw_chunk =
            RawChunk::read_from_io(&mut self.inner).map_err(|e| Error::DataRead("chunk", e))?;

        raw_chunk.validate(self.chunk, &self.header, self.block)?;

        self.inner
            .read_discard(self.header.excess_raw_chunk_bytes().into())
            .map_err(|e| Error::DataRead("chunk_excess", e))?;

        let data: ChunkData;

        match raw_chunk.chunk_type.get() {
            CHUNK_TYPE_RAW => {
                self.data_remain =
                    raw_chunk.total_sz.get() - u32::from(self.header.chunk_hdr_sz.get());

                data = ChunkData::Data;
            }
            CHUNK_TYPE_FILL => {
                let fill_value = little_endian::U32::read_from_io(&mut self.inner)
                    .map_err(|e| Error::DataRead("chunk_fill_value", e))?;

                if let Some(hasher) = &mut self.hasher {
                    hash_fill_chunk(&raw_chunk, fill_value, &self.header, hasher);
                }

                data = ChunkData::Fill(fill_value.get());
            }
            CHUNK_TYPE_DONT_CARE => {
                if let Some(hasher) = &mut self.hasher {
                    hash_fill_chunk(&raw_chunk, 0.into(), &self.header, hasher);
                }

                data = ChunkData::Hole;
            }
            CHUNK_TYPE_CRC32 => {
                let expected = little_endian::U32::read_from_io(&mut self.inner)
                    .map_err(|e| Error::DataRead("chunk_crc32", e))?;

                if let Some(hasher) = &mut self.hasher {
                    let actual = hasher.clone().finalize();

                    if actual != expected.get() {
                        return Err(Error::MismatchedCrc32Checkpoint {
                            expected: expected.get(),
                            actual,
                        });
                    }
                }

                data = ChunkData::Crc32(expected.get());
            }
            _ => unreachable!(),
        }

        let chunk = Chunk {
            bounds: ChunkBounds {
                start: self.block,
                end: self.block + raw_chunk.chunk_sz.get(),
            },
            data,
        };

        self.chunk += 1;
        self.block = chunk.bounds.end;

        Ok(Some(chunk))
    }

    /// Verify the final checksum and return the underlying reader.
    pub fn finish(self) -> Result<R> {
        if let Some(hasher) = self.hasher {
            let expected = self.header.image_checksum.get();
            if expected != 0 {
                let actual = hasher.finalize();

                if actual != expected {
                    return Err(Error::MismatchedCrc32Final { expected, actual });
                }
            }
        }

        Ok(self.inner)
    }
}

impl<R: Read> Read for SparseReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let to_read = buf.len().min(self.data_remain as usize);

        let n = self.inner.read(&mut buf[..to_read])?;

        if let Some(hasher) = &mut self.hasher {
            hasher.update(&buf[..n]);
        }

        self.data_remain -= n as u32;

        Ok(n)
    }
}

/// A type for writing sparse files.
pub struct SparseWriter<W> {
    inner: W,
    header: RawHeader,
    /// Starting block for next chunk.
    block: u32,
    /// Next chunk to write.
    chunk: u32,
    /// Number of bytes left to write for the current chunk if the chunk has
    /// [`ChunkData::Data`].
    data_remain: u32,
    hasher: Hasher,
}

impl<W: Write> SparseWriter<W> {
    /// Create a new writer from a stream. This does not require the underlying
    /// file to be seekable, so the [`Header`] must be fully known up front.
    pub fn new(mut inner: W, header: Header) -> Result<Self> {
        if header.minor_version != MINOR_VERSION {
            return Err(Error::UnsupportedMinorVersion(header.minor_version));
        }

        let header = RawHeader {
            magic: HEADER_MAGIC.into(),
            major_version: header.major_version.into(),
            minor_version: header.minor_version.into(),
            file_hdr_sz: (mem::size_of::<RawHeader>() as u16).into(),
            chunk_hdr_sz: (mem::size_of::<RawChunk>() as u16).into(),
            blk_sz: header.block_size.into(),
            total_blks: header.num_blocks.into(),
            total_chunks: header.num_chunks.into(),
            image_checksum: header.crc32.into(),
        };

        header.validate()?;

        header
            .write_to_io(&mut inner)
            .map_err(|e| Error::DataWrite("header", e))?;

        Ok(Self {
            inner,
            header,
            block: 0,
            chunk: 0,
            data_remain: 0,
            // We include this unconditionally because we don't know if we'll
            // get any CRC32 chunks later.
            hasher: Hasher::new(),
        })
    }

    /// Write the header for the next chunk. If the previous chunk had
    /// [`ChunkData::Data`], the data must be fully written first.
    pub fn start_chunk(&mut self, chunk: Chunk) -> Result<()> {
        if self.data_remain != 0 {
            return Err(Error::UnwrittenChunkData(self.data_remain));
        }

        if self.chunk == self.header.total_chunks.get() {
            return Err(Error::TooManyChunks);
        }

        if chunk.bounds.start != self.block {
            return Err(Error::GapBetweenChunks {
                prev_end: self.block,
                cur_start: chunk.bounds.start,
            });
        }

        let mut raw_chunk = RawChunk {
            chunk_type: match chunk.data {
                ChunkData::Data => CHUNK_TYPE_RAW.into(),
                ChunkData::Fill(_) => CHUNK_TYPE_FILL.into(),
                ChunkData::Hole => CHUNK_TYPE_DONT_CARE.into(),
                ChunkData::Crc32(_) => CHUNK_TYPE_CRC32.into(),
            },
            reserved1: 0.into(),
            chunk_sz: chunk.bounds.len().into(),
            total_sz: 0.into(),
        };

        raw_chunk.total_sz = raw_chunk.expected_size(self.chunk, &self.header)?.into();

        raw_chunk.validate(self.chunk, &self.header, self.block)?;

        self.chunk += 1;
        self.block = chunk.bounds.end;

        raw_chunk
            .write_to_io(&mut self.inner)
            .map_err(|e| Error::DataWrite("chunk", e))?;

        match chunk.data {
            ChunkData::Data => {
                self.data_remain =
                    raw_chunk.total_sz.get() - u32::from(self.header.chunk_hdr_sz.get());
            }
            ChunkData::Fill(fill_value) => {
                self.inner
                    .write_all(&fill_value.to_le_bytes())
                    .map_err(|e| Error::DataWrite("chunk_fill_value", e))?;

                hash_fill_chunk(
                    &raw_chunk,
                    fill_value.into(),
                    &self.header,
                    &mut self.hasher,
                );
            }
            ChunkData::Hole => {
                hash_fill_chunk(&raw_chunk, 0.into(), &self.header, &mut self.hasher);
            }
            ChunkData::Crc32(expected) => {
                self.inner
                    .write_all(&expected.to_le_bytes())
                    .map_err(|e| Error::DataWrite("chunk_crc32", e))?;

                let actual = self.hasher.clone().finalize();
                if actual != expected {
                    return Err(Error::MismatchedCrc32Checkpoint { expected, actual });
                }
            }
        }

        Ok(())
    }

    /// Verify the final checksum and return the underlying writer.
    pub fn finish(self) -> Result<W> {
        let expected = self.header.image_checksum.get();
        if expected != 0 {
            let actual = self.hasher.finalize();

            if actual != expected {
                return Err(Error::MismatchedCrc32Final { expected, actual });
            }
        }

        Ok(self.inner)
    }
}

impl<W: Write> Write for SparseWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let to_write = buf.len().min(self.data_remain as usize);

        let n = self.inner.write(&buf[..to_write])?;

        self.hasher.update(&buf[..n]);

        self.data_remain -= n as u32;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_list_merge() {
        let mut list = ChunkList::new();

        // Insert adjacent blocks in non-sequential order.
        list.insert_fill(ChunkBounds { start: 1, end: 2 }, 0xaaaaaaaa);
        list.insert_fill(ChunkBounds { start: 0, end: 1 }, 0xaaaaaaaa);
        list.insert_fill(ChunkBounds { start: 2, end: 3 }, 0xaaaaaaaa);
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 3 },
                data: ChunkData::Fill(0xaaaaaaaa),
            },]
        );
    }

    #[test]
    fn chunk_list_overlap() {
        let mut list = ChunkList::new();

        // Replace existing chunks with a new chunk that ends at the same block,
        // but starts earlier.
        list.insert_fill(ChunkBounds { start: 2, end: 3 }, 0xaaaaaaaa);
        list.insert_fill(ChunkBounds { start: 3, end: 4 }, 0xaaaaaaaa);
        list.insert_fill(ChunkBounds { start: 1, end: 4 }, 0xbbbbbbbb);
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Hole,
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 4 },
                    data: ChunkData::Fill(0xbbbbbbbb),
                },
            ]
        );

        // Replace existing chunks with a new chunk that starts at the same
        // block, but ends later.
        list.insert_fill(ChunkBounds { start: 1, end: 5 }, 0xcccccccc);
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Hole,
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 5 },
                    data: ChunkData::Fill(0xcccccccc),
                },
            ]
        );

        // Replace existing chunks with a new chunk that's larger in both
        // directions.
        list.insert_fill(ChunkBounds { start: 0, end: 6 }, 0xdddddddd);
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 6 },
                data: ChunkData::Fill(0xdddddddd),
            },]
        );

        // Replace existing chunks with a new chunk that falls on the same
        // boundaries exactly.
        list.insert_fill(ChunkBounds { start: 0, end: 6 }, 0xeeeeeeee);
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 6 },
                data: ChunkData::Fill(0xeeeeeeee),
            },]
        );
    }

    #[test]
    fn chunk_list_split_chunk() {
        let mut list = ChunkList::new();

        // Insert a different chunk type into the middle of an existing chunk.
        list.insert_fill(ChunkBounds { start: 0, end: 3 }, 0xaaaaaaaa);
        list.insert_fill(ChunkBounds { start: 1, end: 2 }, 0xbbbbbbbb);
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 2 },
                    data: ChunkData::Fill(0xbbbbbbbb),
                },
                Chunk {
                    bounds: ChunkBounds { start: 2, end: 3 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
            ]
        );

        // Insert a chunk of the same type into the middle.
        list.insert_fill(ChunkBounds { start: 0, end: 3 }, 0xcccccccc);
        list.insert_fill(ChunkBounds { start: 1, end: 2 }, 0xcccccccc);
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 3 },
                data: ChunkData::Fill(0xcccccccc),
            },]
        );
    }

    #[test]
    fn chunk_list_punch_hole() {
        let mut list = ChunkList::new();

        // Punch a hole in the middle.
        list.insert_fill(ChunkBounds { start: 0, end: 3 }, 0xaaaaaaaa);
        list.insert_hole(ChunkBounds { start: 1, end: 2 });
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 2 },
                    data: ChunkData::Hole,
                },
                Chunk {
                    bounds: ChunkBounds { start: 2, end: 3 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
            ]
        );

        // Punch a hole at the end. The file size should not decrease.
        list.insert_hole(ChunkBounds { start: 2, end: 3 });
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 3 },
                    data: ChunkData::Hole,
                },
            ]
        );

        // Make the entire file a hole.
        list.insert_hole(ChunkBounds { start: 0, end: 1 });
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 3 },
                data: ChunkData::Hole,
            },]
        );
    }

    #[test]
    fn chunk_list_set_len() {
        let mut list = ChunkList::new();

        // Truncate the file.
        list.insert_fill(ChunkBounds { start: 0, end: 3 }, 0xaaaaaaaa);
        list.set_len(2);
        assert_eq!(
            list.to_chunks(),
            vec![Chunk {
                bounds: ChunkBounds { start: 0, end: 2 },
                data: ChunkData::Fill(0xaaaaaaaa),
            },]
        );

        // Expand the file.
        list.set_len(3);
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 2 },
                    data: ChunkData::Fill(0xaaaaaaaa),
                },
                Chunk {
                    bounds: ChunkBounds { start: 2, end: 3 },
                    data: ChunkData::Hole,
                },
            ]
        );

        // Clear the file.
        list.set_len(0);
        assert_eq!(list.to_chunks(), vec![]);

        // File size should remain the same when adding a chunk that does not
        // force an expansion.
        list.set_len(3);
        list.insert_fill(ChunkBounds { start: 0, end: 1 }, 0xbbbbbbbb);
        assert_eq!(
            list.to_chunks(),
            vec![
                Chunk {
                    bounds: ChunkBounds { start: 0, end: 1 },
                    data: ChunkData::Fill(0xbbbbbbbb),
                },
                Chunk {
                    bounds: ChunkBounds { start: 1, end: 3 },
                    data: ChunkData::Hole,
                },
            ]
        );
    }
}
