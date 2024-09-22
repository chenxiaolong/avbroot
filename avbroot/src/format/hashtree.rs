// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    io::{self, Cursor, Read, SeekFrom, Write},
    ops::Range,
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::ToPrimitive;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use ring::digest::{Algorithm, Context};
use thiserror::Error;

use crate::{
    format::{avb, padding},
    stream::{self, FromReader, ReadSeekReopen, ReadStringExt, ToWriter, WriteStringExt},
    util::{self, NumBytes},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Hash tree should have size {expected} for input size {input}, but has size {actual}")]
    InvalidHashTreeSize {
        input: u64,
        expected: usize,
        actual: usize,
    },
    #[error("Expected root digest {expected}, but have {actual}")]
    InvalidRootDigest { expected: String, actual: String },
    #[error("Expected hash tree {expected}, but have {actual}")]
    InvalidHashTree { expected: String, actual: String },
    #[error("Invalid hash tree header magic: {:?}", .0.as_bstr())]
    InvalidHeaderMagic([u8; 16]),
    #[error("Invalid hash tree header version: {0}")]
    InvalidHeaderVersion(u16),
    #[error("Hashing algorithm not supported: {0:?}")]
    UnsupportedHashAlgorithm(String),
    #[error("{0:?} field is out of bounds")]
    FieldOutOfBounds(&'static str),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct HashTree {
    block_size: u32,
    salted_context: Context,
}

impl HashTree {
    pub fn new(block_size: u32, algorithm: &'static Algorithm, salt: &[u8]) -> Self {
        let mut salted_context = Context::new(algorithm);
        salted_context.update(salt);

        Self {
            block_size,
            salted_context,
        }
    }

    /// Compute the list of offset ranges that each level occupies in the hash
    /// tree data. The items are returned with the bottom level's offsets first
    /// in the list. Note that the bottom level is stored at the end of the hash
    /// tree data.
    pub fn compute_level_offsets(&self, image_size: u64) -> Result<Vec<Range<usize>>> {
        let algorithm = self.salted_context.algorithm();
        let digest_size = algorithm.output_len().next_power_of_two();
        let mut ranges = vec![];
        let mut level_size = image_size;

        while level_size > u64::from(self.block_size) {
            let blocks = level_size.div_ceil(u64::from(self.block_size));
            level_size = blocks
                .checked_mul(digest_size as u64)
                .and_then(|s| padding::round(s, u64::from(self.block_size)))
                .ok_or_else(|| Error::FieldOutOfBounds("level_size"))?;

            // Depending on the chosen block size, the original file size could
            // overflow a usize without the first level's size doing the same.
            let level_size_usize = level_size
                .to_usize()
                .ok_or_else(|| Error::FieldOutOfBounds("level_size"))?;

            ranges.push(0..level_size_usize);
        }

        // The hash tree puts the leaves at the end.
        let mut offset = 0;
        for range in ranges.iter_mut().rev() {
            let level_size = range.end - range.start;
            range.start += offset;
            range.end += offset;
            offset += level_size;
        }

        Ok(ranges)
    }

    /// Convert a list of ranges of byte offsets to a sorted, non-overlapping
    /// list of block ranges.
    fn blocks_for_ranges(&self, image_size: u64, ranges: &[Range<u64>]) -> Result<Vec<Range<u64>>> {
        let ranges = util::merge_overlapping(ranges);
        if let Some(last) = ranges.last() {
            if last.end > image_size {
                return Err(Error::FieldOutOfBounds("ranges"));
            }
        }

        let block_size = u64::from(self.block_size);
        let mut result = Vec::new();

        for range in ranges {
            let start_block = range.start / block_size;
            let end_block = if range.end % block_size == 0 {
                range.end / block_size
            } else {
                range.end.div_ceil(block_size)
            };

            result.push(start_block..end_block);
        }

        Ok(util::merge_overlapping(&result))
    }

    /// Calculate the hash tree digests for a single level of the tree. If the
    /// reader's position is block-aligned and `image_size` is a multiple of the
    /// block size, then this function can also be used to calculate the digests
    /// for a portion of a level.
    fn hash_partial_level(
        &self,
        mut reader: impl Read,
        mut size: u64,
        mut level_data: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<()> {
        // Each digest must be a power of 2.
        let algorithm = self.salted_context.algorithm();
        let digest_padding = algorithm.output_len().next_power_of_two() - algorithm.output_len();
        let mut buf = vec![0u8; self.block_size as usize];

        while size > 0 {
            stream::check_cancel(cancel_signal)?;

            let n = size.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..n])?;

            // For undersized blocks, we still hash the whole buffer, except
            // with padding.
            buf[n..].fill(0);

            let mut context = self.salted_context.clone();
            context.update(&buf);

            // Add the digest to the tree level. Each tree node must be a power
            // of two.
            let digest = context.finish();

            level_data[..digest.as_ref().len()].copy_from_slice(digest.as_ref());
            level_data = &mut level_data[digest.as_ref().len()..];

            level_data[..digest_padding].fill(0);
            level_data = &mut level_data[digest_padding..];

            size -= n as u64;
        }

        Ok(())
    }

    /// Hash one full level in parallel.
    fn hash_one_level_parallel(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        size: u64,
        level_data: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<()> {
        assert!(
            size > self.block_size as u64,
            "Images smaller than block size must use a normal hash",
        );

        // Parallelize in larger chunks to avoid too much seek thrashing.
        let algorithm = self.salted_context.algorithm();
        let digest_size = algorithm.output_len().next_power_of_two();
        let multiplier = 1024u64;

        level_data
            .par_chunks_mut(digest_size * multiplier as usize)
            .enumerate()
            .map(|(chunk, out_data)| -> io::Result<()> {
                let digests = out_data.len() / digest_size;
                let in_start = (chunk as u64) * multiplier * u64::from(self.block_size);
                let in_size = ((digests as u64) * u64::from(self.block_size)).min(size - in_start);

                let mut reader = input.reopen_boxed()?;
                reader.seek(SeekFrom::Start(in_start))?;

                self.hash_partial_level(reader, in_size, out_data, cancel_signal)
            })
            .collect::<io::Result<()>>()?;

        Ok(())
    }

    /// Update parts of the hash tree level corresponding to the specified
    /// blocks.
    fn hash_partial_level_parallel(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        size: u64,
        block_ranges: &[Range<u64>],
        level_data: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<()> {
        let algorithm = self.salted_context.algorithm();
        let digest_size = algorithm.output_len().next_power_of_two();

        level_data
            .par_chunks_exact_mut(digest_size)
            .enumerate()
            .filter(|(chunk, _)| util::ranges_contains(block_ranges, &(*chunk as u64)))
            .map(|(chunk, out_data)| -> io::Result<()> {
                let in_start = (chunk as u64) * u64::from(self.block_size);
                let in_size = u64::from(self.block_size).min(size - in_start);

                let mut reader = input.reopen_boxed()?;
                reader.seek(SeekFrom::Start(in_start))?;

                self.hash_partial_level(reader, in_size, out_data, cancel_signal)
            })
            .collect::<io::Result<()>>()?;

        Ok(())
    }

    /// Compute the hash tree and return the root digest. If `ranges` is
    /// specified, then only the input file blocks containing those ranges are
    /// recomputed.
    ///
    /// `hash_tree_data` must match `level_offsets`. In other words, the ending
    /// offset of the leaf layer of the tree must equal `hash_tree_data`'s size.
    fn calculate(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        ranges: Option<&[Range<u64>]>,
        level_offsets: &[Range<usize>],
        hash_tree_data: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<u8>> {
        // Small files are hashed directly.
        if image_size <= u64::from(self.block_size) {
            let mut reader = input.reopen_boxed()?;
            let mut buf = vec![0u8; image_size as usize];
            reader.read_exact(&mut buf)?;

            let mut context = self.salted_context.clone();
            context.update(&buf);
            let digest = context.finish();

            return Ok(digest.as_ref().to_vec());
        }

        // Large files use the hash tree.
        for (i, level_range) in level_offsets.iter().enumerate() {
            let (front, back) = hash_tree_data.split_at_mut(level_range.end);
            let level_data = &mut front[level_range.clone()];

            if i > 0 {
                // Hash the previous level.
                let prev_range = level_offsets[i - 1].clone();
                let prev_size = prev_range.end - prev_range.start;
                let prev_data = &back[..prev_size];

                self.hash_partial_level(
                    Cursor::new(prev_data),
                    prev_size as u64,
                    level_data,
                    cancel_signal,
                )?;
            } else if let Some(r) = ranges {
                // Read partial blocks from file.
                let block_ranges = self.blocks_for_ranges(image_size, r)?;

                self.hash_partial_level_parallel(
                    input,
                    image_size,
                    &block_ranges,
                    level_data,
                    cancel_signal,
                )?;
            } else {
                // Read entire file.
                self.hash_one_level_parallel(input, image_size, level_data, cancel_signal)?;
            }

            // No need to explicitly ensure the level is padded to the block
            // size since the tree is initialized with zeros.
        }

        // Calculate the root hash.
        let mut context = self.salted_context.clone();
        context.update(&hash_tree_data[level_offsets.last().unwrap().clone()]);
        let root_hash = context.finish().as_ref().to_vec();

        Ok(root_hash)
    }

    /// Generate hash tree data for the file. Returns the root digest and the
    /// hash tree data.
    pub fn generate(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        cancel_signal: &AtomicBool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let offsets = self.compute_level_offsets(image_size)?;
        let hash_tree_size = offsets.first().map(|r| r.end).unwrap_or(0);
        let mut hash_tree_data = vec![0u8; hash_tree_size];

        let root_digest = self.calculate(
            input,
            image_size,
            None,
            &offsets,
            &mut hash_tree_data,
            cancel_signal,
        )?;

        Ok((root_digest, hash_tree_data))
    }

    /// Update hash tree data corresponding to the specified file ranges.
    /// Returns the new root digest.
    pub fn update(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        ranges: &[Range<u64>],
        hash_tree_data: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<u8>> {
        let offsets = self.compute_level_offsets(image_size)?;
        let hash_tree_size = offsets.first().map(|r| r.end).unwrap_or(0);
        if hash_tree_data.len() != hash_tree_size {
            return Err(Error::InvalidHashTreeSize {
                input: image_size,
                expected: hash_tree_size,
                actual: hash_tree_data.len(),
            });
        }

        self.calculate(
            input,
            image_size,
            Some(ranges),
            &offsets,
            hash_tree_data,
            cancel_signal,
        )
    }

    /// Verify that the file contains no errors.
    pub fn verify(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        root_digest: &[u8],
        hash_tree_data: &[u8],
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let offsets = self.compute_level_offsets(image_size)?;
        let hash_tree_size = offsets.first().map(|r| r.end).unwrap_or(0);
        if hash_tree_data.len() != hash_tree_size {
            return Err(Error::InvalidHashTreeSize {
                input: image_size,
                expected: hash_tree_size,
                actual: hash_tree_data.len(),
            });
        }

        let (actual_root_digest, actual_hash_tree_data) =
            self.generate(input, image_size, cancel_signal)?;

        if root_digest != actual_root_digest {
            return Err(Error::InvalidRootDigest {
                expected: hex::encode(root_digest),
                actual: hex::encode(&actual_root_digest),
            });
        }

        if hash_tree_data != actual_hash_tree_data {
            // These are multiple megabytes, so only report the hashes.
            let algorithm = self.salted_context.algorithm();
            let expected = ring::digest::digest(algorithm, hash_tree_data);
            let actual = ring::digest::digest(algorithm, &actual_hash_tree_data);

            return Err(Error::InvalidHashTree {
                expected: hex::encode(expected),
                actual: hex::encode(actual),
            });
        }

        Ok(())
    }
}

/// A type for reading and writing a custom hash tree image format.
///
/// File format:
/// - [0  .. 16]   - ASCII  - "avbroot!hashtree"
/// - [16 .. 18]   - U16LE  - Version
/// - [18 .. 26]   - U64LE  - Image size
/// - [26 .. 30]   - U32LE  - Block size
/// - [30 .. 46]   - ASCII  - Hash algorithm
/// - [46 .. 48]   - U16LE  - Salt size
/// - [48 .. 50]   - U16LE  - Root digest size
/// - [50 .. 54]   - U32LE  - Hash tree size
/// - [<variable>] - BINARY - Salt
/// - [<variable>] - BINARY - Root digest
/// - [<variable>] - BINARY - Hash tree
#[derive(Clone, PartialEq, Eq)]
pub struct HashTreeImage {
    pub image_size: u64,
    pub block_size: u32,
    pub algorithm: String,
    pub salt: Vec<u8>,
    pub root_digest: Vec<u8>,
    pub hash_tree: Vec<u8>,
}

impl fmt::Debug for HashTreeImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashTreeImage")
            .field("block_size", &self.block_size)
            .field("algorithm", &self.algorithm)
            .field("salt", &hex::encode(&self.salt))
            .field("root_digest", &hex::encode(&self.root_digest))
            .field("hash_tree", &NumBytes(self.hash_tree.len()))
            .finish()
    }
}

impl HashTreeImage {
    const MAGIC: &'static [u8; 16] = b"avbroot!hashtree";
    const VERSION: u16 = 1;

    pub fn ring_algorithm(name: &str) -> Result<&'static Algorithm> {
        avb::ring_algorithm(name, false)
            .map_err(|_| Error::UnsupportedHashAlgorithm(name.to_owned()))
    }

    /// Generate hash tree data for a file.
    pub fn generate(
        input: &(dyn ReadSeekReopen + Sync),
        block_size: u32,
        algorithm: &str,
        salt: &[u8],
        cancel_signal: &AtomicBool,
    ) -> Result<Self> {
        let image_size = {
            let mut file = input.reopen_boxed()?;
            file.seek(SeekFrom::End(0))?
        };
        let ring_algorithm = Self::ring_algorithm(algorithm)?;
        let hash_tree = HashTree::new(block_size, ring_algorithm, salt);
        let (root_digest, hash_tree_data) = hash_tree.generate(input, image_size, cancel_signal)?;

        Ok(Self {
            image_size,
            block_size,
            algorithm: algorithm.to_owned(),
            salt: salt.to_vec(),
            root_digest,
            hash_tree: hash_tree_data,
        })
    }

    /// Update hash tree data coreesponding to the specified file ranges.
    pub fn update(
        &mut self,
        input: &(dyn ReadSeekReopen + Sync),
        ranges: &[Range<u64>],
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let ring_algorithm = Self::ring_algorithm(&self.algorithm)?;
        let hash_tree = HashTree::new(self.block_size, ring_algorithm, &self.salt);

        self.root_digest = hash_tree.update(
            input,
            self.image_size,
            ranges,
            &mut self.hash_tree,
            cancel_signal,
        )?;

        Ok(())
    }

    /// Check that a file contains no errors.
    pub fn verify(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let ring_algorithm = Self::ring_algorithm(&self.algorithm)?;
        let hash_tree = HashTree::new(self.block_size, ring_algorithm, &self.salt);

        hash_tree.verify(
            input,
            self.image_size,
            &self.root_digest,
            &self.hash_tree,
            cancel_signal,
        )
    }
}

impl<R: Read> FromReader<R> for HashTreeImage {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 16];
        reader.read_exact(&mut magic)?;
        if magic != *Self::MAGIC {
            return Err(Error::InvalidHeaderMagic(magic));
        }

        let version = reader.read_u16::<LittleEndian>()?;
        if version != Self::VERSION {
            return Err(Error::InvalidHeaderVersion(version));
        }

        let image_size = reader.read_u64::<LittleEndian>()?;
        let block_size = reader.read_u32::<LittleEndian>()?;
        let algorithm = reader.read_string_padded(16)?;
        let salt_size = reader.read_u16::<LittleEndian>()?;
        let root_digest_size = reader.read_u16::<LittleEndian>()?;
        let hash_tree_size = reader
            .read_u32::<LittleEndian>()?
            .to_usize()
            .ok_or_else(|| Error::FieldOutOfBounds("hash_tree_size"))?;

        let mut salt = vec![0u8; usize::from(salt_size)];
        reader.read_exact(&mut salt)?;

        let mut root_digest = vec![0u8; usize::from(root_digest_size)];
        reader.read_exact(&mut root_digest)?;

        let mut hash_tree = vec![0u8; hash_tree_size];
        reader.read_exact(&mut hash_tree)?;

        Ok(Self {
            image_size,
            block_size,
            algorithm,
            salt,
            root_digest,
            hash_tree,
        })
    }
}

impl<W: Write> ToWriter<W> for HashTreeImage {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        let salt_size = self
            .salt
            .len()
            .to_u16()
            .ok_or_else(|| Error::FieldOutOfBounds("salt_size"))?;
        let root_digest_size = self
            .root_digest
            .len()
            .to_u16()
            .ok_or_else(|| Error::FieldOutOfBounds("root_digest_size"))?;
        let hash_tree_size = self
            .hash_tree
            .len()
            .to_u32()
            .ok_or_else(|| Error::FieldOutOfBounds("hash_tree_size"))?;

        writer.write_all(Self::MAGIC)?;
        writer.write_u16::<LittleEndian>(Self::VERSION)?;
        writer.write_u64::<LittleEndian>(self.image_size)?;
        writer.write_u32::<LittleEndian>(self.block_size)?;
        writer.write_string_padded(&self.algorithm, 16)?;
        writer.write_u16::<LittleEndian>(salt_size)?;
        writer.write_u16::<LittleEndian>(root_digest_size)?;
        writer.write_u32::<LittleEndian>(hash_tree_size)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.root_digest)?;
        writer.write_all(&self.hash_tree)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use assert_matches::assert_matches;

    use crate::stream::SharedCursor;

    use super::*;

    #[test]
    fn calculate_level_ranges() {
        let hash_tree = HashTree::new(4096, &ring::digest::SHA256, &[]);
        assert_eq!(
            hash_tree.compute_level_offsets(0).unwrap(),
            &[] as &[Range<usize>],
        );
        assert_eq!(
            hash_tree.compute_level_offsets(1024 * 1024 * 1024).unwrap(),
            &[69632..8458240, 4096..69632, 0..4096],
        )
    }

    #[test]
    fn blocks_for_ranges() {
        let hash_tree = HashTree::new(4096, &ring::digest::SHA256, b"Salt");
        assert_eq!(
            hash_tree.blocks_for_ranges(16384, &[0..16384]).unwrap(),
            &[0..4],
        );
        assert_eq!(hash_tree.blocks_for_ranges(16384, &[0..0]).unwrap(), &[]);
        assert_eq!(
            hash_tree
                .blocks_for_ranges(16384, &[12287..12289, 0..1, 5000..5001])
                .unwrap(),
            &[0..4],
        );
        assert_matches!(
            hash_tree.blocks_for_ranges(16384, &[0..16385]),
            Err(Error::FieldOutOfBounds(_))
        );
    }

    #[test]
    fn generate_update_verify() {
        let cancel_signal = AtomicBool::new(false);
        let hash_tree = HashTree::new(64, &ring::digest::SHA256, b"Salt");
        let mut input = SharedCursor::new();

        // Try input smaller than one block.
        let (root_digest, hash_tree_data) = hash_tree.generate(&input, 0, &cancel_signal).unwrap();

        assert_eq!(
            root_digest,
            &[
                0x15, 0x0f, 0xe5, 0x51, 0x40, 0x30, 0xb1, 0x43, 0x4a, 0x5d, 0xea, 0xf4, 0x91, 0xec,
                0xe9, 0x2c, 0x0e, 0x64, 0x97, 0x44, 0x7d, 0x6d, 0xe7, 0xbd, 0x6b, 0xa8, 0x5e, 0x8c,
                0xae, 0x1e, 0x00, 0xa3
            ],
        );
        assert_eq!(hash_tree_data, &[]);

        // Try larger input that spans multiple blocks are results in an actual
        // hash tree being created.
        input.write_all(&b"Data".repeat(25)).unwrap();

        let (root_digest, mut hash_tree_data) =
            hash_tree.generate(&input, 100, &cancel_signal).unwrap();
        assert_eq!(
            root_digest,
            &[
                0x92, 0xc3, 0xd7, 0x4a, 0x64, 0x03, 0x4b, 0xcc, 0xa9, 0x9a, 0x44, 0xf6, 0x81, 0xa2,
                0x4d, 0xdd, 0x97, 0xd3, 0xda, 0x84, 0xdc, 0xe2, 0x1b, 0x83, 0xd1, 0x7b, 0xab, 0x60,
                0x59, 0xe8, 0x45, 0x59
            ],
        );
        assert_eq!(
            hash_tree_data,
            &[
                0x7e, 0x33, 0x47, 0xb6, 0xf3, 0x7c, 0xde, 0x0e, 0xe2, 0x8d, 0x9e, 0x49, 0x8e, 0xd4,
                0xbd, 0x53, 0x3a, 0xa1, 0xff, 0xeb, 0x4f, 0x6d, 0x5a, 0x5f, 0x55, 0x28, 0x37, 0x79,
                0xd0, 0x25, 0x07, 0xd5, 0xb7, 0x7f, 0x1a, 0x48, 0x92, 0x12, 0x91, 0xdb, 0x92, 0x04,
                0x74, 0xf6, 0x86, 0x31, 0xfc, 0x64, 0xb6, 0xc8, 0x72, 0xb0, 0xf7, 0x7d, 0x24, 0xa4,
                0x3c, 0x87, 0x1f, 0xc9, 0xd8, 0x17, 0x8a, 0xd9
            ],
        );

        // Change some data and update the hash tree.
        input.rewind().unwrap();
        input.write_all(b"Changed").unwrap();

        let root_digest = hash_tree
            .update(&input, 100, &[0..7], &mut hash_tree_data, &cancel_signal)
            .unwrap();
        assert_eq!(
            root_digest,
            &[
                0x8d, 0x03, 0xad, 0x18, 0xf2, 0x53, 0x13, 0x59, 0xf5, 0xbf, 0x68, 0x0e, 0x0c, 0x4a,
                0x86, 0xe2, 0x6e, 0xaa, 0x3d, 0x4b, 0x0f, 0x1b, 0x57, 0xad, 0x92, 0xe7, 0xbf, 0x3e,
                0xa6, 0xb1, 0x2e, 0xcc
            ],
        );
        assert_eq!(
            hash_tree_data,
            &[
                0xfe, 0x46, 0xf7, 0x8c, 0xa1, 0xd9, 0xc8, 0xdd, 0x47, 0x9e, 0x6c, 0x32, 0x7c, 0x38,
                0x7f, 0x09, 0xe1, 0x58, 0x92, 0xa3, 0xb6, 0xbd, 0x96, 0xef, 0x10, 0xe8, 0x30, 0xb0,
                0x37, 0x8d, 0xef, 0x9a, 0xb7, 0x7f, 0x1a, 0x48, 0x92, 0x12, 0x91, 0xdb, 0x92, 0x04,
                0x74, 0xf6, 0x86, 0x31, 0xfc, 0x64, 0xb6, 0xc8, 0x72, 0xb0, 0xf7, 0x7d, 0x24, 0xa4,
                0x3c, 0x87, 0x1f, 0xc9, 0xd8, 0x17, 0x8a, 0xd9
            ],
        );

        // Updated hash tree should match newly generated tree.
        let (new_root_digest, new_hash_tree_data) =
            hash_tree.generate(&input, 100, &cancel_signal).unwrap();
        assert_eq!(new_root_digest, root_digest);
        assert_eq!(new_hash_tree_data, hash_tree_data);

        // Data should validate successfully.
        hash_tree
            .verify(&input, 100, &root_digest, &hash_tree_data, &cancel_signal)
            .unwrap();

        // But not if the data is corrupted.
        input.rewind().unwrap();
        input.write_all(b"Bad").unwrap();

        hash_tree
            .verify(&input, 100, &root_digest, &hash_tree_data, &cancel_signal)
            .unwrap_err();
    }
}
