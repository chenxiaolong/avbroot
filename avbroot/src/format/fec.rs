/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::HashSet,
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    ops::Range,
    sync::atomic::AtomicBool,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::ToPrimitive;
use rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};
use thiserror::Error;

use crate::{
    format::verityrs,
    stream::{self, FromReader, ReadSeekReopen, ToWriter, WriteSeekReopen, WriteZerosExt},
    util::{self, NumBytes},
};

// Not to be confused with the 255-byte RS block size.
const FEC_BLOCK_SIZE: usize = 4096;
const FEC_HEADER_SIZE: usize = 60;
const FEC_MAGIC: u32 = 0xFECFECFE;
const FEC_VERSION: u32 = 0;

const FEC_MAX_BLOCK_SIZE: u32 = 16384;

#[derive(Debug, Error)]
pub enum Error {
    #[error("FEC with parity byte count of {0} is not supported")]
    UnsupportedParity(u8),
    #[error("Cannot calculate FEC for empty data")]
    InputEmpty,
    #[error("Input size ({input}) is not a multiple of FEC block size ({block})")]
    NotBlockAligned { input: u64, block: u32 },
    #[error("FEC should have size {expected} for input size {input}, but has size {actual}")]
    InvalidFecSize {
        input: u64,
        expected: usize,
        actual: usize,
    },
    #[error("Cannot repair data due to too many errors")]
    TooManyErrors,
    #[error("Input data contains errors")]
    HasErrors,
    #[error("Data is too small to contain FEC headers")]
    DataTooSmall,
    #[error("The two FEC headers are different")]
    HeadersDifferent,
    #[error("Invalid FEC header magic: {0:#x}")]
    InvalidHeaderMagic(u32),
    #[error("Unsupported FEC header version: {0}")]
    UnsupportedHeaderVersion(u32),
    #[error("Invalid FEC header size: {0}")]
    InvalidHeaderSize(u32),
    #[error("FEC size in header {value} does not match available data ({available})")]
    InvalidHeaderFecSize { value: usize, available: usize },
    #[error("Expected FEC digest {expected}, but have {actual}")]
    InvalidFecDigest { expected: String, actual: String },
    #[error("{0:?} field is out of bounds")]
    FieldOutOfBounds(&'static str),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// A small wrapper around a byte array to represent a single Reed-Solomon
/// codeword for any `RS(255, K)`.
struct Codeword {
    data: [u8; 255],
    rs_k: u8,
}

impl Codeword {
    fn new(rs_k: u8) -> Self {
        Self {
            data: [0u8; 255],
            rs_k,
        }
    }

    fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.rs_k)]
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..usize::from(self.rs_k)]
    }

    fn parity(&mut self) -> &[u8] {
        &self.data[usize::from(self.rs_k)..]
    }

    fn parity_mut(&mut self) -> &mut [u8] {
        &mut self.data[usize::from(self.rs_k)..]
    }

    fn all(&self) -> &[u8] {
        &self.data
    }

    fn all_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// A type for performing FEC generation, verification, and error correction for
/// a specific file size and Reed Solomon configuration. The implementation uses
/// dm-verity's interleaving access pattern.
///
/// The interleaving access pattern can be visualized by placing the file
/// offsets in a two-dimensional grid. For example, when reading a 2072576-byte
/// file for calculating RS(255, 253):
///
/// ```text
///      | <-------- Round 0 --------> | <-------- Round 1 --------> |
///      |-----------------------------|-----------------------------|
///  ^   | 0       1       ... 4095    | 4096    4097    ... 8191    |
///  |   | 8192    8192    ... 12287   | 12288   12289   ... 16383   |
/// rs_k | 16384   16385   ... 20479   | 20480   20481   ... 24575   |
///  |   | ....... ....... ... ....... | ....... ....... ... ....... |
///  v   | 2064384 2064385 ... 2068479 | 2068480 2068481 ... 2072575 |
/// ```
///
/// A regular sequential read of the file is traversing the grid row-by-row,
/// while an interleaving read is traversing the grid column-by-column. Each
/// column is always `rs_k` items tall, so each column forms the data portion of
/// an RS codeword. The number of columns is always a multiple of the FEC block
/// size. Since RS operates on fixed-size codewords and a file size might not
/// always fill the grid completely, out-of-bounds offsets are treated as if
/// they contain a `\0` byte.
///
/// All operations are multithreaded with I/O operations parallelized at the
/// "round" level and RS operations parallelized at the column level.
pub struct Fec {
    file_size: u64,
    block_size: u32,
    rs_k: u8,
    rounds: u64,
}

impl Fec {
    pub fn new(file_size: u64, block_size: u32, parity: u8) -> Result<Self> {
        if file_size == 0 {
            return Err(Error::InputEmpty);
        } else if file_size % u64::from(block_size) != 0 {
            return Err(Error::NotBlockAligned {
                input: file_size,
                block: block_size,
            });
        } else if block_size > FEC_MAX_BLOCK_SIZE {
            return Err(Error::FieldOutOfBounds("block_size"));
        }

        let rs_k = 255 - parity;
        if !verityrs::FN_ENCODE.contains_key(&rs_k) {
            return Err(Error::UnsupportedParity(parity));
        }

        let blocks = util::div_ceil(file_size, u64::from(block_size));
        let rounds = util::div_ceil(blocks, u64::from(rs_k));

        // Check upfront so we don't need to do checked multiplication later.
        rounds
            .checked_mul(u64::from(parity))
            .and_then(|s| s.checked_mul(u64::from(block_size)))
            .and_then(|s| s.to_usize())
            .ok_or_else(|| Error::FieldOutOfBounds("fec_data_size"))?;
        rounds
            .checked_mul(u64::from(rs_k))
            .and_then(|s| s.checked_mul(u64::from(block_size)))
            .ok_or_else(|| Error::FieldOutOfBounds("fec_grid_size"))?;

        Ok(Self {
            file_size,
            block_size,
            rs_k,
            rounds,
        })
    }

    /// Get the number of parity bytes per codeword.
    #[inline]
    fn parity(&self) -> u8 {
        255 - self.rs_k
    }

    /// Get the size of the FEC data needed to cover the entire file.
    #[inline]
    fn fec_size(&self) -> usize {
        usize::from(self.parity()) * self.rounds as usize * self.block_size as usize
    }

    /// Get the backing file offset for the specified `offset` in the
    /// interleaved view.
    fn backing_offset(&self, offset: u64) -> u64 {
        let rs_k = u64::from(self.rs_k);

        offset / rs_k + offset % rs_k * self.rounds * u64::from(self.block_size)
    }

    /// Get the rounds that correspond to the specified ranges.
    fn rounds_for_ranges(&self, ranges: &[Range<u64>]) -> Result<HashSet<u64>> {
        let ranges = util::merge_overlapping(ranges);
        if let Some(last) = ranges.last() {
            if last.end > self.file_size {
                return Err(Error::FieldOutOfBounds("ranges"));
            }
        }

        let block_size = u64::from(self.block_size);
        let mut result = HashSet::new();

        for range in ranges {
            let start_block = range.start / block_size;
            let end_block = if range.end % block_size == 0 {
                range.end / block_size
            } else {
                util::div_ceil(range.end, block_size)
            };

            for block in start_block..end_block {
                result.insert(block % self.rounds);
            }
        }

        Ok(result)
    }

    /// Read a raw sequential block from the backing file, starting at offset
    /// `offset` in the interleaved view. This reads a horizontal block-aligned
    /// slice in the file offset grid.
    fn read_seq_block(
        &self,
        mut reader: impl Read + Seek,
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        assert_eq!(
            buf.len(),
            self.block_size as usize,
            "Buffer does not match block size",
        );

        let backing_offset = self.backing_offset(offset);

        // Out of bounds offsets are treated as if they contain zeros.
        if backing_offset >= self.file_size {
            buf.fill(0);
        } else {
            reader.seek(SeekFrom::Start(backing_offset))?;
            reader.read_exact(buf)?;
        }

        Ok(())
    }

    /// Write a raw sequential block to the backing file, starting at offset
    /// `offset` in the interleaved view. This writes a horizontal block-aligned
    /// slice in the file offset grid.
    fn write_seq_block(
        &self,
        mut writer: impl Write + Seek,
        offset: u64,
        buf: &[u8],
    ) -> io::Result<()> {
        assert_eq!(
            buf.len(),
            self.block_size as usize,
            "Buffer does not match block size",
        );

        let backing_offset = self.backing_offset(offset);

        // Out of bounds offsets are ignored.
        if backing_offset < self.file_size {
            writer.seek(SeekFrom::Start(backing_offset))?;
            writer.write_all(buf)?;
        }

        Ok(())
    }

    /// Read the nth round from the file. The data is laid out sequentially
    /// (row-by-row).
    fn read_round(&self, mut reader: impl Read + Seek, round: u64) -> io::Result<Vec<u8>> {
        let mut grid = vec![0u8; usize::from(self.rs_k) * self.block_size as usize];

        for row in 0..self.rs_k {
            let interleaved_offset =
                round * u64::from(self.rs_k) * u64::from(self.block_size) + u64::from(row);
            let row_start = usize::from(row) * self.block_size as usize;
            let row_end = row_start + self.block_size as usize;
            let row_slice = &mut grid[row_start..row_end];

            self.read_seq_block(&mut reader, interleaved_offset, row_slice)?;
        }

        Ok(grid)
    }

    /// Write the nth round to the file. The data is expected to be laid out
    /// sequentially (row-by-row).
    fn write_round(
        &self,
        mut writer: impl Write + Seek,
        round: u64,
        grid: &[u8],
    ) -> io::Result<()> {
        for row in 0..self.rs_k {
            let interleaved_offset =
                round * u64::from(self.rs_k) * u64::from(self.block_size) + u64::from(row);
            let row_start = usize::from(row) * self.block_size as usize;
            let row_end = row_start + self.block_size as usize;
            let row_slice = &grid[row_start..row_end];

            self.write_seq_block(&mut writer, interleaved_offset, row_slice)?;
        }

        Ok(())
    }

    /// Get the nth RS codeword from a round's grid.
    fn get_codeword(&self, grid: &[u8], column: usize) -> Codeword {
        let mut codeword = Codeword::new(self.rs_k);
        let data = codeword.data_mut();

        for row in 0..usize::from(self.rs_k) {
            data[row] = grid[row * self.block_size as usize + column];
        }

        codeword
    }

    /// Put the nth RS codeword into a round's grid.
    fn put_codeword(&self, grid: &mut [u8], column: usize, codeword: &Codeword) {
        let data = codeword.data();

        for row in 0..usize::from(self.rs_k) {
            grid[row * self.block_size as usize + column] = data[row];
        }
    }

    /// Generate FEC data for a single round.
    fn generate_one_round(
        &self,
        reader: impl Read + Seek,
        round: u64,
        fec: &mut [u8],
    ) -> Result<()> {
        assert_eq!(
            fec.len(),
            usize::from(self.parity()) * self.block_size as usize,
            "FEC buffer length does not match block size",
        );

        let grid = self.read_round(reader, round)?;
        let encode = verityrs::FN_ENCODE[&self.rs_k];
        let parity = usize::from(self.parity());

        for (column, buf) in fec.chunks_exact_mut(parity).enumerate() {
            let mut codeword = self.get_codeword(&grid, column);
            encode(codeword.all_mut());
            buf.copy_from_slice(codeword.parity());
        }

        Ok(())
    }

    /// Verify file data for a single round.
    fn verify_one_round(&self, reader: impl Read + Seek, round: u64, fec: &[u8]) -> Result<()> {
        assert_eq!(
            fec.len(),
            usize::from(self.parity()) * self.block_size as usize,
            "FEC buffer length does not match block size",
        );

        let grid = self.read_round(reader, round)?;
        let is_correct = verityrs::FN_IS_CORRECT[&self.rs_k];
        let parity = usize::from(self.parity());

        for (column, buf) in fec.chunks_exact(parity).enumerate() {
            let mut codeword = self.get_codeword(&grid, column);
            codeword.parity_mut().copy_from_slice(buf);

            if !is_correct(codeword.all()) {
                return Err(Error::HasErrors);
            }
        }

        Ok(())
    }

    /// Repair file data for a single round.
    fn repair_one_round(
        &self,
        reader: impl Read + Seek,
        writer: impl Write + Seek,
        round: u64,
        fec: &[u8],
    ) -> Result<u64> {
        assert_eq!(
            fec.len(),
            usize::from(self.parity()) * self.block_size as usize,
            "FEC buffer length does not match block size",
        );

        let mut grid = self.read_round(reader, round)?;
        let correct_errors = verityrs::FN_CORRECT_ERRORS[&self.rs_k];
        let parity = usize::from(self.parity());
        let mut num_corrected = 0;

        for (column, buf) in fec.chunks_exact(parity).enumerate() {
            let mut codeword = self.get_codeword(&grid, column);
            codeword.parity_mut().copy_from_slice(buf);

            let n = correct_errors(codeword.all_mut()).ok_or(Error::TooManyErrors)?;
            if n > 0 {
                self.put_codeword(&mut grid, column, &codeword);
            }

            num_corrected += n as u64;
        }

        if num_corrected > 0 {
            self.write_round(writer, round, &grid)?;
        }

        Ok(num_corrected)
    }

    /// Generate FEC data for the file. The file size must match the file size
    /// given to [`Self::new()`].
    ///
    /// This function is multithreaded and uses rayon's global thread pool.
    pub fn generate(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<u8>> {
        let fec_size = self.fec_size();
        let mut fec = vec![0u8; fec_size];

        fec.par_chunks_exact_mut(fec_size / self.rounds as usize)
            .enumerate()
            .map(|(round, buf)| -> Result<()> {
                stream::check_cancel(cancel_signal)?;

                let reader = input.reopen_boxed()?;
                self.generate_one_round(reader, round as u64, buf)
            })
            .collect::<Result<()>>()?;

        Ok(fec)
    }

    /// Update FEC data coreesponding to the specified file ranges.
    ///
    /// This function is multithreaded and uses rayon's global thread pool.
    pub fn update(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        ranges: &[Range<u64>],
        fec: &mut [u8],
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let fec_size = self.fec_size();
        if fec.len() != fec_size {
            return Err(Error::InvalidFecSize {
                input: self.file_size,
                expected: fec_size,
                actual: fec.len(),
            });
        }

        let rounds_to_update = self.rounds_for_ranges(ranges)?;

        fec.par_chunks_exact_mut(fec_size / self.rounds as usize)
            .enumerate()
            .filter(|(round, _)| rounds_to_update.contains(&(*round as u64)))
            .map(|(round, buf)| -> Result<()> {
                stream::check_cancel(cancel_signal)?;

                let reader = input.reopen_boxed()?;
                self.generate_one_round(reader, round as u64, buf)
            })
            .collect::<Result<()>>()?;

        Ok(())
    }

    /// Verify that the file contains no errors. This is significantly faster
    /// than [`Self::repair()`] if only error detection, not correction, is
    /// needed.
    ///
    /// This function is multithreaded and uses rayon's global thread pool.
    pub fn verify(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        fec: &[u8],
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let fec_size = self.fec_size();
        if fec.len() != fec_size {
            return Err(Error::InvalidFecSize {
                input: self.file_size,
                expected: fec_size,
                actual: fec.len(),
            });
        }

        fec.par_chunks_exact(fec_size / self.rounds as usize)
            .enumerate()
            .map(|(round, buf)| -> Result<()> {
                stream::check_cancel(cancel_signal)?;

                let reader = input.reopen_boxed()?;
                self.verify_one_round(reader, round as u64, buf)
            })
            .collect::<Result<()>>()?;

        Ok(())
    }

    /// Repair the file. Up to `parity / 2` bytes per codeword can be repaired.
    /// If the file is successfully repaired, the number of repaired bytes is
    /// returned. If the file is corrupt beyond repair, [`Error::TooManyErrors`]
    /// is returned. It's not safe to assume that as much data as possible has
    /// been repaired when [`Error::TooManyErrors`] is returned due to fail-fast
    /// behavior.
    ///
    /// This function corrects errors at unknown locations only. Correcting
    /// erasures at known locations is not supported.
    ///
    /// This function is multithreaded and uses rayon's global thread pool.
    pub fn repair(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        output: &(dyn WriteSeekReopen + Sync),
        fec: &[u8],
        cancel_signal: &AtomicBool,
    ) -> Result<u64> {
        let fec_size = self.fec_size();
        if fec.len() != fec_size {
            return Err(Error::InvalidFecSize {
                input: self.file_size,
                expected: fec_size,
                actual: fec.len(),
            });
        }

        let num_corrected = fec
            .par_chunks_exact(fec_size / self.rounds as usize)
            .enumerate()
            .map(|(round, buf)| -> Result<u64> {
                stream::check_cancel(cancel_signal)?;

                let reader = input.reopen_boxed()?;
                let writer = output.reopen_boxed()?;
                self.repair_one_round(reader, writer, round as u64, buf)
            })
            .collect::<Result<Vec<u64>>>()?
            .into_iter()
            .sum();

        Ok(num_corrected)
    }
}

/// A type for reading and writing AOSP's standalone FEC image format.
///
/// The FEC data parser in this implementation is strict. All header fields,
/// like the version, header size, and digest, must be valid and both copies of
/// the header must match.
#[derive(Clone, PartialEq, Eq)]
pub struct FecImage {
    pub fec: Vec<u8>,
    pub data_size: u64,
    pub parity: u8,
}

impl fmt::Debug for FecImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FecImage")
            .field("fec", &NumBytes(self.fec.len()))
            .field("data_size", &self.data_size)
            .field("parity", &self.parity)
            .finish()
    }
}

impl FecImage {
    /// Generate FEC data for a file. `parity` is the number of parity bytes per
    /// 255-byte Reed-Solomon codeword.
    pub fn generate(
        input: &(dyn ReadSeekReopen + Sync),
        parity: u8,
        cancel_signal: &AtomicBool,
    ) -> Result<Self> {
        let data_size = {
            let mut file = input.reopen_boxed()?;
            file.seek(SeekFrom::End(0))?
        };
        let fec = Fec::new(data_size, FEC_BLOCK_SIZE as u32, parity)?;
        let fec_data = fec.generate(input, cancel_signal)?;

        Ok(Self {
            fec: fec_data,
            data_size,
            parity,
        })
    }

    /// Update FEC data coreesponding to the specified file ranges.
    pub fn update(
        &mut self,
        input: &(dyn ReadSeekReopen + Sync),
        ranges: &[Range<u64>],
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let fec = Fec::new(self.data_size, FEC_BLOCK_SIZE as u32, self.parity)?;
        fec.update(input, ranges, &mut self.fec, cancel_signal)
    }

    /// Check that a file contains no errors. This is significantly faster than
    /// [`Self::repair()`] if performing a repair is not necessary.
    pub fn verify(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let fec = Fec::new(self.data_size, FEC_BLOCK_SIZE as u32, self.parity)?;
        fec.verify(input, &self.fec, cancel_signal)
    }

    /// Repair a file using this instance's FEC data. The maximum correctable
    /// errors per 255-byte codeword is half of [`Self::parity`]. Returns the
    /// number of bytes corrected if the file is successfully repaired or
    /// [`Error::TooManyErrors`] if the file cannot be repaired. This function
    /// fails fast. If an RS codeword cannot be repaired, other potentially
    /// repairable codewords may not be repaired.
    ///
    /// Note that if there are too many errors inside a certain codeword, it's
    /// possible for there to be a false positive where the corrupted codeword
    /// is "corrected" into an incorrect value. FEC error detection is not a
    /// replacement for cryptographically secure digests.
    ///
    /// The inputs and outputs should point to the same underlying file because
    /// only regions where errors are corrected are written. It is guaranteed
    /// that multiple threads will always read and write disjoint file offsets.
    pub fn repair(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        output: &(dyn WriteSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<u64> {
        let fec = Fec::new(self.data_size, FEC_BLOCK_SIZE as u32, self.parity)?;
        fec.repair(input, output, &self.fec, cancel_signal)
    }

    /// Build one instance of the FEC header. The caller is responsible for
    /// writing it to both of the header locations at the end of the file.
    fn build_header(&self) -> Result<[u8; FEC_HEADER_SIZE]> {
        let fec_size = self
            .fec
            .len()
            .to_u32()
            .ok_or_else(|| Error::FieldOutOfBounds("fec_size"))?;

        let mut writer = Cursor::new([0u8; FEC_HEADER_SIZE]);

        let digest = ring::digest::digest(&ring::digest::SHA256, &self.fec);

        writer.write_u32::<LittleEndian>(FEC_MAGIC)?;
        writer.write_u32::<LittleEndian>(FEC_VERSION)?;
        writer.write_u32::<LittleEndian>(FEC_HEADER_SIZE as u32)?;
        writer.write_u32::<LittleEndian>(self.parity.into())?;
        writer.write_u32::<LittleEndian>(fec_size)?;
        writer.write_u64::<LittleEndian>(self.data_size)?;
        writer.write_all(digest.as_ref())?;

        Ok(writer.into_inner())
    }
}

impl<R: Read> FromReader<R> for FecImage {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        // Avoid requiring seekable readers since we need to read everything
        // into memory anyway.
        let mut fec = Vec::new();
        reader.read_to_end(&mut fec)?;

        if fec.len() < FEC_BLOCK_SIZE {
            return Err(Error::DataTooSmall);
        }

        // Make sure both headers match.
        let header1_offset = fec.len() - FEC_BLOCK_SIZE;
        let header2_offset = fec.len() - FEC_HEADER_SIZE;
        let header1_raw = &fec[header1_offset..header1_offset + FEC_HEADER_SIZE];
        let header2_raw = &fec[header2_offset..header2_offset + FEC_HEADER_SIZE];

        if header1_raw != header2_raw {
            return Err(Error::HeadersDifferent);
        }

        let mut header_reader = Cursor::new(header1_raw);

        let magic = header_reader.read_u32::<LittleEndian>()?;
        if magic != FEC_MAGIC {
            return Err(Error::InvalidHeaderMagic(magic));
        }

        let version = header_reader.read_u32::<LittleEndian>()?;
        if version != FEC_VERSION {
            return Err(Error::UnsupportedHeaderVersion(version));
        }

        let header_size = header_reader.read_u32::<LittleEndian>()?;
        if header_size != FEC_HEADER_SIZE as u32 {
            return Err(Error::InvalidHeaderSize(header_size));
        }

        let parity = header_reader
            .read_u32::<LittleEndian>()?
            .to_u8()
            .ok_or_else(|| Error::FieldOutOfBounds("parity"))?;

        let fec_size = header_reader
            .read_u32::<LittleEndian>()?
            .to_usize()
            .ok_or_else(|| Error::FieldOutOfBounds("fec_size"))?;
        let actual_fec_size = fec.len() - FEC_BLOCK_SIZE;
        if fec_size != actual_fec_size {
            return Err(Error::InvalidHeaderFecSize {
                value: fec_size,
                available: actual_fec_size,
            });
        }

        let input_size = header_reader.read_u64::<LittleEndian>()?;

        let mut digest = [0u8; 32];
        header_reader.read_exact(&mut digest)?;

        // Chop off headers.
        fec.resize(fec_size, 0);

        let actual_digest = ring::digest::digest(&ring::digest::SHA256, &fec);
        if digest != actual_digest.as_ref() {
            return Err(Error::InvalidFecDigest {
                expected: hex::encode(digest),
                actual: hex::encode(actual_digest),
            });
        }

        Ok(Self {
            fec,
            data_size: input_size,
            parity,
        })
    }
}

impl<W: Write> ToWriter<W> for FecImage {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        let header = self.build_header()?;

        writer.write_all(&self.fec)?;
        writer.write_all(&header)?;
        writer.write_zeros_exact((FEC_BLOCK_SIZE - 2 * FEC_HEADER_SIZE) as u64)?;
        writer.write_all(&header)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Seek,
        sync::{atomic::AtomicBool, Arc},
    };

    use assert_matches::assert_matches;
    use rand::RngCore;

    use crate::stream::SharedCursor;

    use super::*;

    #[test]
    fn rounds_for_ranges() {
        let size = 2 * 253 * 4096;
        let fec = Fec::new(size, 4096, 2).unwrap();

        assert_eq!(fec.rounds_for_ranges(&[0..0]).unwrap(), HashSet::new());
        assert_eq!(
            fec.rounds_for_ranges(&[0..size]).unwrap(),
            HashSet::from([0, 1]),
        );
        assert_eq!(fec.rounds_for_ranges(&[0..1]).unwrap(), HashSet::from([0]));
        assert_eq!(
            fec.rounds_for_ranges(&[4095..4096]).unwrap(),
            HashSet::from([0]),
        );
        assert_eq!(
            fec.rounds_for_ranges(&[4095..4097]).unwrap(),
            HashSet::from([0, 1]),
        );
        assert_eq!(
            fec.rounds_for_ranges(&[size - 1..size]).unwrap(),
            HashSet::from([1]),
        );
    }

    fn corrupt_byte(file: &mut SharedCursor, offset: u64) {
        let mut buf = [0u8; 1];

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut buf).unwrap();

        buf[0] = buf[0].wrapping_add(1);

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&buf).unwrap();
    }

    fn run_test(block_size: u32, rs_k: u8) {
        let cancel_signal = Arc::new(AtomicBool::new(false));
        let parity = 255 - rs_k;

        // Generate data big enough to span multiple rounds, but don't fill the
        // offset grid to ensure that the out-of-bounds-is-0 behavior works.
        let size = usize::from(rs_k) * block_size as usize * 3 - block_size as usize;
        let mut file = SharedCursor::default();
        let orig_digest = {
            let mut buf = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut buf);
            file.write_all(&buf).unwrap();
            ring::digest::digest(&ring::digest::SHA256, &buf)
        };

        let fec = Fec::new(size as u64, block_size, parity).unwrap();
        assert_eq!(fec.rounds, 3);

        let num_codewords = fec.rounds as usize * block_size as usize;

        // Generate FEC data.
        let fec_data = fec.generate(&file, &cancel_signal).unwrap();

        // Verify that there are no errors.
        fec.verify(&file, &fec_data, &cancel_signal).unwrap();

        // Verify that errors are detected.
        corrupt_byte(&mut file, 0);
        assert_matches!(
            fec.verify(&file, &fec_data, &cancel_signal),
            Err(Error::HasErrors)
        );

        // Corrupt one byte in every single codeword.
        for offset in 1..num_codewords {
            corrupt_byte(&mut file, offset as u64);
        }

        // Verify that all the single-byte errors can be fixed. We don't test
        // for Error::TooManyErrors because of the chance of false positives due
        // to the nature of RS.
        fec.repair(&file, &file, &fec_data, &cancel_signal).unwrap();

        let repaired_digest = {
            let mut buf = Vec::new();
            file.rewind().unwrap();
            file.read_to_end(&mut buf).unwrap();
            ring::digest::digest(&ring::digest::SHA256, &buf)
        };
        assert_eq!(repaired_digest.as_ref(), orig_digest.as_ref());

        // Intentionally update some data.
        corrupt_byte(&mut file, 0);
        let mut fec_data_updated = fec_data.clone();
        let fec_data = fec.generate(&file, &cancel_signal).unwrap();
        fec.update(&file, &[0..1], &mut fec_data_updated, &cancel_signal)
            .unwrap();
        assert_eq!(fec_data_updated, fec_data);
    }

    #[test]
    fn generate_update_verify_repair() {
        for block_size in [1, 2, 4, 8, 16, 32, 64] {
            for rs_k in verityrs::FN_ENCODE.keys() {
                println!("Testing block_size={block_size}, rs_k={rs_k}");
                run_test(block_size, *rs_k);
            }
        }
    }

    #[test]
    fn round_trip_image() {
        let cancel_signal = Arc::new(AtomicBool::new(false));

        let mut file = SharedCursor::default();
        {
            let mut buf = [0u8; FEC_BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut buf);
            file.write_all(&buf).unwrap();
        }

        let image = FecImage::generate(&file, 2, &cancel_signal).unwrap();

        let mut fec_file = Cursor::new(Vec::new());
        image.to_writer(&mut fec_file).unwrap();

        fec_file.rewind().unwrap();
        let new_image = FecImage::from_reader(&mut fec_file).unwrap();

        assert_eq!(image, new_image);
    }
}
