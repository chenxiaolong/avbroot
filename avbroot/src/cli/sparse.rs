// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use crc32fast::Hasher;
use zerocopy::{little_endian, AsBytes};

use crate::{
    format::{
        padding,
        sparse::{
            self, Chunk, ChunkBounds, ChunkData, ChunkList, CrcMode, Header, SparseReader,
            SparseWriter,
        },
    },
    stream,
};

struct CompactView<'a, T>(&'a [T]);

impl<'a, T: fmt::Debug> fmt::Debug for CompactView<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();

        for item in self.0 {
            // No alternate mode for no inner newlines.
            list.entry(&format_args!("{item:?}"));
        }

        list.finish()
    }
}

#[derive(Clone)]
struct Metadata {
    header: Header,
    chunks: Vec<Chunk>,
}

impl fmt::Debug for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata")
            .field("header", &self.header)
            .field("chunks", &CompactView(&self.chunks))
            .finish()
    }
}

fn open_reader(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("Failed to open for reading: {path:?}"))
}

fn open_writer(path: &Path, truncate: bool) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(truncate)
        .open(path)
        .with_context(|| format!("Failed to open for writing: {path:?}"))
}

fn display_metadata(cli: &SparseCli, metadata: &Metadata) {
    if !cli.quiet {
        println!("{metadata:#?}");
    }
}

/// Splits large data chunks to ensure that none exceed 64 MiB. This is not
/// necessary in most cases, but is kept to match the behavior of AOSP's
/// libsparse.
fn split_chunks(chunks: &[Chunk], block_size: u32) -> Vec<Chunk> {
    const MAX_BYTES: u32 = 64 * 1024 * 1024;

    let max_blocks_per_chunk = MAX_BYTES / block_size;
    let mut result = vec![];

    for mut chunk in chunks.iter().copied() {
        if chunk.data == ChunkData::Data {
            while chunk.bounds.len() > max_blocks_per_chunk {
                result.push(Chunk {
                    bounds: ChunkBounds {
                        start: chunk.bounds.start,
                        end: chunk.bounds.start + max_blocks_per_chunk,
                    },
                    data: chunk.data,
                });

                chunk.bounds.start += max_blocks_per_chunk;
            }
        }

        result.push(chunk);
    }

    result
}

/// [Linux only] Find allocated regions of the file. This avoids needing to read
/// unused portions of the file if it is a native sparse file.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn find_allocated_regions(
    path: &Path,
    reader: &mut File,
    cancel_signal: &AtomicBool,
) -> Result<Vec<Range<u64>>> {
    use rustix::{fs::SeekFrom, io::Errno};

    let mut result = vec![];
    let mut start;
    let mut end = 0;

    loop {
        stream::check_cancel(cancel_signal)?;

        start = match rustix::fs::seek(&*reader, SeekFrom::Data(end as i64)) {
            Ok(offset) => offset,
            Err(e) if e == Errno::NXIO => break,
            Err(e) => return Err(e).with_context(|| format!("Failed to seek to data: {path:?}")),
        };

        end = rustix::fs::seek(&*reader, SeekFrom::Hole(start as i64))
            .with_context(|| format!("Failed to seek to hole: {path:?}"))?;

        result.push(start..end);
    }

    Ok(result)
}

/// Compute chunk boundaries for the list of potentially overlapping file byte
/// regions. If `exact_bounds` is true, then the regions must be block-aligned.
/// Otherwise, the lower boundaries are aligned down and the upper boundaries
/// are aligned up.
fn get_chunks_for_regions(
    block_size: u32,
    file_size: u64,
    file_regions: &[Range<u64>],
    exact_bounds: bool,
) -> Result<(u32, Vec<ChunkBounds>)> {
    let block_size_64 = u64::from(block_size);

    let file_blocks: u32 = (file_size / u64::from(block_size))
        .try_into()
        .map_err(|_| anyhow!("File size {file_size} too large for block size {block_size}"))?;

    let mut chunk_list = ChunkList::new();
    chunk_list.set_len(file_blocks);

    for region in file_regions {
        let mut start_byte = region.start;
        let mut end_byte = region.end;

        if exact_bounds {
            if start_byte % block_size_64 != 0 || end_byte % block_size_64 != 0 {
                bail!("File region bounds are not block-aligned: {region:?}");
            }
        } else {
            start_byte = start_byte / block_size_64 * block_size_64;
            end_byte = padding::round(end_byte, block_size_64).unwrap();
        }

        let start_block: u32 = (start_byte / block_size_64).try_into().map_err(|_| {
            anyhow!("Region start offset {start_byte} too large for block size {block_size}")
        })?;
        let end_block: u32 = (end_byte / block_size_64).try_into().map_err(|_| {
            anyhow!("Region end offset {end_byte} too large for block size {block_size}")
        })?;

        chunk_list.insert_data(ChunkBounds {
            start: start_block,
            end: end_block,
        });
    }

    let chunks = chunk_list.iter_allocated().map(|c| c.bounds).collect();

    Ok((file_blocks, chunks))
}

/// Compute the sparse [`Chunk`]s needed to cover the specified regions.
fn compute_chunks(
    path: &Path,
    reader: &mut File,
    block_size: u32,
    file_blocks: u32,
    block_regions: &[ChunkBounds],
    cancel_signal: &AtomicBool,
) -> Result<(ChunkList, u32)> {
    let mut chunk_list = ChunkList::new();
    let mut hasher = Some(Hasher::new());
    let mut buf = vec![0u8; block_size as usize];
    let mut block = 0;

    chunk_list.set_len(file_blocks);

    for bounds in block_regions {
        if bounds.start != block {
            // Not contiguous so we cannot compute the checksum.
            hasher = None;
        }

        let offset = u64::from(bounds.start) * u64::from(block_size);

        reader
            .seek(SeekFrom::Start(offset))
            .with_context(|| format!("Failed to seek file: {path:?}"))?;

        for block in *bounds {
            stream::check_cancel(cancel_signal)?;

            reader
                .read_exact(&mut buf)
                .with_context(|| format!("Failed to read full block: {path:?}"))?;

            if let Some(h) = &mut hasher {
                h.update(&buf);
            }

            let new_bounds = ChunkBounds {
                start: block,
                end: block + 1,
            };

            if buf.chunks_exact(4).all(|c| c == &buf[..4]) {
                let fill_value = u32::from_le_bytes(buf[..4].try_into().unwrap());
                chunk_list.insert_fill(new_bounds, fill_value);
            } else {
                chunk_list.insert_data(new_bounds);
            }
        }

        block = bounds.end;
    }

    if block != file_blocks {
        hasher = None;
    }

    let crc32 = hasher.map(|h| h.finalize()).unwrap_or_default();

    Ok((chunk_list, crc32))
}

fn unpack_subcommand(
    sparse_cli: &SparseCli,
    cli: &UnpackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let reader = open_reader(&cli.input)?;
    let mut sparse_reader = SparseReader::new(reader, CrcMode::Validate)
        .with_context(|| format!("Failed to read sparse file: {:?}", cli.input))?;

    let mut metadata = Metadata {
        header: sparse_reader.header(),
        chunks: vec![],
    };

    let mut writer = open_writer(&cli.output, !cli.preserve)?;

    if cli.preserve {
        let expected_size =
            u64::from(metadata.header.num_blocks) * u64::from(metadata.header.block_size);
        let file_size = writer
            .seek(SeekFrom::End(0))
            .with_context(|| format!("Failed to get file size: {:?}", cli.output))?;

        if file_size < expected_size {
            writer
                .set_len(expected_size)
                .with_context(|| format!("Failed to set file size: {:?}", cli.output))?;
        }

        writer
            .seek(SeekFrom::Start(0))
            .with_context(|| format!("Failed to seek file: {:?}", cli.output))?;
    }

    while let Some(chunk) = sparse_reader
        .next_chunk()
        .with_context(|| format!("Failed to read chunk: {:?}", cli.input))?
    {
        match chunk.data {
            ChunkData::Fill(value) => {
                let fill_value = little_endian::U32::from(value);
                let buf = vec![fill_value; metadata.header.block_size as usize / 4];

                for _ in chunk.bounds {
                    stream::check_cancel(cancel_signal)?;

                    writer
                        .write_all(buf.as_bytes())
                        .with_context(|| format!("Failed to write data: {:?}", cli.output))?;
                }
            }
            ChunkData::Data => {
                // This cannot overflow.
                let to_copy = chunk.bounds.len() * metadata.header.block_size;

                stream::copy_n(
                    &mut sparse_reader,
                    &mut writer,
                    to_copy.into(),
                    cancel_signal,
                )
                .with_context(|| {
                    format!("Failed to copy data: {:?} -> {:?}", cli.input, cli.output)
                })?;
            }
            ChunkData::Hole => {
                // This cannot overflow.
                let to_skip = chunk.bounds.len() * metadata.header.block_size;

                writer
                    .seek(SeekFrom::Current(to_skip.into()))
                    .with_context(|| format!("Failed to seek file: {:?}", cli.output))?;
            }
            ChunkData::Crc32(_) => {}
        }

        metadata.chunks.push(chunk);
    }

    display_metadata(sparse_cli, &metadata);

    sparse_reader
        .finish()
        .with_context(|| format!("Failed to finalize reader: {:?}", cli.input))?;

    Ok(())
}

fn pack_subcommand(
    sparse_cli: &SparseCli,
    cli: &PackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    if cli.block_size == 0 || cli.block_size % 4 != 0 {
        bail!(
            "Block size must be a non-zero multiple of 4: {}",
            cli.block_size,
        );
    }

    let mut reader = open_reader(&cli.input)?;

    let file_size = reader
        .seek(SeekFrom::End(0))
        .with_context(|| format!("Failed to get file size: {:?}", cli.input))?;
    if file_size % u64::from(cli.block_size) != 0 {
        bail!(
            "File size {file_size} is not a multiple of block size {}",
            cli.block_size,
        );
    }

    // Compute the byte regions to pack into the sparse file.
    let (file_regions, exact_bounds) = if !cli.region.is_empty() {
        let regions = cli
            .region
            .chunks_exact(2)
            .map(|c| c[0]..c[1])
            .collect::<Vec<_>>();

        (regions, false)
    } else {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let regions = find_allocated_regions(&cli.input, &mut reader, cancel_signal)?;

            (regions, false)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            #[allow(clippy::single_range_in_vec_init)]
            (vec![0..file_size], true)
        }
    };

    // Get the file regions as non-overlapping and sorted block regions.
    let (file_blocks, block_regions) =
        get_chunks_for_regions(cli.block_size, file_size, &file_regions, exact_bounds)?;

    // Compute the checksum (if possible) and the list of actual chunks.
    let (chunk_list, crc32) = compute_chunks(
        &cli.input,
        &mut reader,
        cli.block_size,
        file_blocks,
        &block_regions,
        cancel_signal,
    )?;

    let chunks = split_chunks(&chunk_list.to_chunks(), cli.block_size);
    let metadata = Metadata {
        header: Header {
            major_version: sparse::MAJOR_VERSION,
            minor_version: sparse::MINOR_VERSION,
            block_size: cli.block_size,
            num_blocks: chunk_list.len(),
            // This can't overflow because the number of chunks is always
            // smaller than the number of blocks (because we don't add CRC32
            // chunks).
            num_chunks: chunks.len() as u32,
            // This will be zero if the regions don't span the entire file.
            crc32,
        },
        chunks,
    };

    display_metadata(sparse_cli, &metadata);

    let writer = open_writer(&cli.output, true)?;
    let mut sparse_writer = SparseWriter::new(writer, metadata.header)
        .with_context(|| format!("Failed to initialize sparse file: {:?}", cli.output))?;

    for chunk in metadata.chunks {
        sparse_writer
            .start_chunk(chunk)
            .with_context(|| format!("Failed to start chunk: {:?}", cli.output))?;

        if chunk.data == ChunkData::Data {
            let offset = u64::from(chunk.bounds.start) * u64::from(cli.block_size);

            reader
                .seek(SeekFrom::Start(offset))
                .with_context(|| format!("Failed to seek file: {:?}", cli.input))?;

            let to_copy = u64::from(chunk.bounds.len()) * u64::from(cli.block_size);

            stream::copy_n(&mut reader, &mut sparse_writer, to_copy, cancel_signal).with_context(
                || format!("Failed to copy data: {:?} -> {:?}", cli.input, cli.output),
            )?;
        }
    }

    sparse_writer
        .finish()
        .with_context(|| format!("Failed to finalize writer: {:?}", cli.output))?;

    Ok(())
}

fn repack_subcommand(
    sparse_cli: &SparseCli,
    cli: &RepackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let reader = open_reader(&cli.input)?;
    let mut sparse_reader = SparseReader::new_seekable(reader, CrcMode::Validate)
        .with_context(|| format!("Failed to read sparse file: {:?}", cli.input))?;

    let mut metadata = Metadata {
        header: sparse_reader.header(),
        chunks: vec![],
    };

    let writer = open_writer(&cli.output, true)?;
    let mut sparse_writer = SparseWriter::new(writer, metadata.header)
        .with_context(|| format!("Failed to initialize sparse file: {:?}", cli.output))?;

    while let Some(chunk) = sparse_reader
        .next_chunk()
        .with_context(|| format!("Failed to read chunk: {:?}", cli.input))?
    {
        sparse_writer
            .start_chunk(chunk)
            .with_context(|| format!("Failed to start chunk: {:?}", cli.output))?;

        if chunk.data == ChunkData::Data {
            // This cannot overflow.
            let to_copy = chunk.bounds.len() * metadata.header.block_size;

            stream::copy_n(
                &mut sparse_reader,
                &mut sparse_writer,
                to_copy.into(),
                cancel_signal,
            )
            .with_context(|| format!("Failed to copy data: {:?} -> {:?}", cli.input, cli.output))?;
        }

        metadata.chunks.push(chunk);
    }

    display_metadata(sparse_cli, &metadata);

    sparse_reader
        .finish()
        .with_context(|| format!("Failed to finalize reader: {:?}", cli.input))?;
    sparse_writer
        .finish()
        .with_context(|| format!("Failed to finalize writer: {:?}", cli.output))?;

    Ok(())
}

fn info_subcommand(sparse_cli: &SparseCli, cli: &InfoCli) -> Result<()> {
    let reader = open_reader(&cli.input)?;
    let mut sparse_reader = SparseReader::new_seekable(reader, CrcMode::Ignore)
        .with_context(|| format!("Failed to read sparse file: {:?}", cli.input))?;

    let mut metadata = Metadata {
        header: sparse_reader.header(),
        chunks: vec![],
    };

    while let Some(chunk) = sparse_reader
        .next_chunk()
        .with_context(|| format!("Failed to read chunk: {:?}", cli.input))?
    {
        metadata.chunks.push(chunk);
    }

    display_metadata(sparse_cli, &metadata);

    Ok(())
}

pub fn sparse_main(cli: &SparseCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        SparseCommand::Unpack(c) => unpack_subcommand(cli, c, cancel_signal),
        SparseCommand::Pack(c) => pack_subcommand(cli, c, cancel_signal),
        SparseCommand::Repack(c) => repack_subcommand(cli, c, cancel_signal),
        SparseCommand::Info(c) => info_subcommand(cli, c),
    }
}

/// Unpack a sparse image.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input sparse image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output raw image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Preserve existing data in the output file.
    ///
    /// This is useful when unpacking multiple sparse files into a single output
    /// file because they contain disjoint blocks of data.
    #[arg(long)]
    preserve: bool,
}

/// Pack a sparse image.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output sparse image.
    ///
    /// If `--region` is not used and the input file is not a (native) sparse
    /// file on Linux, then the output sparse image is written with a CRC32
    /// checksum in the header.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to input raw image.
    ///
    /// On Linux, if this is a (native) sparse file, then the unallocated
    /// sections of the file will be skipped and will be stored in the output
    /// file as hole chunks.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Block size.
    #[arg(short, long, value_name = "BYTES", default_value_t = 4096)]
    block_size: u32,

    /// Pack certain byte regions from the file.
    ///
    /// The start offset will be aligned down to the block size and the end
    /// offset will be aligned up. This option can be specified any number of
    /// times and in any order. Overlapping regions are allowed.
    ///
    /// Unused regions will be stored in the sparse file as hole chunks.
    #[arg(short, long, value_names = ["START", "END"], num_args = 2)]
    region: Vec<u64>,
}

/// Repack a sparse image.
///
/// This command is equivalent to running `unpack` and `pack`, except without
/// storing the unpacked data to disk.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input sparse image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output sparse image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,
}

/// Display sparse image metadata.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input sparse image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum SparseCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
}

/// Pack, unpack, and inspect sparse images.
#[derive(Debug, Parser)]
pub struct SparseCli {
    #[command(subcommand)]
    command: SparseCommand,

    /// Don't print sparse image metadata.
    #[arg(short, long, global = true)]
    quiet: bool,
}
