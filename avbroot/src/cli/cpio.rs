/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Seek},
    path::{Path, PathBuf},
    str,
    sync::atomic::AtomicBool,
};

use anyhow::{anyhow, Context, Result};
use bstr::ByteSlice;
use cap_std::{ambient_authority, fs::Dir};
use clap::{Parser, Subcommand};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::{
    format::{
        compression::{CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{self, CpioEntry, CpioEntryData, CpioEntryType, CpioReader, CpioWriter},
    },
    stream, util,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct CpioInfo {
    format: CompressedFormat,
    entries: Vec<CpioEntry>,
}

fn open_reader(
    path: &Path,
    include_trailer: bool,
) -> Result<(
    CpioReader<CompressedReader<BufReader<File>>>,
    CompressedFormat,
)> {
    let file =
        File::open(path).with_context(|| format!("Failed to open cpio for reading: {path:?}"))?;
    let reader = CompressedReader::new(BufReader::new(file), true)
        .with_context(|| format!("Failed to open decompressor: {path:?}"))?;
    let format = reader.format();
    let cpio_reader = CpioReader::new(reader, include_trailer);

    Ok((cpio_reader, format))
}

fn open_writer(
    path: &Path,
    format: CompressedFormat,
) -> Result<CpioWriter<CompressedWriter<BufWriter<File>>>> {
    let file =
        File::create(path).with_context(|| format!("Failed to open cpio for writing: {path:?}"))?;
    let writer = CompressedWriter::new(BufWriter::new(file), format)
        .with_context(|| format!("Failed to open compressor: {path:?}"))?;
    let cpio_writer = CpioWriter::new(writer, false);

    Ok(cpio_writer)
}

fn flush_writer(writer: CpioWriter<CompressedWriter<BufWriter<File>>>) -> Result<()> {
    let compressed_writer = writer.finish().context("Failed to flush cpio writer")?;
    let buf_writer = compressed_writer
        .finish()
        .context("Failed to flush compressor")?;
    buf_writer.into_inner().context("Failed to flush file")?;

    Ok(())
}

/// Read cpio information from TOML file.
fn read_info(path: &Path) -> Result<CpioInfo> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read cpio info TOML: {path:?}"))?;
    let info = toml_edit::de::from_str(&data)
        .with_context(|| format!("Failed to parse cpio info TOML: {path:?}"))?;

    Ok(info)
}

/// Write cpio information to TOML file.
fn write_info(path: &Path, info: &CpioInfo) -> Result<()> {
    let data = toml_edit::ser::to_string_pretty(info)
        .with_context(|| format!("Failed to serialize cpio info TOML: {path:?}"))?;
    fs::write(path, data).with_context(|| format!("Failed to write cpio info TOML: {path:?}"))?;

    Ok(())
}

/// Open reader to the corresponding file inside the tree if the entry is a
/// regular file. Unsafe paths will result in an error.
fn open_tree_file(tree: &Dir, entry: &CpioEntry) -> Result<Option<(BufReader<File>, u32)>> {
    if entry.file_type == CpioEntryType::Regular {
        let path = entry
            .path
            .as_bstr()
            .to_path()
            .with_context(|| format!("Invalid entry path: {:?}", entry.path.as_bstr()))?;

        let mut reader = tree
            .open(path)
            .map(|f| BufReader::new(f.into_std()))
            .with_context(|| format!("Failed to open for reading: {path:?}"))?;

        let file_size = reader
            .seek(std::io::SeekFrom::End(0))
            .with_context(|| format!("Failed to get file size: {path:?}"))?
            .to_u32()
            .ok_or_else(|| anyhow!("File is too large: {path:?}"))?;
        reader
            .rewind()
            .with_context(|| format!("Failed to seek file: {path:?}"))?;

        Ok(Some((reader, file_size)))
    } else {
        Ok(None)
    }
}

/// Open writer to the corresponding file inside the tree if the entry is a
/// regular file. Intermediate directories are automatically created as needed.
/// Unsafe paths will result in an error.
fn create_tree_file(tree: &Dir, entry: &CpioEntry) -> Result<Option<BufWriter<File>>> {
    if entry.file_type == CpioEntryType::Regular {
        let path = entry
            .path
            .as_bstr()
            .to_path()
            .with_context(|| format!("Invalid entry path: {:?}", entry.path.as_bstr()))?;
        let parent = util::parent_path(path);

        tree.create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {parent:?}"))?;

        let writer = tree
            .create(path)
            .map(|f| BufWriter::new(f.into_std()))
            .with_context(|| format!("Failed to open for writing: {path:?}"))?;

        Ok(Some(writer))
    } else {
        Ok(None)
    }
}

fn display_format(cli: &CpioCli, format: CompressedFormat) {
    if !cli.quiet {
        println!("Compression format: {format:?}");
    }
}

fn display_entry(cli: &CpioCli, entry: &CpioEntry) {
    if !cli.quiet {
        println!();
        println!("{entry}");
    }
}

fn unpack_subcommand(
    cpio_cli: &CpioCli,
    cli: &UnpackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let (mut reader, format) = open_reader(&cli.input, false)?;
    let mut info = CpioInfo {
        format,
        entries: vec![],
    };

    display_format(cpio_cli, format);

    let authority = ambient_authority();
    Dir::create_ambient_dir_all(&cli.output_tree, authority)
        .with_context(|| format!("Failed to create directory: {:?}", cli.output_tree))?;
    let tree = Dir::open_ambient_dir(&cli.output_tree, authority)
        .with_context(|| format!("Failed to open directory: {:?}", cli.output_tree))?;

    while let Some(entry) = reader.next_entry().context("Failed to read cpio entry")? {
        display_entry(cpio_cli, &entry);

        if let Some(mut writer) = create_tree_file(&tree, &entry)? {
            let file_size = entry.data.size()?;

            stream::copy_n(&mut reader, &mut writer, file_size.into(), cancel_signal)
                .context("Failed to copy data")?;

            writer.into_inner().context("Failed to flush data")?;
        }

        info.entries.push(entry);
    }

    write_info(&cli.output_info, &info)?;

    Ok(())
}

fn pack_subcommand(cpio_cli: &CpioCli, cli: &PackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let mut info = read_info(&cli.input_info)?;
    let mut writer = open_writer(&cli.output, info.format)?;
    let mut inode = 300000;

    display_format(cpio_cli, info.format);

    if cli.sort {
        cpio::sort(&mut info.entries);
    }

    let authority = ambient_authority();
    let tree = Dir::open_ambient_dir(&cli.input_tree, authority)
        .with_context(|| format!("Failed to open directory: {:?}", cli.input_tree))?;

    for entry in &mut info.entries {
        entry.inode = inode;
        inode += 1;

        let out = open_tree_file(&tree, entry)?;

        if let Some((_, file_size)) = &out {
            entry.data = CpioEntryData::Size(*file_size);
        }

        display_entry(cpio_cli, entry);

        writer
            .start_entry(entry)
            .context("Failed to write cpio entry")?;

        if let Some((mut reader, file_size)) = out {
            stream::copy_n(&mut reader, &mut writer, file_size.into(), cancel_signal)
                .context("Failed to copy data")?;
        }
    }

    flush_writer(writer)?;

    Ok(())
}

fn repack_subcommand(
    cpio_cli: &CpioCli,
    cli: &RepackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let (mut reader, format) = open_reader(&cli.input, false)?;
    let mut writer = open_writer(&cli.output, format)?;

    display_format(cpio_cli, format);

    while let Some(entry) = reader.next_entry().context("Failed to read cpio entry")? {
        display_entry(cpio_cli, &entry);

        writer
            .start_entry(&entry)
            .context("Failed to write cpio entry")?;

        if let CpioEntryData::Size(s) = &entry.data {
            stream::copy_n(&mut reader, &mut writer, u64::from(*s), cancel_signal)
                .context("Failed to copy cpio entry data")?;
        }
    }

    flush_writer(writer)?;

    Ok(())
}

fn info_subcommand(cpio_cli: &CpioCli, cli: &InfoCli) -> Result<()> {
    let (mut reader, format) = open_reader(&cli.input, cli.trailer)?;

    display_format(cpio_cli, format);

    while let Some(entry) = reader.next_entry().context("Failed to read cpio entry")? {
        display_entry(cpio_cli, &entry);
    }

    Ok(())
}

pub fn cpio_main(cli: &CpioCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        CpioCommand::Unpack(c) => unpack_subcommand(cli, c, cancel_signal),
        CpioCommand::Pack(c) => pack_subcommand(cli, c, cancel_signal),
        CpioCommand::Repack(c) => repack_subcommand(cli, c, cancel_signal),
        CpioCommand::Info(c) => info_subcommand(cli, c),
    }
}

/// Unpack a cpio archive.
///
/// Regular files will be extracted to the output tree directory, but not any
/// other type of file (eg. symlinks). All file metadata is written to the info
/// TOML file, like the UID/GID, permissions, and symlink targets.
///
/// If any paths inside the cpio archive are unsafe, the extraction process will
/// fail and exit. Extracted files are never written outside of the tree
/// directory, even if an external process tries to interfere.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output cpio info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "cpio.toml")]
    output_info: PathBuf,

    /// Path to output files directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "cpio_tree")]
    output_tree: PathBuf,
}

/// Pack a cpio archive.
///
/// The new cpio archive will *only* contain files listed in the info TOML file.
/// Extra files inside the input tree directory that aren't listed will be
/// silently ignored. Entries are added to the archive in the order that they
/// are listed unless --sort is specified.
///
/// All fields inside the info TOML are used as-is, except for the inode
/// numbers, which will be regenerated. If any fields for an entry are missing,
/// they will be set to 0.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to input info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "cpio.toml")]
    input_info: PathBuf,

    /// Path to input files directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "cpio_tree")]
    input_tree: PathBuf,

    /// Sort entries before packing.
    #[arg(long)]
    sort: bool,
}

/// Repack a cpio archive.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,
}

/// Display cpio entry information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Show cpio trailer entry.
    #[arg(long, global = true)]
    trailer: bool,
}

#[derive(Debug, Subcommand)]
enum CpioCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
}

/// Pack, unpack, and inspect cpio archives.
#[derive(Debug, Parser)]
pub struct CpioCli {
    #[command(subcommand)]
    command: CpioCommand,

    /// Don't print cpio entry information.
    #[arg(short, long, global = true)]
    quiet: bool,
}
