/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    str,
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{
    format::{
        compression::{CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{CpioEntryData, CpioReader, CpioWriter},
    },
    stream,
};

fn open_reader(
    path: &Path,
    include_trailer: bool,
) -> Result<(
    CpioReader<CompressedReader<BufReader<File>>>,
    CompressedFormat,
)> {
    let file = File::open(path)?;
    let reader = CompressedReader::new(BufReader::new(file), true)?;
    let format = reader.format();
    let cpio_reader = CpioReader::new(reader, include_trailer);

    Ok((cpio_reader, format))
}

fn open_writer(
    path: &Path,
    format: CompressedFormat,
) -> Result<CpioWriter<CompressedWriter<BufWriter<File>>>> {
    let file = File::create(path)?;
    let writer = CompressedWriter::new(BufWriter::new(file), format)?;
    let cpio_writer = CpioWriter::new(writer, false);

    Ok(cpio_writer)
}

fn flush_writer(writer: CpioWriter<CompressedWriter<BufWriter<File>>>) -> Result<()> {
    let compressed_writer = writer.finish()?;
    let buf_writer = compressed_writer.finish()?;
    buf_writer.into_inner()?;

    Ok(())
}

pub fn ramdisk_main(cli: &RamdiskCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        RamdiskCommand::Dump(c) => {
            let (mut reader, format) = open_reader(&c.input, true)
                .with_context(|| format!("Failed to read cpio: {:?}", c.input))?;

            println!("Compression format: {format:?}");

            while let Some(entry) = reader.next_entry().context("Failed to read cpio entry")? {
                println!();
                println!("{entry}");
            }
        }
        RamdiskCommand::Repack(c) => {
            let (mut reader, format) = open_reader(&c.input, false)
                .with_context(|| format!("Failed to open cpio for reading: {:?}", c.input))?;
            let mut writer = open_writer(&c.output, format)
                .with_context(|| format!("Failed to open cpio for writing: {:?}", c.output))?;

            while let Some(entry) = reader.next_entry().context("Failed to read cpio entry")? {
                writer
                    .start_entry(&entry)
                    .context("Failed to write cpio entry")?;

                if let CpioEntryData::Size(s) = &entry.data {
                    stream::copy_n(&mut reader, &mut writer, u64::from(*s), cancel_signal)
                        .context("Failed to copy cpio entry data")?;
                }
            }

            flush_writer(writer).context("Failed to flush cpio writer")?;
        }
    }

    Ok(())
}

/// Dump cpio headers and data.
#[derive(Debug, Parser)]
struct DumpCli {
    /// Path to input cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Do not truncate binary file contents.
    #[arg(long)]
    no_truncate: bool,
}

/// Repack cpio archive.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output cpio file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
enum RamdiskCommand {
    Dump(DumpCli),
    Repack(RepackCli),
}

/// Show information about ramdisk cpio archives.
#[derive(Debug, Parser)]
pub struct RamdiskCli {
    #[command(subcommand)]
    command: RamdiskCommand,
}
