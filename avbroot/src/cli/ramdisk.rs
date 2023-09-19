/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::File,
    path::{Path, PathBuf},
    str,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::format::{
    compression::{CompressedFormat, CompressedReader, CompressedWriter},
    cpio::{self, CpioEntryNew},
};

static CONTENT_BEGIN: &str = "----- BEGIN UTF-8 CONTENT -----";
static CONTENT_END: &str = "----- END UTF-8 CONTENT -----";
static CONTENT_END_NO_NEWLINE: &str = "----- END UTF-8 CONTENT (NO NEWLINE) -----";

static BINARY_BEGIN: &str = "----- BEGIN BINARY CONTENT -----";
static BINARY_END: &str = "----- END BINARY CONTENT -----";
static BINARY_END_TRUNCATED: &str = "----- END BINARY CONTENT (TRUNCATED) -----";

static NO_DATA: &str = "----- NO DATA -----";

fn print_content(data: &[u8], truncate: bool) {
    if data.is_empty() {
        println!("{NO_DATA}");
        return;
    }

    if !data.contains(&b'\0') {
        if let Ok(s) = str::from_utf8(data) {
            if !s.contains(CONTENT_BEGIN)
                && !s.contains(CONTENT_END)
                && !s.contains(CONTENT_END_NO_NEWLINE)
            {
                println!("{CONTENT_BEGIN}");
                print!("{s}");
                if data.last() == Some(&b'\n') {
                    println!("{CONTENT_END}");
                } else {
                    println!();
                    println!("{CONTENT_END_NO_NEWLINE}");
                }

                return;
            }
        }
    }

    println!("{BINARY_BEGIN}");

    if data.len() > 512 && truncate {
        println!("{}", data[..512].escape_ascii());
        println!("{BINARY_END_TRUNCATED}");
    } else {
        println!("{}", data.escape_ascii());
        println!("{BINARY_END}");
    }
}

fn load_archive(
    path: &Path,
    include_trailer: bool,
) -> Result<(Vec<CpioEntryNew>, CompressedFormat)> {
    let file = File::open(path)?;
    let reader = CompressedReader::new(file, true)?;
    let format = reader.format();
    let entries = cpio::load(reader, include_trailer)?;

    Ok((entries, format))
}

fn save_archive(path: &Path, entries: &[CpioEntryNew], format: CompressedFormat) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = CompressedWriter::new(file, format)?;
    cpio::save(&mut writer, entries, false)?;
    writer.finish()?;

    Ok(())
}

pub fn ramdisk_main(cli: &RamdiskCli) -> Result<()> {
    match &cli.command {
        RamdiskCommand::Dump(c) => {
            let (entries, format) = load_archive(&c.input, true)
                .with_context(|| format!("Failed to read cpio: {:?}", c.input))?;

            println!("Compression format: {format:?}");
            println!();

            for entry in entries {
                println!("{entry}");
                print_content(&entry.content, !c.no_truncate);
                println!();
            }
        }
        RamdiskCommand::Repack(c) => {
            let (entries, format) = load_archive(&c.input, false)
                .with_context(|| format!("Failed to read cpio: {:?}", c.input))?;

            save_archive(&c.output, &entries, format)
                .with_context(|| format!("Failed to write cpio: {:?}", c.output))?;
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
