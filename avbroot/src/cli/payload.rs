/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{fs::File, io::BufReader, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{format::payload::PayloadHeader, stream::FromReader};

fn info_subcommand(cli: &InfoCli) -> Result<()> {
    let mut reader = File::open(&cli.input)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open payload: {:?}", cli.input))?;
    let header = PayloadHeader::from_reader(&mut reader)
        .with_context(|| format!("Failed to read payload: {:?}", cli.input))?;

    println!("{header:#?}");

    Ok(())
}

pub fn payload_main(cli: &PayloadCli) -> Result<()> {
    match &cli.command {
        PayloadCommand::Info(c) => info_subcommand(c),
    }
}

/// Display payload information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input payload file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum PayloadCommand {
    Info(InfoCli),
}

/// Inspect OTA payloads.
#[derive(Debug, Parser)]
pub struct PayloadCli {
    #[command(subcommand)]
    command: PayloadCommand,
}
