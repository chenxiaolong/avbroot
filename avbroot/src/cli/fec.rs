// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{
    format::fec::FecImage,
    stream::{FromReader, PSeekFile, ToWriter},
};

fn open_input(path: &Path, rw: bool) -> Result<PSeekFile> {
    OpenOptions::new()
        .read(true)
        .write(rw)
        .open(path)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open file: {path:?}"))
}

fn read_fec(path: &Path) -> Result<FecImage> {
    let reader = File::open(path)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let fec = FecImage::from_reader(reader)
        .with_context(|| format!("Failed to read FEC data: {path:?}"))?;

    Ok(fec)
}

fn write_fec(path: &Path, fec: &FecImage) -> Result<()> {
    let mut writer = File::create(path)
        .map(BufWriter::new)
        .with_context(|| format!("Failed to open for writing: {path:?}"))?;
    fec.to_writer(&mut writer)
        .with_context(|| format!("Failed to write FEC data: {path:?}"))?;
    writer
        .flush()
        .with_context(|| format!("Failed to flush FEC data: {path:?}"))?;

    Ok(())
}

fn generate_subcommand(cli: &GenerateCli, cancel_signal: &AtomicBool) -> Result<()> {
    let input = open_input(&cli.input, false)?;

    let fec = FecImage::generate(&input, cli.parity, cancel_signal)
        .context("Failed to generate FEC data")?;

    write_fec(&cli.fec, &fec)?;

    Ok(())
}

fn update_subcommand(cli: &UpdateCli, cancel_signal: &AtomicBool) -> Result<()> {
    let ranges = cli
        .range
        .chunks_exact(2)
        .map(|w| w[0]..w[1])
        .collect::<Vec<_>>();

    let input = open_input(&cli.input, false)?;
    let mut fec = read_fec(&cli.fec)?;

    fec.update(&input, &ranges, cancel_signal)
        .context("Failed to update FEC data")?;

    write_fec(&cli.fec, &fec)?;

    Ok(())
}

fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let input = open_input(&cli.input, false)?;
    let fec = read_fec(&cli.fec)?;

    fec.verify(&input, cancel_signal)
        .context("Failed to verify data")?;

    Ok(())
}

fn repair_subcommand(cli: &RepairCli, cancel_signal: &AtomicBool) -> Result<()> {
    let input = open_input(&cli.input, true)?;
    let fec = read_fec(&cli.fec)?;

    // The separate buffered readers and writers are safe because the function
    // guarantees that every thread touches disjoint offsets and every offset is
    // read and written at most once.
    fec.repair(&input, &input, cancel_signal)
        .context("Failed to repair file")?;

    Ok(())
}

pub fn fec_main(cli: &FecCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        FecCommand::Generate(c) => generate_subcommand(c, cancel_signal),
        FecCommand::Update(c) => update_subcommand(c, cancel_signal),
        FecCommand::Verify(c) => verify_subcommand(c, cancel_signal),
        FecCommand::Repair(c) => repair_subcommand(c, cancel_signal),
    }
}

/// Generate FEC data for a file.
#[derive(Debug, Parser)]
struct GenerateCli {
    /// Path to input data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output FEC data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    fec: PathBuf,

    /// Number of parity bytes per RS block (min 2, max 24).
    #[arg(short, long, value_name = "BYTES", default_value = "2")]
    parity: u8,
}

/// Update FEC data after a file is modified.
#[derive(Debug, Parser)]
struct UpdateCli {
    /// Path to input data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to FEC data.
    ///
    /// The file will be modified in place.
    #[arg(short, long, value_name = "FILE", value_parser)]
    fec: PathBuf,

    /// Input file ranges that were updated.
    ///
    /// This is a half-open range and can be specified multiple times.
    #[arg(short, long, value_names = ["START", "END"], num_args = 2)]
    range: Vec<u64>,
}

/// Verify that a file contains no errors.
#[derive(Debug, Parser)]
struct VerifyCli {
    /// Path to input data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to input FEC data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    fec: PathBuf,
}

/// Repair a file.
#[derive(Debug, Parser)]
struct RepairCli {
    /// Path to data.
    ///
    /// The file will be modified in place.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to input FEC data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    fec: PathBuf,
}

#[derive(Debug, Subcommand)]
enum FecCommand {
    Generate(GenerateCli),
    Update(UpdateCli),
    Verify(VerifyCli),
    Repair(RepairCli),
}

/// Generate dm-verity FEC data and verify/repair files.
///
/// These commands operate on FEC files with AOSP's header format.
#[derive(Debug, Parser)]
pub struct FecCli {
    #[command(subcommand)]
    command: FecCommand,
}
