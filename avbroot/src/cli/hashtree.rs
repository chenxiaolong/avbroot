/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{
    format::hashtree::HashTreeImage,
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

fn read_hash_tree(path: &Path) -> Result<HashTreeImage> {
    let reader = File::open(path)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let hash_tree = HashTreeImage::from_reader(reader)
        .with_context(|| format!("Failed to read hash tree data: {path:?}"))?;

    Ok(hash_tree)
}

fn write_hash_tree(path: &Path, hash_tree: &HashTreeImage) -> Result<()> {
    let mut writer = File::create(path)
        .map(BufWriter::new)
        .with_context(|| format!("Failed to open for writing: {path:?}"))?;
    hash_tree
        .to_writer(&mut writer)
        .with_context(|| format!("Failed to write hash tree data: {path:?}"))?;
    writer
        .flush()
        .with_context(|| format!("Failed to flush hash tree data: {path:?}"))?;

    Ok(())
}

fn generate_subcommand(cli: &GenerateCli, cancel_signal: &AtomicBool) -> Result<()> {
    let salt = hex::decode(&cli.salt).context("Invalid salt")?;
    let input = open_input(&cli.input, false)?;

    let hash_tree =
        HashTreeImage::generate(&input, cli.block_size, &cli.algorithm, &salt, cancel_signal)
            .context("Failed to generate hash tree data")?;

    write_hash_tree(&cli.hash_tree, &hash_tree)?;

    Ok(())
}

fn update_subcommand(cli: &UpdateCli, cancel_signal: &AtomicBool) -> Result<()> {
    let ranges = cli
        .range
        .chunks_exact(2)
        .map(|w| w[0]..w[1])
        .collect::<Vec<_>>();

    let input = open_input(&cli.input, false)?;
    let mut hash_tree = read_hash_tree(&cli.hash_tree)?;

    hash_tree
        .update(&input, &ranges, cancel_signal)
        .context("Failed to update hash tree data")?;

    write_hash_tree(&cli.hash_tree, &hash_tree)?;

    Ok(())
}

fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let input = open_input(&cli.input, false)?;
    let hash_tree = read_hash_tree(&cli.hash_tree)?;

    hash_tree
        .verify(&input, cancel_signal)
        .context("Failed to verify data")?;

    Ok(())
}

pub fn hash_tree_main(cli: &HashTreeCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        HashTreeCommand::Generate(c) => generate_subcommand(c, cancel_signal),
        HashTreeCommand::Update(c) => update_subcommand(c, cancel_signal),
        HashTreeCommand::Verify(c) => verify_subcommand(c, cancel_signal),
    }
}

/// Generate hash tree data for a file.
#[derive(Debug, Parser)]
struct GenerateCli {
    /// Path to input data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output hash tree data.
    #[arg(short = 'H', long, value_name = "FILE", value_parser)]
    hash_tree: PathBuf,

    /// Block size.
    #[arg(short, long, value_name = "BYTES", default_value = "4096")]
    block_size: u32,

    /// Hash algorithm.
    #[arg(short, long, value_name = "NAME", default_value = "sha256")]
    algorithm: String,

    /// Salt (in hex).
    #[arg(short, long, value_name = "HEX", default_value = "")]
    salt: String,
}

/// Update hash tree data after a file is modified.
#[derive(Debug, Parser)]
struct UpdateCli {
    /// Path to input data.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to hash tree data.
    ///
    /// The file will be modified in place.
    #[arg(short = 'H', long, value_name = "FILE", value_parser)]
    hash_tree: PathBuf,

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

    /// Path to input hash tree data.
    #[arg(short = 'H', long, value_name = "FILE", value_parser)]
    hash_tree: PathBuf,
}

#[derive(Debug, Subcommand)]
enum HashTreeCommand {
    Generate(GenerateCli),
    Update(UpdateCli),
    Verify(VerifyCli),
}

/// Generate dm-verity hash tree data and verify files.
///
/// These commands operate on a standard hash tree data prepended by a custom
/// header.
#[derive(Debug, Parser)]
pub struct HashTreeCli {
    #[command(subcommand)]
    command: HashTreeCommand,
}
