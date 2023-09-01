/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{ffi::OsString, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Args)]
pub struct DeviceGroup {
    /// Device config name.
    #[arg(short, long, value_name = "NAME")]
    pub device: Vec<String>,

    /// All device configs.
    #[arg(short, long, conflicts_with = "device")]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct DownloadGroup {
    /// Revalidate hash of existing download.
    #[arg(long)]
    pub revalidate: bool,

    /// Download the stripped OTA instead of the full OTA.
    #[arg(long)]
    pub stripped: bool,
}

#[derive(Debug, Args)]
pub struct PatchGroup {
    /// Delete patched output files on success.
    #[arg(long)]
    pub delete_on_success: bool,

    /// Suffix for patched output files.
    #[arg(long = "output-file-suffix", value_parser, default_value = ".patched")]
    pub suffix: OsString,
}

#[derive(Debug, Args)]
pub struct ConfigGroup {
    /// Path to config file.
    #[arg(
        short,
        long,
        value_name = "FILE",
        value_parser,
        default_value = "e2e.toml"
    )]
    pub config: PathBuf,

    /// Working directory for storing images.
    #[arg(
        short,
        long,
        value_name = "DIRECTORY",
        value_parser,
        default_value = "files"
    )]
    pub work_dir: PathBuf,
}

/// Convert a full OTA to stripped form.
///
/// A stripped OTA omits byte regions of the OTA that aren't needed for testing
/// avbroot's patching logic (eg. the system partition image). This reduces the
/// size of the test files by about two orders of magnitude.
#[derive(Debug, Parser)]
pub struct StripCli {
    /// Path to original OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub input: PathBuf,

    /// Path to new stripped OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Sha256Arg(pub [u8; 32]);

impl FromStr for Sha256Arg {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = [0u8; 32];
        hex::decode_to_slice(s, &mut data)?;
        Ok(Self(data))
    }
}

/// Add a new OTA image to the test config.
///
/// This will download the OTA image, strip it, patch both images, and add the
/// resulting metadata (eg. checksums) to the specified test config file.
#[derive(Debug, Parser)]
pub struct AddCli {
    /// URL to the full OTA zip.
    #[arg(short, long)]
    pub url: String,

    /// Device config name.
    #[arg(short, long, value_name = "NAME")]
    pub device: String,

    /// Expected sha256 hash of the full OTA zip.
    #[arg(short = 'H', long, value_name = "SHA256_HEX", value_parser)]
    pub hash: Option<Sha256Arg>,

    #[command(flatten)]
    pub patch: PatchGroup,

    #[command(flatten)]
    pub config: ConfigGroup,

    /// Skip verifying OTA and AVB signatures.
    ///
    /// OTAs for some devices (eg. ossi) ship with vbmeta partitions containing
    /// invalid hashes. These will normally fail during validation.
    #[arg(long)]
    pub skip_verify: bool,
}

/// Download a device image.
#[derive(Debug, Parser)]
pub struct DownloadCli {
    /// Download the Magisk APK.
    #[arg(short, long)]
    pub magisk: bool,

    #[command(flatten)]
    pub device: DeviceGroup,

    #[command(flatten)]
    pub download: DownloadGroup,

    #[command(flatten)]
    pub config: ConfigGroup,
}

/// Run tests.
#[derive(Debug, Parser)]
pub struct TestCli {
    #[command(flatten)]
    pub device: DeviceGroup,

    #[command(flatten)]
    pub download: DownloadGroup,

    #[command(flatten)]
    pub patch: PatchGroup,

    #[command(flatten)]
    pub config: ConfigGroup,
}

/// List devices in config file.
#[derive(Debug, Parser)]
pub struct ListCli {
    #[command(flatten)]
    pub config: ConfigGroup,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Strip(StripCli),
    Add(AddCli),
    Download(DownloadCli),
    Test(TestCli),
    List(ListCli),
}

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
