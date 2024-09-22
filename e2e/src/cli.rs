// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{ffi::OsString, path::PathBuf};

use avbroot::cli::args::LogFormat;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::Level;

#[derive(Debug, Args)]
pub struct ProfileGroup {
    /// OTA profile name.
    #[arg(short, long, value_name = "NAME")]
    pub profile: Vec<String>,

    /// All profiles.
    #[arg(short, long, conflicts_with = "profile")]
    pub all: bool,
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

    /// Working directory.
    ///
    /// If unset, a temporary directory is used, which will be automatically
    /// cleaned up, even if a failure occurs. Custom working directories are
    /// not deleted.
    #[arg(short, long, value_name = "DIRECTORY", value_parser)]
    pub work_dir: Option<PathBuf>,
}

/// Run tests.
#[derive(Debug, Parser)]
pub struct TestCli {
    #[command(flatten)]
    pub profile: ProfileGroup,

    #[command(flatten)]
    pub config: ConfigGroup,
}

/// List profiles in config file.
#[derive(Debug, Parser)]
pub struct ListCli {
    #[command(flatten)]
    pub config: ConfigGroup,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Test(TestCli),
    List(ListCli),
}

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Lowest log message severity to output.
    #[arg(long, global = true, value_name = "LEVEL", default_value_t = Level::INFO)]
    pub log_level: Level,

    /// Output format for log messages.
    #[arg(long, global = true, value_name = "FORMAT", default_value_t = LogFormat::Medium)]
    pub log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PassSource {
    Env,
    File,
}

#[derive(Debug, Parser)]
pub struct HelperCli {
    /// Signature algorithm.
    pub algorithm: String,

    /// Public key.
    #[arg(value_name = "FILE", value_parser)]
    pub public_key: PathBuf,

    /// Non-interactive password source.
    #[arg(value_name = "SOURCE")]
    pub pass_source: PassSource,

    /// Non-interactive password source value.
    #[arg(value_name = "VALUE", value_parser)]
    pub pass_source_value: OsString,
}
