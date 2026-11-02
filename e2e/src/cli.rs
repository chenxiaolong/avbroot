// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{ffi::OsString, path::PathBuf};

use avbroot::cli::args::LogFormat;
use tracing::Level;
use winnow_args::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
pub struct ProfileGroup {
    /// OTA profile name.
    #[arg(short, long, value_name = "NAME")]
    pub profile: Vec<String>,

    /// All profiles.
    #[arg(short, long, conflicts("--profile"))]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct ConfigGroup {
    /// Path to config file.
    #[arg(short, long, value_name = "FILE", default = "e2e.toml")]
    pub config: PathBuf,

    /// Working directory.
    ///
    /// If unset, a temporary directory is used, which will be automatically
    /// cleaned up, even if a failure occurs. Custom working directories are
    /// not deleted.
    #[arg(short, long, value_name = "DIRECTORY")]
    pub work_dir: Option<PathBuf>,
}

/// Run tests.
#[derive(Debug, Args)]
pub struct TestCli {
    #[arg(flatten)]
    pub profile: ProfileGroup,

    #[arg(flatten)]
    pub config: ConfigGroup,
}

/// List profiles in config file.
#[derive(Debug, Args)]
pub struct ListCli {
    #[arg(flatten)]
    pub config: ConfigGroup,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Test(TestCli),
    List(ListCli),
}

fn default_level() -> Level {
    Level::INFO
}

fn default_format() -> LogFormat {
    LogFormat::Medium
}

#[derive(Debug, Args)]
pub struct Cli {
    #[arg(subcommand)]
    pub command: Command,

    /// Lowest log message severity to output.
    #[arg(long, global, value_name = "LEVEL", from_str, default_fn = default_level)]
    pub log_level: Level,

    /// Output format for log messages.
    #[arg(long, global, value_name = "FORMAT", default_fn = default_format)]
    pub log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PassSource {
    Env,
    File,
}

#[derive(Debug, Args)]
pub struct HelperCli {
    /// Signature algorithm.
    #[arg(positional)]
    pub algorithm: String,

    /// Public key.
    #[arg(positional, value_name = "FILE")]
    pub public_key: PathBuf,

    /// Non-interactive password source.
    #[arg(positional, value_name = "SOURCE")]
    pub pass_source: PassSource,

    /// Non-interactive password source value.
    #[arg(positional, value_name = "VALUE")]
    pub pass_source_value: OsString,
}
