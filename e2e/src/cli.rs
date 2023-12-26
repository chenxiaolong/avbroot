/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
}
