// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

mod changelog;
mod fuzz_corpus;
mod version;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::version::SetVersionCli;

const WORKSPACE_DIR: &str = env!("CARGO_WORKSPACE_DIR");

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::SetVersion(c) => version::set_version_subcommand(&c),
        Command::FuzzCorpus => fuzz_corpus::fuzz_corpus_subcommand(),
        Command::UpdateChangelog => changelog::update_changelog_subcommand(),
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    SetVersion(SetVersionCli),
    /// Generate initial fuzzing corpus.
    FuzzCorpus,
    /// Update links in CHANGELOG.md.
    UpdateChangelog,
}

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
