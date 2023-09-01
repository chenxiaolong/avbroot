/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::Shell;

use crate::cli::args::Cli;

pub fn completion_main(cli: &CompletionCli) -> Result<()> {
    clap_complete::generate(
        cli.shell,
        &mut Cli::command(),
        env!("CARGO_PKG_NAME"),
        &mut io::stdout(),
    );

    Ok(())
}

/// Generate shell tab completion configs.
#[derive(Debug, Parser)]
pub struct CompletionCli {
    /// The shell to generate completions for.
    #[arg(short, long, value_name = "SHELL", value_parser)]
    pub shell: Shell,
}
