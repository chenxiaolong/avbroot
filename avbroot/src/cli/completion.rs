// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use winnow_args::{Args, complete::Shell};

use crate::cli::args::Cli;

pub fn completion_main(cli: &CompletionCli) -> Result<()> {
    print!("{}", Cli::completion_script(cli.shell));

    Ok(())
}

/// Generate shell tab completion configs.
#[derive(Debug, Args)]
pub struct CompletionCli {
    /// The shell to generate completions for.
    #[arg(short, long, value_name = "SHELL")]
    pub shell: Shell,
}
