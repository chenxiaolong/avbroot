/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::cli::{avb, boot, completion, key, ota, ramdisk};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    Avb(avb::AvbCli),
    Boot(boot::BootCli),
    Completion(completion::CompletionCli),
    Key(key::KeyCli),
    Ota(ota::OtaCli),
    Ramdisk(ramdisk::RamdiskCli),
    /// (Deprecated: Use `avbroot ota patch` instead.)
    Patch(ota::PatchCli),
    /// (Deprecated: Use `avbroot ota extract` instead.)
    Extract(ota::ExtractCli),
    /// (Deprecated: Use `avbroot boot magisk-info` instead.)
    MagiskInfo(boot::MagiskInfoCli),
}

#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

pub fn main(cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Avb(c) => avb::avb_main(&c, cancel_signal),
        Command::Boot(c) => boot::boot_main(&c),
        Command::Completion(c) => completion::completion_main(&c),
        Command::Key(c) => key::key_main(&c),
        Command::Ota(c) => ota::ota_main(&c, cancel_signal),
        Command::Ramdisk(c) => ramdisk::ramdisk_main(&c),
        // Deprecated aliases.
        Command::Patch(c) => ota::patch_subcommand(&c, cancel_signal),
        Command::Extract(c) => ota::extract_subcommand(&c, cancel_signal),
        Command::MagiskInfo(c) => boot::magisk_info_subcommand(&c),
    }
}
