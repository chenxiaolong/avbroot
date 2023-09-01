/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
    str,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use rsa::RsaPublicKey;

use crate::{
    cli::{status, warning},
    format::avb::{self, Descriptor},
    stream::PSeekFile,
};

fn ensure_name_is_safe(name: &str) -> Result<()> {
    if Path::new(name).file_name() != Some(OsStr::new(name)) {
        bail!("Unsafe partition name: {name}");
    }

    Ok(())
}

/// Recursively verify an image's vbmeta header and all of the chained images.
/// `seen` is used to prevent cycles. `descriptors` will contain all of the hash
/// and hashtree descriptors that need to be verified.
pub fn verify_headers(
    directory: &Path,
    name: &str,
    expected_key: Option<&RsaPublicKey>,
    seen: &mut HashSet<String>,
    descriptors: &mut HashMap<String, Descriptor>,
) -> Result<()> {
    if !seen.insert(name.to_owned()) {
        return Ok(());
    }

    ensure_name_is_safe(name)?;

    let path = directory.join(format!("{name}.img"));
    let raw_reader =
        File::open(&path).with_context(|| anyhow!("Failed to open for reading: {path:?}"))?;
    let (header, _, _) = avb::load_image(BufReader::new(raw_reader))
        .with_context(|| anyhow!("Failed to load vbmeta structures: {path:?}"))?;

    // Verify the header's signature.
    let public_key = header
        .verify()
        .with_context(|| anyhow!("Failed to verify header signature: {path:?}"))?;

    if let Some(k) = &public_key {
        let prefix = format!("{name} has a signed vbmeta header");

        if let Some(e) = expected_key {
            if k == e {
                status!("{prefix}");
            } else {
                bail!("{prefix}, but is signed by an untrusted key");
            }
        } else {
            warning!("{prefix}, but parent does not list a trusted key");
        }
    } else {
        status!("{name} has an unsigned vbmeta header");
    }

    for descriptor in &header.descriptors {
        let Some(target_name) = descriptor.partition_name() else {
            continue;
        };

        match descriptor {
            avb::Descriptor::Hashtree(_) | avb::Descriptor::Hash(_) => {
                if let Some(prev) = descriptors.get(target_name) {
                    if prev != descriptor {
                        bail!("{name} descriptor does not match previous encounter");
                    }
                } else {
                    descriptors.insert(target_name.to_owned(), descriptor.clone());
                }
            }
            avb::Descriptor::ChainPartition(d) => {
                let target_key = avb::decode_public_key(&d.public_key).with_context(|| {
                    anyhow!("Failed to decode chained public key for: {target_name}")
                })?;

                verify_headers(directory, target_name, Some(&target_key), seen, descriptors)?;
            }
            _ => {}
        }
    }

    Ok(())
}

pub fn verify_descriptors(
    directory: &Path,
    descriptors: &HashMap<String, Descriptor>,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    descriptors
        .par_iter()
        .map(|(name, descriptor)| {
            let path = directory.join(format!("{name}.img"));
            let reader = match File::open(&path).map(PSeekFile::new) {
                Ok(f) => f,
                // Some devices, like bluejay, have vbmeta descriptors that
                // refer to partitions that exist on the device, but not in the
                // OTA.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    warning!("Partition image does not exist: {path:?}");
                    return Ok(());
                }
                Err(e) => {
                    Err(e).with_context(|| format!("Failed to open for reading: {path:?}"))?
                }
            };

            match descriptor {
                Descriptor::Hashtree(d) => {
                    status!("Verifying hashtree descriptor for: {name}");
                    d.verify(
                        || Ok(Box::new(BufReader::new(reader.clone()))),
                        cancel_signal,
                    )
                    .with_context(|| anyhow!("Failed to verify hashtree descriptor for: {name}"))?;
                }
                Descriptor::Hash(d) => {
                    status!("Verifying hash descriptor for: {name}");
                    d.verify(BufReader::new(reader), cancel_signal)
                        .with_context(|| anyhow!("Failed to verify hash descriptor for: {name}"))?;
                }
                _ => unreachable!("Non-verifiable descriptor: {descriptor:?}"),
            }

            Ok(())
        })
        .collect()
}

pub fn avb_main(cli: &AvbCli, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    match &cli.command {
        AvbCommand::Dump(c) => {
            let raw_reader = File::open(&c.input)
                .with_context(|| anyhow!("Failed to open for reading: {:?}", c.input))?;
            let reader = BufReader::new(raw_reader);
            let (header, footer, image_size) = avb::load_image(reader)
                .with_context(|| anyhow!("Failed to load vbmeta structures: {:?}", c.input))?;

            println!("Image size: {image_size}");
            println!("Header: {header:#?}");
            println!("Footer: {footer:#?}");
        }
        AvbCommand::Verify(c) => {
            let public_key = if let Some(p) = &c.public_key {
                let data = fs::read(p).with_context(|| anyhow!("Failed to read file: {p:?}"))?;
                let key = avb::decode_public_key(&data)
                    .with_context(|| anyhow!("Failed to decode public key: {p:?}"))?;

                Some(key)
            } else {
                None
            };

            let directory = c.input.parent().unwrap_or_else(|| Path::new("."));
            let name = c
                .input
                .file_stem()
                .with_context(|| anyhow!("Path is not a file: {:?}", c.input))?
                .to_str()
                .ok_or_else(|| anyhow!("Invalid UTF-8: {:?}", c.input))?;

            let mut seen = HashSet::<String>::new();
            let mut descriptors = HashMap::<String, Descriptor>::new();

            verify_headers(
                directory,
                name,
                public_key.as_ref(),
                &mut seen,
                &mut descriptors,
            )?;
            verify_descriptors(directory, &descriptors, cancel_signal)?;

            status!("Successfully verified all vbmeta signatures and hashes");
        }
    }

    Ok(())
}

/// Dump AVB header and footer information.
#[derive(Debug, Parser)]
struct DumpCli {
    /// Path to input image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

/// Verify vbmeta signatures.
#[derive(Debug, Parser)]
struct VerifyCli {
    /// Path to input image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to public key in AVB binary format.
    ///
    /// If this is not specified, the signatures can only be checked for
    /// validity, not whether they are trusted.
    #[arg(short, long, value_name = "FILE", value_parser)]
    public_key: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum AvbCommand {
    Dump(DumpCli),
    Verify(VerifyCli),
}

/// Show information about AVB-protected images.
#[derive(Debug, Parser)]
pub struct AvbCli {
    #[command(subcommand)]
    command: AvbCommand,
}
