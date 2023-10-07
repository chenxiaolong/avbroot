/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str,
    sync::atomic::AtomicBool,
};

use anyhow::{anyhow, bail, Context, Result};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    cli::{status, warning},
    crypto::{self, PassphraseSource},
    format::avb::{
        self, AlgorithmType, AppendedDescriptorMut, AppendedDescriptorRef, Descriptor, Footer,
        Header,
    },
    stream::{self, PSeekFile},
    util,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct AvbInfo {
    header: Header,
    footer: Option<Footer>,
    image_size: u64,
}

fn read_avb_image(path: &Path) -> Result<(AvbInfo, BufReader<File>)> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open AVB image for reading: {path:?}"))?;
    let mut reader = BufReader::new(file);
    let (header, footer, image_size) = avb::load_image(&mut reader)
        .with_context(|| format!("Failed to load AVB image: {path:?}"))?;

    let info = AvbInfo {
        header,
        footer,
        image_size,
    };

    Ok((info, reader))
}

fn write_avb_image(file: PSeekFile, info: &mut AvbInfo) -> Result<()> {
    let mut writer = BufWriter::new(file);

    if let Some(f) = &mut info.footer {
        avb::write_appended_image(&mut writer, &info.header, f, info.image_size)
            .context("Failed to write appended AVB image")?;
    } else {
        avb::write_root_image(&mut writer, &info.header, 4096)
            .context("Failed to write root AVB image")?;
    }

    writer.flush().context("Failed to flush writes")?;

    Ok(())
}

/// Read AVB information from TOML file.
fn read_info(path: &Path) -> Result<AvbInfo> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read AVB info TOML: {path:?}"))?;
    let info = toml_edit::de::from_str(&data)
        .with_context(|| format!("Failed to parse AVB info TOML: {path:?}"))?;

    Ok(info)
}

/// Write AVB information to TOML file.
fn write_info(path: &Path, info: &AvbInfo) -> Result<()> {
    let data = toml_edit::ser::to_string_pretty(info)
        .with_context(|| format!("Failed to serialize AVB info TOML: {path:?}"))?;
    fs::write(path, data).with_context(|| format!("Failed to write AVB info TOML: {path:?}"))?;

    Ok(())
}

/// Copy `size` bytes from `reader` into a new file `path` that's opened as
/// both readable and writable.
fn write_raw(
    path: &Path,
    reader: &mut BufReader<File>,
    size: u64,
    cancel_signal: &AtomicBool,
) -> Result<PSeekFile> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open raw image for writing: {path:?}"))?;
    let mut writer = BufWriter::new(file);

    reader
        .rewind()
        .with_context(|| format!("Failed to seek file: {path:?}"))?;
    stream::copy_n(reader, &mut writer, size, cancel_signal)
        .with_context(|| format!("Failed to copy raw image: {path:?}"))?;

    let file = writer
        .into_inner()
        .with_context(|| format!("Failed to flush writes: {path:?}"))?;

    Ok(file)
}

/// Copy a raw image into `path` and verify the descriptor. If corruption is
/// detected and FEC data is available, then a repair is attempted.
fn write_raw_and_verify(
    path: &Path,
    reader: &mut BufReader<File>,
    info: &AvbInfo,
    ignore_invalid: bool,
    cancel_signal: &AtomicBool,
) -> Result<PSeekFile> {
    let f = info.footer.as_ref().expect("Not an appended image");

    let descriptor = info.header.appended_descriptor()?;

    // The hash tree and FEC need to be present for verification. We don't
    // verify against the original file because a repair would require writes.
    let copy_size = match descriptor {
        AppendedDescriptorRef::HashTree(d) => d.image_size + d.tree_size + d.fec_size,
        AppendedDescriptorRef::Hash(d) => d.image_size,
    };

    let raw_file = write_raw(path, reader, copy_size, cancel_signal)?;

    let result = verify_and_repair(None, raw_file.reopen(), descriptor, true, cancel_signal);

    // Chop off the old hash tree and FEC data.
    raw_file.set_len(f.original_image_size)?;

    if let Err(e) = result {
        if ignore_invalid {
            warning!("{e:?}");
        } else {
            return Err(e);
        }
    }

    Ok(raw_file)
}

/// Copy a raw image into `path` and update the appended descriptor with the new
/// digests, offsets, and sizes.
fn write_raw_and_update(
    path: &Path,
    reader: &mut BufReader<File>,
    info: &mut AvbInfo,
    cancel_signal: &AtomicBool,
) -> Result<PSeekFile> {
    assert!(info.footer.is_some(), "Not an appended image");

    let image_size = reader
        .seek(SeekFrom::End(0))
        .context("Failed to get input data size")?;

    let mut raw_file = write_raw(path, reader, image_size, cancel_signal)?;

    match info.header.appended_descriptor_mut()? {
        AppendedDescriptorMut::HashTree(d) => {
            d.image_size = image_size;
            d.update(
                || Ok(Box::new(raw_file.reopen())),
                || Ok(Box::new(raw_file.reopen())),
                cancel_signal,
            )
            .context("Failed to update hash tree descriptor")?;
        }
        AppendedDescriptorMut::Hash(d) => {
            d.image_size = image_size;
            raw_file.rewind()?;
            d.update(&mut raw_file, cancel_signal)
                .context("Failed to update hash descriptor")?;
        }
    }

    Ok(raw_file)
}

/// Sign or clear header signatures based on whether the original header was
/// signed. If the original header was signed and is unchanged, then the
/// original signature is used as-is. If the force option is specified, then
/// the header is signed or cleared based on the presence of the private key
/// parameter.
fn sign_or_clear(info: &mut AvbInfo, orig_header: &Header, key_group: &KeyGroup) -> Result<()> {
    enum SignAction {
        None,
        Sign,
        Clear,
    }

    let originally_signed = !info.header.signature.is_empty();
    let mut sign_action = if originally_signed && &info.header != orig_header {
        SignAction::Sign
    } else {
        // If the original image was signed, we can preserve the existing
        // signature since no changes were made. If the original image was not
        // signed, then there's nothing to do anyway.
        SignAction::None
    };

    if key_group.force {
        sign_action = if key_group.key.is_some() {
            SignAction::Sign
        } else {
            SignAction::Clear
        };
    }

    match sign_action {
        SignAction::None => {
            if originally_signed {
                status!("Preserving original AVB header signature");
            } else {
                status!("Leaving AVB header unsigned");
            }
        }
        SignAction::Sign => {
            if originally_signed {
                status!("Replacing AVB header signature");
            } else {
                status!("Signing AVB header");
            }

            let Some(key_path) = &key_group.key else {
                bail!("Need to sign new AVB header, but no private key was specified");
            };

            let source = PassphraseSource::new(
                key_path,
                key_group.pass_file.as_deref(),
                key_group.pass_env_var.as_deref(),
            );
            let private_key = crypto::read_pem_key_file(key_path, &source)
                .with_context(|| format!("Failed to load key: {key_path:?}"))?;

            info.header.set_algo_for_key(&private_key)?;
            info.header
                .sign(&private_key)
                .context("Failed to sign new AVB header")?;
        }
        SignAction::Clear => {
            if originally_signed {
                status!("Clearing AVB header signature");
            } else {
                status!("Leaving AVB header unsigned");
            }

            info.header.algorithm_type = AlgorithmType::None;
            info.header.clear_sig();
        }
    }

    Ok(())
}

/// Dump AVB information to stdout.
fn display_info(display: &DisplayGroup, info: &AvbInfo) {
    if !display.quiet {
        println!("{info:#?}");
    }
}

/// Ensure that the partition name won't cause directory traversals.
fn ensure_name_is_safe(name: &str) -> Result<()> {
    if Path::new(name).file_name() != Some(OsStr::new(name)) {
        bail!("Unsafe partition name: {name}");
    }

    Ok(())
}

/// Recursively verify an image's vbmeta header and all of the chained images.
/// `seen` is used to prevent cycles. `descriptors` will contain all of the hash
/// and hash tree descriptors that need to be verified.
pub fn verify_headers(
    directory: &Dir,
    name: &str,
    expected_key: Option<&RsaPublicKey>,
    seen: &mut HashSet<String>,
    descriptors: &mut HashMap<String, Descriptor>,
) -> Result<()> {
    if !seen.insert(name.to_owned()) {
        return Ok(());
    }

    ensure_name_is_safe(name)?;

    let path = format!("{name}.img");
    let raw_reader = directory
        .open(&path)
        .with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let (header, _, _) = avb::load_image(BufReader::new(raw_reader))
        .with_context(|| format!("Failed to load vbmeta structures: {path:?}"))?;

    // Verify the header's signature.
    let public_key = header
        .verify()
        .with_context(|| format!("Failed to verify header signature: {path:?}"))?;

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
            avb::Descriptor::HashTree(_) | avb::Descriptor::Hash(_) => {
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
                    format!("Failed to decode chained public key for: {target_name}")
                })?;

                verify_headers(directory, target_name, Some(&target_key), seen, descriptors)?;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Verify the descriptor for a file. For hash tree descriptors, if FEC data is
/// available and `repair` is true, then attempt to repair data in the event of
/// corruption. `file` must be opened as read-write for the repair operation to
/// work.
fn verify_and_repair(
    name: Option<&str>,
    mut file: PSeekFile,
    descriptor: AppendedDescriptorRef,
    repair: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let suffix = match name {
        Some(n) => format!(" for: {n}"),
        None => String::new(),
    };

    match descriptor {
        AppendedDescriptorRef::HashTree(d) => {
            status!("Verifying hash tree descriptor{suffix}");

            match d.verify(|| Ok(Box::new(file.reopen())), cancel_signal) {
                Err(
                    e @ avb::Error::InvalidRootDigest { .. }
                    | e @ avb::Error::InvalidHashTree { .. },
                ) if repair => {
                    warning!("Failed to verify hash tree descriptor{suffix}: {e}");
                    warning!("Attempting to repair using FEC data{suffix}");

                    d.repair(
                        || Ok(Box::new(file.reopen())),
                        || Ok(Box::new(file.reopen())),
                        cancel_signal,
                    )
                    .with_context(|| format!("Failed to repair data{suffix}"))?;

                    d.verify(|| Ok(Box::new(file.reopen())), cancel_signal)
                        .map(|_| {
                            status!("Successfully repaired data{suffix}");
                        })
                }
                ret => ret,
            }
            .with_context(|| format!("Failed to verify hash tree descriptor{suffix}"))?;
        }
        AppendedDescriptorRef::Hash(d) => {
            status!("Verifying hash descriptor{suffix}");

            file.rewind()?;
            d.verify(file, cancel_signal)
                .with_context(|| format!("Failed to verify hash descriptor{suffix}"))?;
        }
    }

    Ok(())
}

/// Verify hash and hash tree descriptor digests and FEC data against their
/// corresponding input files.
pub fn verify_descriptors(
    directory: &Dir,
    descriptors: &HashMap<String, Descriptor>,
    repair: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    descriptors
        .par_iter()
        .map(|(name, descriptor)| {
            let path = format!("{name}.img");
            let file = match directory
                .open_with(&path, OpenOptions::new().read(true).write(repair))
                .map(|f| PSeekFile::new(f.into_std()))
            {
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

            verify_and_repair(
                Some(name),
                file,
                descriptor.try_into()?,
                repair,
                cancel_signal,
            )
        })
        .collect()
}

fn unpack_subcommand(cli: &UnpackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (info, mut reader) = read_avb_image(&cli.input)?;
    display_info(&cli.display, &info);

    write_info(&cli.output_info, &info)?;

    if info.footer.is_some() {
        write_raw_and_verify(
            &cli.output_raw,
            &mut reader,
            &info,
            cli.ignore_invalid,
            cancel_signal,
        )?;
    }

    Ok(())
}

fn pack_subcommand(cli: &PackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let mut info = read_info(&cli.input_info)?;
    let orig_header = info.header.clone();

    let file = if info.footer.is_some() {
        let mut reader = File::open(&cli.input_raw)
            .map(BufReader::new)
            .with_context(|| {
                format!("Failed to open raw image for reading: {:?}", cli.input_raw)
            })?;

        write_raw_and_update(&cli.output, &mut reader, &mut info, cancel_signal)?
    } else {
        File::create(&cli.output)
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to open output for writing: {:?}", cli.output))?
    };

    sign_or_clear(&mut info, &orig_header, &cli.key)?;

    write_avb_image(file, &mut info)?;

    // We display the info at the very end after both the header and footer are
    // updated so that incorrect/incomplete information isn't shown.
    display_info(&cli.display, &info);

    Ok(())
}

fn repack_subcommand(cli: &RepackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (mut info, mut reader) = read_avb_image(&cli.input)?;
    let orig_header = info.header.clone();

    let file = if info.footer.is_some() {
        let file = write_raw_and_verify(&cli.output, &mut reader, &info, false, cancel_signal)?;

        // Write new hash tree and FEC data instead of copying the original.
        // THere could have been errors in the original FEC data itself.
        if let AppendedDescriptorMut::HashTree(d) = info.header.appended_descriptor_mut()? {
            d.update(
                || Ok(Box::new(file.reopen())),
                || Ok(Box::new(file.reopen())),
                cancel_signal,
            )?;
        }

        file
    } else {
        File::create(&cli.output)
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to open for writing: {:?}", cli.output))?
    };

    sign_or_clear(&mut info, &orig_header, &cli.key)?;

    write_avb_image(file, &mut info)?;

    // We display the info at the very end after both the header and footer are
    // updated so that incorrect/incomplete information isn't shown.
    display_info(&cli.display, &info);

    Ok(())
}

fn info_subcommand(cli: &InfoCli) -> Result<()> {
    let (info, _) = read_avb_image(&cli.input)?;
    display_info(&cli.display, &info);

    Ok(())
}

fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let public_key = if let Some(p) = &cli.public_key {
        let data = fs::read(p).with_context(|| format!("Failed to read file: {p:?}"))?;
        let key = avb::decode_public_key(&data)
            .with_context(|| format!("Failed to decode public key: {p:?}"))?;

        Some(key)
    } else {
        None
    };

    let authority = ambient_authority();
    let parent_path = util::parent_path(&cli.input);
    let directory = Dir::open_ambient_dir(parent_path, authority)
        .with_context(|| format!("Failed to open directory: {parent_path:?}"))?;
    let name = cli
        .input
        .file_stem()
        .with_context(|| format!("Path is not a file: {:?}", cli.input))?
        .to_str()
        .ok_or_else(|| anyhow!("Invalid UTF-8: {:?}", cli.input))?;

    let mut seen = HashSet::<String>::new();
    let mut descriptors = HashMap::<String, Descriptor>::new();

    verify_headers(
        &directory,
        name,
        public_key.as_ref(),
        &mut seen,
        &mut descriptors,
    )?;
    verify_descriptors(&directory, &descriptors, cli.repair, cancel_signal)?;

    status!("Successfully verified all vbmeta signatures and hashes");

    Ok(())
}

pub fn avb_main(cli: &AvbCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        AvbCommand::Unpack(c) => unpack_subcommand(c, cancel_signal),
        AvbCommand::Pack(c) => pack_subcommand(c, cancel_signal),
        AvbCommand::Repack(c) => repack_subcommand(c, cancel_signal),
        AvbCommand::Info(c) => info_subcommand(c),
        AvbCommand::Verify(c) => verify_subcommand(c, cancel_signal),
    }
}

#[derive(Debug, Args)]
struct DisplayGroup {
    /// Don't print AVB image information.
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct KeyGroup {
    /// Path to private key for signing.
    ///
    /// A private key is needed if packing an image where the original header
    /// was signed and the header needs to be modified (eg. for a new checksum).
    /// If the header was originally not signed, then the private key is not
    /// used, unless --force is specified.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: Option<PathBuf>,

    /// Force signing or clearing signature.
    ///
    /// If --key is specified, then the output is signed, regardless if the
    /// original image was signed. Similarly, if --key is not specified, then
    /// the output is left unsigned, even if the image is unchanged and it's
    /// possible to preserve an existing signature.
    #[arg(short, long)]
    force: bool,

    /// Environment variable containing private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pass_env_var: Option<OsString>,

    /// File containing private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "pass")]
    pass_file: Option<PathBuf>,
}

/// Unpack an AVB image.
///
/// This command splits an AVB image into an AVB info TOML file and a raw image.
/// For root AVB images (eg. vbmeta), only the info file is created, which will
/// contain a header section. For appended AVB images (eg. boot), the raw image
/// will be written and the info file will additionally have a footer section.
///
/// For appended AVB images that contain a hash tree descriptor (eg. dm-verity
/// protected system image), FEC data, if available, will be used to repair the
/// extracted raw image in the event of data corruption.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output AVB info TOML.
    ///
    /// The file will always contain a header section, but a footer section will
    /// only be present if the input is an appended AVB image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "avb.toml")]
    output_info: PathBuf,

    /// Path to output raw image.
    ///
    /// Only appended AVB images will have a raw image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "raw.img")]
    output_raw: PathBuf,

    /// Ignore invalid digests or FEC data.
    #[arg(long)]
    ignore_invalid: bool,

    #[command(flatten)]
    display: DisplayGroup,
}

/// Pack an AVB image.
///
/// This command creates an AVB image from the AVB info toml file and the raw
/// image components. If the info file does not contain a footer, then a root
/// image is created. Otherwise, an appended image is created and a raw image
/// must be specified.
///
/// For appended images, the checksums in the header's descriptors and the
/// offsets in the footer will be updated. If the header fields are updated and
/// the header was originally signed, then the newly created image will also be
/// signed. If a signed image is repacked without modification, then the
/// original signature is used as-is.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to input AVB info TOML.
    ///
    /// If an appended image is being created, then the hash or hash tree
    /// descriptor in the header will be updated with the new digest, offset,
    /// and size field values. There must be exactly one hash or hash tree
    /// descriptor. The offset and size fields in the footer will be updated as
    /// well.
    ///
    /// For root images, all header descriptor fields are left unmodified.
    #[arg(long, value_name = "FILE", value_parser, default_value = "avb.toml")]
    input_info: PathBuf,

    /// Path to input raw image.
    ///
    /// Appended AVB images require a raw image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "raw.img")]
    input_raw: PathBuf,

    #[command(flatten)]
    key: KeyGroup,

    #[command(flatten)]
    display: DisplayGroup,
}

/// Repack an AVB image.
///
/// This command is equivalent to running `unpack` and `pack`, except without
/// storing the unpacked data to disk.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    #[command(flatten)]
    key: KeyGroup,

    #[command(flatten)]
    display: DisplayGroup,
}

/// Display AVB header and footer information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    #[command(flatten)]
    display: DisplayGroup,
}

/// Verify vbmeta signatures.
///
/// If the header contains chain descriptors, then those images will be
/// recursively verified. For hash tree descriptors, the FEC (forward error
/// correction) data will also be verified.
#[derive(Debug, Parser)]
struct VerifyCli {
    /// Path to input AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to public key in AVB binary format.
    ///
    /// If this is not specified, the signatures can only be checked for
    /// validity, not whether they are trusted.
    #[arg(short, long, value_name = "FILE", value_parser)]
    public_key: Option<PathBuf>,

    /// Repair corrupted files using FEC data if possible.
    ///
    /// Only images with hash tree descriptors can contain FEC data.
    #[arg(short, long)]
    repair: bool,
}

#[derive(Debug, Subcommand)]
enum AvbCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    #[command(alias = "dump")]
    Info(InfoCli),
    Verify(VerifyCli),
}

/// Pack, unpack, and inspect AVB-protected images.
#[derive(Debug, Parser)]
pub struct AvbCli {
    #[command(subcommand)]
    command: AvbCommand,
}
