// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Cursor, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{Span, debug_span, info, warn};

use crate::{
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::avb::{
        self, AlgorithmType, AppendedDescriptorMut, AppendedDescriptorRef, Descriptor, Footer,
        HashTreeDescriptor, Header, KernelCmdlineDescriptor,
    },
    stream::{self, ReadFixedSizeExt, ToWriter, UserPosFile, check_cancel},
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

fn write_avb_image(file: &File, info: &mut AvbInfo, recompute_size: bool) -> Result<()> {
    let mut writer = BufWriter::new(file);

    info.image_size = if let Some(f) = &mut info.footer {
        let image_size = if recompute_size {
            None
        } else {
            Some(info.image_size)
        };

        avb::write_appended_image(&mut writer, &info.header, f, image_size)
            .context("Failed to write appended AVB image")?
    } else {
        avb::write_root_image(&mut writer, &info.header, 4096)
            .context("Failed to write root AVB image")?
    };

    writer.flush().context("Failed to flush writes")?;

    Ok(())
}

/// Read AVB information from TOML file.
fn read_info(path: &Path) -> Result<AvbInfo> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read AVB info TOML: {path:?}"))?;
    let info = toml::de::from_str(&data)
        .with_context(|| format!("Failed to parse AVB info TOML: {path:?}"))?;

    Ok(info)
}

/// Write AVB information to TOML file.
fn write_info(path: &Path, info: &AvbInfo) -> Result<()> {
    let data = toml::ser::to_string_pretty(info)
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
) -> Result<File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
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
) -> Result<File> {
    let f = info.footer.as_ref().expect("Not an appended image");

    let descriptor = info.header.appended_descriptor()?;

    // The hash tree and FEC need to be present for verification. We don't
    // verify against the original file because a repair would require writes.
    let copy_size = match descriptor {
        AppendedDescriptorRef::HashTree(d) => d.image_size + d.tree_size + d.fec_size,
        AppendedDescriptorRef::Hash(d) => d.image_size,
    };

    let raw_file = write_raw(path, reader, copy_size, cancel_signal)?;

    let result = verify_and_repair(None, &raw_file, descriptor, true, cancel_signal);

    // Chop off the old hash tree and FEC data.
    raw_file.set_len(f.original_image_size)?;

    if let Err(e) = result {
        if ignore_invalid {
            warn!("{e:?}");
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
) -> Result<File> {
    assert!(info.footer.is_some(), "Not an appended image");

    let image_size = reader
        .seek(SeekFrom::End(0))
        .context("Failed to get input data size")?;

    let mut raw_file = write_raw(path, reader, image_size, cancel_signal)?;

    match info.header.appended_descriptor_mut()? {
        AppendedDescriptorMut::HashTree(d) => {
            d.image_size = image_size;
            d.update(&raw_file, None, cancel_signal)
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

/// Compute the kernel command line arguments to allow the kernel to set up the
/// dm-verity block device without dm-init or userspace helpers. This is handled
/// by init/do_mounts_dm.c in older Pixel devices (and ChromiumOS).
fn compute_dm_verity_cmdline(descriptor: &HashTreeDescriptor) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    // Number of device mapper devices.
    result.push_str("dm=\"1");
    // Block device name.
    result.push_str(" vroot");
    // Block device UUID.
    result.push_str(" none");
    // Block device write mode.
    result.push_str(" ro");
    // Number of device mapper targets.
    result.push_str(" 1,");
    // Starting sector.
    result.push('0');
    // Sector count.
    write!(&mut result, " {}", descriptor.image_size / 512).unwrap();
    // dm-verity version.
    write!(&mut result, " verity {}", descriptor.dm_verity_version).unwrap();
    // Data block device (replaced by bootloader at runtime).
    result.push_str(" PARTUUID=$(ANDROID_SYSTEM_PARTUUID)");
    // Hash block device (replaced by bootloader at runtime).
    result.push_str(" PARTUUID=$(ANDROID_SYSTEM_PARTUUID)");
    // Data block size.
    write!(&mut result, " {}", descriptor.data_block_size).unwrap();
    // Hash block size.
    write!(&mut result, " {}", descriptor.hash_block_size).unwrap();
    // Number of data blocks.
    write!(
        &mut result,
        " {}",
        descriptor.image_size / u64::from(descriptor.data_block_size),
    )
    .unwrap();
    // Hash starting block (in units of the hash block size).
    write!(
        &mut result,
        " {}",
        descriptor.image_size / u64::from(descriptor.hash_block_size),
    )
    .unwrap();
    // Hash algorithm.
    write!(&mut result, " {}", descriptor.hash_algorithm).unwrap();
    // Root digest.
    write!(&mut result, " {}", &hex::encode(&descriptor.root_digest)).unwrap();
    // Salt.
    write!(&mut result, " {}", &hex::encode(&descriptor.salt)).unwrap();

    // Number of optional arguments.
    let num_optional_args = if descriptor.fec_num_roots != 0 { 10 } else { 2 }
        + u8::from(descriptor.flags & HashTreeDescriptor::FLAG_CHECK_AT_MOST_ONCE != 0);
    write!(&mut result, " {num_optional_args}").unwrap();

    if descriptor.flags & HashTreeDescriptor::FLAG_CHECK_AT_MOST_ONCE != 0 {
        // [n + 1] Only check blocks once instead of on each access.
        result.push_str(" check_at_most_once");
    }

    // [0] Corruption handling mode (replaced by bootloader at runtime).
    result.push_str(" $(ANDROID_VERITY_MODE)");
    // [1] Force return zeros and skip validation for blocks expected to contain
    // only zeros.
    result.push_str(" ignore_zero_blocks");

    if descriptor.fec_num_roots != 0 {
        // [2-3] Enable FEC (replaced by bootloader at runtime).
        result.push_str(" use_fec_from_device PARTUUID=$(ANDROID_SYSTEM_PARTUUID)");
        // [4-5] Number of parity bytes per FEC codeword.
        write!(&mut result, " fec_roots {}", descriptor.fec_num_roots).unwrap();

        let fec_block_offset = descriptor.fec_offset / u64::from(descriptor.data_block_size);

        // [6-7] Number of data blocks covered by FEC.
        write!(&mut result, " fec_blocks {fec_block_offset}").unwrap();
        // [8-9] Starting block (in data block size units) of FEC.
        write!(&mut result, " fec_start {fec_block_offset}").unwrap();
    }

    // Root filesystem block device.
    result.push_str("\" root=/dev/dm-0");

    result
}

/// Update the dm-verity kernel command line descriptor to match the hash tree
/// descriptor. This is a no-op if there's no matching existing kernel command
/// line descriptor to update. Returns whether the descriptor was updated.
fn update_dm_verity_cmdline(info: &mut AvbInfo) -> Result<bool> {
    assert!(info.footer.is_some(), "Not an appended image");

    let new_cmdline = match info.header.appended_descriptor()? {
        AppendedDescriptorRef::HashTree(d) => compute_dm_verity_cmdline(d),
        AppendedDescriptorRef::Hash(_) => return Ok(false),
    };

    for d in &mut info.header.descriptors {
        if let Descriptor::KernelCmdline(d) = d
            && d.flags & KernelCmdlineDescriptor::FLAG_USE_ONLY_IF_HASHTREE_NOT_DISABLED != 0
            && d.cmdline.starts_with("dm=")
            && d.cmdline != new_cmdline
        {
            d.cmdline = new_cmdline;
            return Ok(true);
        }
    }

    Ok(false)
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
    let sign_action = if key_group.force {
        if key_group.key.is_some() {
            SignAction::Sign
        } else {
            SignAction::Clear
        }
    } else if originally_signed && (&info.header != orig_header || info.header.verify().is_err()) {
        SignAction::Sign
    } else {
        // If the original image was signed, we can preserve the existing
        // signature since no changes were made. If the original image was not
        // signed, then there's nothing to do anyway.
        SignAction::None
    };

    match sign_action {
        SignAction::None => {
            if originally_signed {
                info!("Preserving original AVB header signature");
            } else {
                info!("Leaving AVB header unsigned");
            }
        }
        SignAction::Sign => {
            if originally_signed {
                info!("Replacing AVB header signature");
            } else {
                info!("Signing AVB header");
            }

            let Some(key_path) = &key_group.key else {
                bail!("Need to sign new AVB header, but no private key was specified");
            };

            let source = PassphraseSource::new(
                key_path,
                key_group.pass_file.as_deref(),
                key_group.pass_env_var.as_deref(),
            );
            let signing_key = if let Some(helper) = &key_group.signing_helper {
                let public_key = crypto::read_pem_public_key_file(key_path)
                    .with_context(|| format!("Failed to load key: {key_path:?}"))?;

                RsaSigningKey::External {
                    program: helper.clone(),
                    public_key_file: key_path.clone(),
                    public_key,
                    passphrase_source: source,
                }
            } else {
                let private_key = crypto::read_pem_key_file(key_path, &source)
                    .with_context(|| format!("Failed to load key: {key_path:?}"))?;

                RsaSigningKey::Internal(private_key)
            };

            info.header
                .set_algo_for_key(&signing_key)
                .context("Failed to set signature algorithm")?;
            info.header
                .sign(&signing_key)
                .context("Failed to sign new AVB header")?;
        }
        SignAction::Clear => {
            if originally_signed {
                info!("Clearing AVB header signature");
            } else {
                info!("Leaving AVB header unsigned");
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

#[derive(Debug, Clone)]
struct SearchPath {
    dir: PathBuf,
    suffix: String,
}

impl fmt::Display for SearchPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (suffix: {:?})", self.dir, self.suffix)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ImageOpener {
    search: Vec<SearchPath>,
}

impl ImageOpener {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        let mut result = Self::new();
        result.add_dir(dir, ".img");
        result
    }

    pub fn add_dir(&mut self, dir: impl Into<PathBuf>, suffix: impl Into<String>) {
        self.search.push(SearchPath {
            dir: dir.into(),
            suffix: suffix.into(),
        });
    }

    fn open(&self, name: &str, options: &OpenOptions) -> io::Result<(PathBuf, File)> {
        for search in &self.search {
            let path = util::path_join_single(&search.dir, format!("{name}{}", search.suffix))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            match options.open(&path) {
                Ok(f) => return Ok((path, f)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("Failed to open for reading: {path:?}: {e}"),
                    ));
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Failed to find {name:?} image in: {}",
                util::join(&self.search, ", "),
            ),
        ))
    }
}

#[derive(Debug, Clone)]
pub enum TrustMethod {
    Key(RsaPublicKey),
    KeyDigest([u8; 32]),
    Anything,
}

/// Recursively verify an image's vbmeta header and all of the chained images.
/// `seen` is used to prevent cycles. `descriptors` will contain all of the hash
/// and hash tree descriptors that need to be verified.
pub fn verify_headers(
    opener: &ImageOpener,
    name: &str,
    trust_method: &TrustMethod,
    seen: &mut HashSet<String>,
    descriptors: &mut HashMap<String, Descriptor>,
) -> Result<()> {
    if !seen.insert(name.to_owned()) {
        return Ok(());
    }

    let (path, raw_reader) = opener.open(name, OpenOptions::new().read(true))?;
    let (header, _, _) = avb::load_image(BufReader::new(raw_reader))
        .with_context(|| format!("Failed to load vbmeta structures: {path:?}"))?;

    // Verify the header's signature.
    let public_key = header
        .verify()
        .with_context(|| format!("Failed to verify header signature: {path:?}"))?;

    if let Some(k) = &public_key {
        let prefix = format!("{name} has a signed vbmeta header");

        match trust_method {
            TrustMethod::Key(expected) => {
                if k == expected {
                    info!("{prefix}");
                } else {
                    bail!("{prefix}, but is signed by an untrusted key");
                }
            }
            TrustMethod::KeyDigest(expected_sha256) => {
                let encoded = avb::encode_public_key(k)?;
                let digest = Sha256::digest(&encoded);

                if digest.as_slice() == expected_sha256 {
                    info!("{prefix}");
                } else {
                    bail!("{prefix}, but is signed by an untrusted key");
                }
            }
            TrustMethod::Anything => {
                warn!("{prefix}, but parent does not list a trusted key");
            }
        }
    } else {
        info!("{name} has an unsigned vbmeta header");
    }

    if header.flags != 0 {
        warn!("{name} has insecure flags: {:#x}", header.flags);
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
                let target_trust = TrustMethod::Key(target_key);

                verify_headers(opener, target_name, &target_trust, seen, descriptors)?;
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
    file: &File,
    descriptor: AppendedDescriptorRef,
    repair: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let _span = debug_span!("image", name = name.unwrap_or_default()).entered();
    let suffix = name.map_or_else(String::new, |n| format!(" for: {n}"));

    match descriptor {
        AppendedDescriptorRef::HashTree(d) => {
            info!("Verifying hash tree descriptor{suffix}");

            match d.verify(&file, cancel_signal) {
                Err(e @ avb::Error::HashTreeVerify(_)) if repair => {
                    warn!("Failed to verify hash tree descriptor{suffix}: {e}");
                    warn!("Attempting to repair using FEC data{suffix}");

                    d.repair(&file, cancel_signal)
                        .with_context(|| format!("Failed to repair data{suffix}"))?;

                    d.verify(&file, cancel_signal).inspect(|()| {
                        info!("Successfully repaired data{suffix}");
                    })
                }
                ret => ret,
            }
            .with_context(|| format!("Failed to verify hash tree descriptor{suffix}"))?;
        }
        AppendedDescriptorRef::Hash(d) => {
            info!("Verifying hash descriptor{suffix}");

            d.verify(UserPosFile::new(file), cancel_signal)
                .with_context(|| format!("Failed to verify hash descriptor{suffix}"))?;
        }
    }

    Ok(())
}

/// Verify hash and hash tree descriptor digests and FEC data against their
/// corresponding input files.
pub fn verify_descriptors(
    opener: &ImageOpener,
    descriptors: &HashMap<String, Descriptor>,
    repair: bool,
    allow_missing: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let parent_span = Span::current();

    let mut options = OpenOptions::new();
    options.read(true);
    options.write(repair);

    descriptors.par_iter().try_for_each(|(name, descriptor)| {
        let _span = parent_span.enter();

        let file = match opener.open(name, &options) {
            Ok((_, f)) => f,
            // Some devices, like bluejay, have vbmeta descriptors that refer to
            // partitions that exist on the device, but not in the OTA.
            Err(e) if e.kind() == io::ErrorKind::NotFound && allow_missing => {
                warn!("{e}");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        verify_and_repair(
            Some(name),
            &file,
            descriptor.try_into()?,
            repair,
            cancel_signal,
        )
    })
}

fn compute_digest_recursive(
    directory: &Path,
    name: &str,
    context: &mut ring::digest::Context,
    max_depth: u8,
    seen: &mut HashSet<String>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    if max_depth == 0 {
        return Ok(());
    }

    check_cancel(cancel_signal)?;

    seen.insert(name.to_owned());

    let path = util::path_join_single(directory, format!("{name}.img"))?;
    let mut raw_reader = File::open(&path)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let (header, footer, _) = avb::load_image(&mut raw_reader)
        .with_context(|| format!("Failed to load vbmeta structures: {path:?}"))?;

    // We don't have a good way to get the length of the header, so we serialize
    // what we just parsed and compare it to the raw file so ensure that the
    // round-tripped data is identical.
    let raw_header = {
        let mut writer = Cursor::new(Vec::new());
        header
            .to_writer(&mut writer)
            .with_context(|| format!("Failed to serialize header: {path:?}"))?;
        writer.into_inner()
    };

    let header_offset = footer.map(|f| f.vbmeta_offset).unwrap_or_default();
    raw_reader
        .seek(SeekFrom::Start(header_offset))
        .with_context(|| format!("Failed to seek file: {path:?}"))?;

    let raw_header_orig = raw_reader
        .read_vec_exact(raw_header.len())
        .with_context(|| format!("Failed to reread AVB header: {path:?}"))?;

    if raw_header != raw_header_orig {
        bail!("Serialized header does not match original header: {path:?}");
    }

    context.update(&raw_header);

    for descriptor in &header.descriptors {
        if let avb::Descriptor::ChainPartition(d) = descriptor {
            compute_digest_recursive(
                directory,
                &d.partition_name,
                context,
                max_depth - 1,
                seen,
                cancel_signal,
            )?;
        }
    }

    Ok(())
}

/// Compute the vbmeta digest. This is defined as the digest of the header in
/// the root vbmeta image, followed by the headers in the immediate chained
/// partitions. This digest is not defined to be recursive, so headers of
/// chained partitions more than one level deep are ignored.
pub fn compute_digest(
    directory: &Path,
    name: &str,
    cancel_signal: &AtomicBool,
) -> Result<[u8; 32]> {
    let mut seen = HashSet::<String>::new();
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);

    compute_digest_recursive(directory, name, &mut context, 2, &mut seen, cancel_signal)?;

    let digest = context.finish();

    Ok(digest.as_ref().try_into().unwrap())
}

fn unpack_subcommand(cli: &UnpackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (info, mut reader) = read_avb_image(&cli.input)?;
    display_info(&cli.display, &info);

    write_info(&cli.output_info, &info)?;

    if info.footer.is_some() && !cli.no_output_raw {
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

        let file = write_raw_and_update(&cli.output, &mut reader, &mut info, cancel_signal)?;

        update_dm_verity_cmdline(&mut info)?;

        file
    } else {
        File::create(&cli.output)
            .with_context(|| format!("Failed to open output for writing: {:?}", cli.output))?
    };

    sign_or_clear(&mut info, &orig_header, &cli.key)?;

    write_avb_image(&file, &mut info, cli.recompute_size)?;

    // We display the info at the very end after both the header and footer are
    // updated so that incorrect/incomplete information isn't shown.
    display_info(&cli.display, &info);

    if let Some(path) = &cli.output_info {
        write_info(path, &info)?;
    }

    Ok(())
}

fn repack_subcommand(cli: &RepackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (mut info, mut reader) = read_avb_image(&cli.input)?;
    let orig_header = info.header.clone();

    let file = if info.footer.is_some() {
        let file = write_raw_and_verify(&cli.output, &mut reader, &info, false, cancel_signal)?;

        // Write new hash tree and FEC data instead of copying the original.
        // There could have been errors in the original FEC data itself.
        if let AppendedDescriptorMut::HashTree(d) = info.header.appended_descriptor_mut()? {
            d.update(&file, None, cancel_signal)?;
        }

        update_dm_verity_cmdline(&mut info)?;

        file
    } else {
        File::create(&cli.output)
            .with_context(|| format!("Failed to open for writing: {:?}", cli.output))?
    };

    sign_or_clear(&mut info, &orig_header, &cli.key)?;

    write_avb_image(&file, &mut info, false)?;

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

fn verify_internal(
    public_key_path: Option<&Path>,
    public_key_digest: Option<[u8; 32]>,
    opener: &ImageOpener,
    name: &str,
    repair: bool,
    allow_missing: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let trust_method = if let Some(p) = public_key_path {
        let data = fs::read(p).with_context(|| format!("Failed to read file: {p:?}"))?;
        let key = avb::decode_public_key(&data)
            .with_context(|| format!("Failed to decode public key: {p:?}"))?;

        TrustMethod::Key(key)
    } else if let Some(d) = public_key_digest {
        TrustMethod::KeyDigest(d)
    } else {
        TrustMethod::Anything
    };

    let mut seen = HashSet::<String>::new();
    let mut descriptors = HashMap::<String, Descriptor>::new();

    verify_headers(opener, name, &trust_method, &mut seen, &mut descriptors)?;
    verify_descriptors(opener, &descriptors, repair, allow_missing, cancel_signal)?;

    info!("Successfully verified all vbmeta signatures and hashes");

    Ok(())
}

fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let directory = util::parent_path(&cli.input);
    let name = cli
        .input
        .file_stem()
        .with_context(|| format!("Path is not a file: {:?}", cli.input))?
        .to_str()
        .ok_or_else(|| anyhow!("Invalid UTF-8: {:?}", cli.input))?;

    let opener = ImageOpener::with_dir(directory);

    verify_internal(
        cli.public_key.as_deref(),
        None,
        &opener,
        name,
        cli.repair,
        !cli.fail_if_missing,
        cancel_signal,
    )
}

#[cfg(target_os = "android")]
fn get_required_property(name: &str) -> Result<String> {
    system_properties::read(name)
        .with_context(|| format!("Failed to query property: {name}"))?
        .ok_or_else(|| anyhow!("Property is not set: {name}"))
}

#[cfg(target_os = "android")]
fn verify_device_subcommand(cli: &VerifyDeviceCli, cancel_signal: &AtomicBool) -> Result<()> {
    let slot_suffix = get_required_property("ro.boot.slot_suffix")?;

    // Use the bootloader's public key digest if no key is specified. This is
    // what the user flashed for avb_custom_key.
    let public_key_digest = if cli.public_key.is_none() {
        let hex_digest = get_required_property("ro.boot.vbmeta.public_key_digest")?;
        let mut digest = [0u8; 32];

        hex::decode_to_slice(&hex_digest, &mut digest)
            .with_context(|| format!("Invalid public key digest: {hex_digest}"))?;

        info!("Verifying against bootloader public key digest: {hex_digest}");

        Some(digest)
    } else {
        None
    };

    let mut opener = ImageOpener::new();
    opener.add_dir("/dev/block/by-name", &slot_suffix);
    opener.add_dir("/dev/block/mapper", &slot_suffix);

    verify_internal(
        cli.public_key.as_deref(),
        public_key_digest,
        &opener,
        &cli.partition,
        false,
        false,
        cancel_signal,
    )
}

fn digest_subcommand(cli: &DigestCli, cancel_signal: &AtomicBool) -> Result<()> {
    let directory = util::parent_path(&cli.input);
    let name = cli
        .input
        .file_stem()
        .with_context(|| format!("Path is not a file: {:?}", cli.input))?
        .to_str()
        .ok_or_else(|| anyhow!("Invalid UTF-8: {:?}", cli.input))?;

    let digest = compute_digest(directory, name, cancel_signal)?;

    println!("{}", hex::encode(digest));

    Ok(())
}

pub fn avb_main(cli: &AvbCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        AvbCommand::Unpack(c) => unpack_subcommand(c, cancel_signal),
        AvbCommand::Pack(c) => pack_subcommand(c, cancel_signal),
        AvbCommand::Repack(c) => repack_subcommand(c, cancel_signal),
        AvbCommand::Info(c) => info_subcommand(c),
        AvbCommand::Verify(c) => verify_subcommand(c, cancel_signal),
        #[cfg(target_os = "android")]
        AvbCommand::VerifyDevice(c) => verify_device_subcommand(c, cancel_signal),
        AvbCommand::Digest(c) => digest_subcommand(c, cancel_signal),
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
    /// Path to signing key.
    ///
    /// A signing key is needed if packing an image where the original header
    /// was signed and the header needs to be modified (eg. for a new checksum).
    /// If the header was originally not signed, then the signing key is not
    /// used, unless --force is specified.
    ///
    /// This should normally be a private key. However, if --signing-helper is
    /// used, then it should be a public key instead.
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

    /// External program for signing.
    ///
    /// If this option is specified, then --key must refer to a public key. The
    /// program will be invoked as:
    ///
    /// <program> <algo> <public key> [file <pass file>|env <pass env>]
    #[arg(long, value_name = "PROGRAM", value_parser)]
    signing_helper: Option<PathBuf>,
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

    /// Do not output raw image.
    #[arg(long, conflicts_with = "output_raw")]
    no_output_raw: bool,

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

    /// Path to output AVB info TOML.
    ///
    /// If specified, the AVB info containing all recomputed fields will be
    /// written to this file. This can point to the same file as --input-info.
    #[arg(long, value_name = "FILE", value_parser)]
    output_info: Option<PathBuf>,

    /// Path to input raw image.
    ///
    /// Appended AVB images require a raw image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "raw.img")]
    input_raw: PathBuf,

    /// Recompute image size.
    ///
    /// By default, it is assumed that the image has a fixed size specified by
    /// the image_size top-level field in the AVB info TOML. If flag is passed,
    /// then that field is ignored and the smallest possible output image will
    /// be created.
    #[arg(long)]
    recompute_size: bool,

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

    /// Fail if a referenced image is missing.
    ///
    /// Missing images are ignored by default because some OTAs contain vbmeta
    /// images referencing partitions that only exist on the real device.
    #[arg(long)]
    fail_if_missing: bool,
}

/// Verify vbmeta signatures for the currently booted system.
///
/// This behaves like the `verify` subcommand, except that it checks the actual
/// partitions that this device is currently booted from.
#[cfg(target_os = "android")]
#[derive(Debug, Parser)]
struct VerifyDeviceCli {
    /// Path to public key in AVB binary format.
    ///
    /// If this is not specified, the signatures can only be checked for
    /// validity, not whether they are trusted.
    #[arg(short, long, value_name = "FILE", value_parser)]
    public_key: Option<PathBuf>,

    /// Partition to recursively verify.
    #[arg(short = 'P', long, value_name = "NAME", default_value = "vbmeta")]
    partition: String,
}

/// Compute the vbmeta digest.
///
/// This value is equal to what is reported by the ro.boot.vbmeta.digest
/// property on a real device.
#[derive(Debug, Parser)]
struct DigestCli {
    /// Path to input AVB image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum AvbCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    #[command(alias = "dump")]
    Info(InfoCli),
    Verify(VerifyCli),
    #[cfg(target_os = "android")]
    VerifyDevice(VerifyDeviceCli),
    Digest(DigestCli),
}

/// Pack, unpack, and inspect AVB-protected images.
#[derive(Debug, Parser)]
pub struct AvbCli {
    #[command(subcommand)]
    command: AvbCommand,
}
