// SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

use anyhow::{Context, Result, anyhow, bail};
use bitflags::bitflags;
use clap::{ArgAction, Args, Parser, Subcommand, value_parser};
use rawzip::{
    CompressionMethod, RECOMMENDED_BUFFER_SIZE, ZipArchive, ZipArchiveEntryWayfinder,
    ZipArchiveWriter, extra_fields::ExtraFieldId,
};
use rayon::{iter::IntoParallelRefIterator, prelude::ParallelIterator};
use tempfile::{NamedTempFile, TempDir};
use topological_sort::TopologicalSort;
use tracing::{debug_span, error, info, warn};
use x509_cert::Certificate;

use crate::{
    cli::{
        self,
        avb::{ImageOpener, TrustMethod},
    },
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::{
        avb::{self, Descriptor, Header},
        ota::{self, SigningWriter, ZipEntry, ZipMode},
        padding,
        payload::{self, CowVersion, PayloadHeader, PayloadWriter, VabcAlgo, VabcParams},
        zip::{
            self, ReaderAtWrapper, ZipArchiveReadAtExt, ZipEntriesSafeExt, ZipFileHeaderRecordExt,
        },
    },
    patch::{
        boot::{
            self, BootImageOpener, BootImagePatch, DsuPubKeyPatcher, MagiskRootPatcher,
            OtaCertPatcher, PrepatchedImagePatcher,
        },
        system,
    },
    protobuf::{
        build::tools::releasetools::OtaMetadata, chromeos_update_engine::DeltaArchiveManifest,
    },
    stream::{
        self, FromReader, HashingWriter, MutexFile, ReadAt, ReadSeek, SectionReader,
        SectionReaderAt, ToWriter, UserPosFile, WriteAt, WriteSeek,
    },
    util,
};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PartitionFlags: u8 {
        const BOOT = 1 << 0;
        const SYSTEM = 1 << 1;
        const VBMETA = 1 << 2;
        const COW = 1 << 3;

        const KNOWN = Self::BOOT.bits() | Self::SYSTEM.bits() | Self::VBMETA.bits();
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RequiredFlags: u8 {
        const SYSTEM = 1 << 0;
        const ALL_COW = 1 << 1;
    }
}

fn is_zero_sha256(mut size: u64, digest: &[u8]) -> bool {
    if digest.len() != ring::digest::SHA256_OUTPUT_LEN {
        return false;
    }

    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    while size > 0 {
        let n = size.min(util::ZEROS.len() as u64);
        context.update(&util::ZEROS[..n as usize]);
        size -= n;
    }

    let zero_digest = context.finish();

    zero_digest.as_ref() == digest
}

/// Get the images required for patching. If [`RequiredFlags::SYSTEM`] is
/// specified, then the system image is included. If [`RequiredFlags::ALL_COW`]
/// is specified, then all images with CoW size estimates are included.
pub fn get_required_images(
    manifest: &DeltaArchiveManifest,
    required_flags: RequiredFlags,
) -> HashMap<String, PartitionFlags> {
    let mut result = HashMap::new();

    for partition in &manifest.partitions {
        let name = &partition.partition_name;
        let mut flags = PartitionFlags::empty();

        if name == "boot" || name == "init_boot" || name == "recovery" || name == "vendor_boot" {
            flags |= PartitionFlags::BOOT;
        } else if required_flags.contains(RequiredFlags::SYSTEM) && name == "system" {
            flags |= PartitionFlags::SYSTEM;
        } else if name.starts_with("vbmeta") {
            let Some(pi) = &partition.new_partition_info else {
                continue;
            };

            // Some devices seem to ship with empty unused vbmeta partitions.
            // Use the SHA-256 checksum to skip them so we don't have to extract
            // them to check.
            let size = pi.size();
            if (4096..=65536).contains(&size) && is_zero_sha256(size, pi.hash()) {
                continue;
            }

            flags |= PartitionFlags::VBMETA;
        }

        if partition.estimate_cow_size.is_some() {
            flags |= PartitionFlags::COW;
        }

        // Skip completely unrecognized partitions.
        if flags.is_empty() {
            continue;
        }

        // Skip unrecognized CoW partitions unless we ask for them.
        if flags == PartitionFlags::COW && !required_flags.contains(RequiredFlags::ALL_COW) {
            continue;
        }

        result.insert(name.clone(), flags);
    }

    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputFileState {
    External,
    Extracted,
    Modified,
}

struct InputFile {
    file: Arc<File>,
    state: InputFileState,
}

/// Open all input files listed in `required_images`. If an image has a path
/// in `external_images`, that file is opened. Otherwise, the image is extracted
/// from the payload into a temporary file (that is unnamed if supported by the
/// operating system).
fn open_input_files(
    payload: &(dyn ReadAt + Sync),
    required_images: &HashMap<String, PartitionFlags>,
    external_images: &HashMap<String, PathBuf>,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<HashMap<String, InputFile>> {
    let mut input_files = HashMap::<String, InputFile>::new();

    // We always include replacement images that the user specifies, even if
    // they don't need to be patched.
    let all_images = required_images
        .keys()
        .chain(external_images.keys())
        .collect::<HashSet<_>>();

    for name in all_images {
        let _span = debug_span!("image", name).entered();

        if let Some(path) = external_images.get(name) {
            info!("Opening external image: {name}: {path:?}");

            let file = File::open(path)
                .map(Arc::new)
                .with_context(|| format!("Failed to open external image: {path:?}"))?;
            input_files.insert(
                name.clone(),
                InputFile {
                    file,
                    state: InputFileState::External,
                },
            );
        } else {
            info!("Extracting from original payload: {name}");

            let file = tempfile::tempfile()
                .map(Arc::new)
                .with_context(|| format!("Failed to create temp file for: {name}"))?;

            payload::extract_image(payload, &file, header, name, cancel_signal)
                .with_context(|| format!("Failed to extract from original payload: {name}"))?;
            input_files.insert(
                name.clone(),
                InputFile {
                    file,
                    state: InputFileState::Extracted,
                },
            );
        }
    }

    Ok(input_files)
}

/// Patch the boot images listed in `required_images`. Not every image is
/// necessarily patched. Each patcher will determine which image it should
/// target. If the original image is signed, then it will be re-signed with
/// `key_avb`.
fn patch_boot_images(
    required_images: &HashMap<String, PartitionFlags>,
    input_files: &mut HashMap<String, InputFile>,
    boot_patchers: &[Box<dyn BootImagePatch + Sync>],
    key_avb: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let boot_partitions = required_images
        .iter()
        .filter(|(_, flags)| flags.contains(PartitionFlags::BOOT))
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();

    info!(
        "Candidate boot images: {}",
        util::join(util::sort(boot_partitions.iter()), ", "),
    );

    struct Opener<'a>(Mutex<&'a mut HashMap<String, InputFile>>);

    impl BootImageOpener for Opener<'_> {
        fn open_original(&self, name: &str) -> io::Result<Box<dyn ReadSeek + Sync>> {
            let locked = self.0.lock().unwrap();
            Ok(Box::new(locked[name].file.clone()))
        }

        fn open_replacement(&self, name: &str) -> io::Result<Box<dyn WriteSeek + Sync>> {
            let mut locked = self.0.lock().unwrap();
            let input_file = locked.get_mut(name).unwrap();
            input_file.file = tempfile::tempfile().map(Arc::new)?;
            input_file.state = InputFileState::Modified;
            Ok(Box::new(input_file.file.clone()))
        }
    }

    boot::patch_boot_images(
        &boot_partitions,
        &Opener(Mutex::new(input_files)),
        key_avb,
        boot_patchers,
        cancel_signal,
    )
    .with_context(|| {
        format!(
            "Failed to patch boot images: {}",
            util::join(util::sort(boot_partitions.iter()), ", "),
        )
    })?;

    Ok(())
}

/// Patch the single system image listed in `required_images` to replace the
/// `otacerts.zip` contents.
fn patch_system_image<'a>(
    required_images: &'a HashMap<String, PartitionFlags>,
    input_files: &mut HashMap<String, InputFile>,
    cert_ota: &Certificate,
    key_avb: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<(&'a str, Vec<Range<u64>>)> {
    let mut system_iter = required_images
        .iter()
        .filter(|(_, flags)| flags.contains(PartitionFlags::SYSTEM))
        .map(|(name, _)| name);
    let Some(target) = system_iter.next() else {
        bail!("No system partition found");
    };
    if system_iter.next().is_some() {
        bail!("Multiple system partitions found");
    }

    let _span = debug_span!("image", name = target).entered();

    info!("Patching system image: {target}");

    let input_file = input_files.get_mut(target).unwrap();

    // We can't modify external files in place.
    if input_file.state == InputFileState::External {
        let mut reader = UserPosFile::new(&input_file.file);
        let mut writer = tempfile::tempfile()
            .with_context(|| format!("Failed to create temp file for: {target}"))?;

        stream::copy(&mut reader, &mut writer, cancel_signal)?;

        input_file.file = Arc::new(writer);
        input_file.state = InputFileState::Extracted;
    }

    let (mut ranges, other_ranges) =
        system::patch_system_image(&input_file.file, cert_ota, key_avb, cancel_signal)
            .with_context(|| format!("Failed to patch system image: {target}"))?;

    input_file.state = InputFileState::Modified;

    info!("Patched otacerts.zip offsets in {target}: {ranges:?}");

    ranges.extend(other_ranges);

    Ok((target, ranges))
}

/// Load the specified vbmeta image headers. If an image has a vbmeta footer,
/// then an error is returned because the vbmeta patching logic only ever writes
/// root vbmeta images.
fn load_vbmeta_images(
    images: &mut HashMap<String, InputFile>,
    vbmeta_images: &HashSet<&str>,
) -> Result<HashMap<String, Header>> {
    let mut result = HashMap::new();

    for &name in vbmeta_images {
        let input_file = images.get_mut(name).unwrap();
        let (header, footer, _) = avb::load_image(&mut input_file.file)
            .with_context(|| format!("Failed to load vbmeta image: {name}"))?;

        if let Some(f) = footer {
            bail!("{name} is a vbmeta partition, but has a footer: {f:?}");
        }

        result.insert(name.to_owned(), header);
    }

    Ok(result)
}

/// Check that all critical partitions within the payload are protected by a
/// vbmeta image in `vbmeta_headers`.
fn ensure_partitions_protected(
    required_images: &HashMap<String, PartitionFlags>,
    vbmeta_headers: &HashMap<String, Header>,
) -> Result<()> {
    let critical_partitions = required_images
        .iter()
        .filter(|(_, flags)| flags.intersects(PartitionFlags::BOOT | PartitionFlags::VBMETA))
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();

    // vbmeta partitions first.
    let mut avb_partitions = vbmeta_headers
        .keys()
        .map(|n| n.as_str())
        .collect::<BTreeSet<_>>();

    // Then, everything referred to by the descriptors.
    for header in vbmeta_headers.values() {
        let partition_names = header.descriptors.iter().filter_map(|d| d.partition_name());

        avb_partitions.extend(partition_names);
    }

    let missing = critical_partitions
        .difference(&avb_partitions)
        .collect::<Vec<_>>();

    if !missing.is_empty() {
        bail!(
            "Found critical partitions that are not protected by AVB: {}",
            util::join(missing, ", "),
        );
    }

    Ok(())
}

/// From the set of input images (modified partitions + all vbmeta partitions),
/// determine the order to patch the vbmeta images so that it can be done in a
/// single pass.
fn get_vbmeta_patch_order(
    images: &HashMap<String, InputFile>,
    vbmeta_headers: &HashMap<String, Header>,
) -> Result<Vec<(String, HashSet<String>)>> {
    let mut dep_graph = HashMap::<&str, HashSet<String>>::new();
    let mut missing = images.keys().cloned().collect::<BTreeSet<_>>();

    for (vbmeta_name, header) in vbmeta_headers {
        dep_graph.insert(vbmeta_name, HashSet::new());
        missing.remove(vbmeta_name);

        for descriptor in &header.descriptors {
            let Some(partition_name) = descriptor.partition_name() else {
                continue;
            };

            // Only consider (chained) vbmeta partitions and other partitions
            // that were modified during patching.
            if images.contains_key(partition_name)
                && (vbmeta_headers.contains_key(partition_name)
                    || images[partition_name].state != InputFileState::Extracted)
            {
                dep_graph
                    .get_mut(vbmeta_name.as_str())
                    .unwrap()
                    .insert(partition_name.to_owned());
            }

            missing.remove(partition_name);
        }
    }

    if !missing.is_empty() {
        warn!(
            "Partitions aren't protected by AVB: {}",
            util::join(missing, ", "),
        );
    }

    // Ensure that there's only a single root of trust. Otherwise, there could
    // be eg. a `vbmeta_unused` containing all the relevant descriptors, but is
    // never loaded by the bootloader.
    let mut roots = BTreeSet::new();

    for name in vbmeta_headers.keys() {
        if !dep_graph.values().any(|d| d.contains(name)) {
            roots.insert(name.as_str());
        }
    }

    // For zero roots, let TopologicalSort report the cycle.
    if roots.len() > 1 {
        bail!(
            "Found multiple root vbmeta images: {}",
            util::join(roots, ", "),
        );
    }

    // Compute the patching order. This only includes vbmeta images. All vbmeta
    // images are included (even those that have no dependencies) so that
    // update_vbmeta_headers() can check and update the flags field if needed.
    let mut topo = TopologicalSort::<String>::new();
    let mut order = vec![];

    for (name, deps) in &dep_graph {
        for dep in deps {
            topo.add_dependency(dep, name.to_owned());
        }
    }

    while !topo.is_empty() {
        match topo.pop() {
            Some(item) => {
                // Only include vbmeta images.
                if dep_graph.contains_key(item.as_str()) {
                    order.push((item.clone(), dep_graph.remove(item.as_str()).unwrap()));
                }
            }
            None => bail!("vbmeta dependency graph has cycle: {topo:?}"),
        }
    }

    Ok(order)
}

/// Copy the hash or hashtree descriptor from the child image header into the
/// parent image header if the child is unsigned or update the parent's chain
/// descriptor if the child is signed. The existing descriptor in the parent
/// must have the same type as the child.
fn update_security_descriptors(
    parent_header: &mut Header,
    child_header: &Header,
    parent_name: &str,
    child_name: &str,
) -> Result<()> {
    // This can't fail since the descriptor must have existed for the dependency
    // to exist.
    let parent_descriptor = parent_header
        .descriptors
        .iter_mut()
        .find(|d| d.partition_name() == Some(child_name))
        .unwrap();
    let parent_type = parent_descriptor.type_name();

    if child_header.public_key.is_empty() {
        // vbmeta is unsigned. Copy the child's existing descriptor.
        let Some(child_descriptor) = child_header
            .descriptors
            .iter()
            .find(|d| d.partition_name() == Some(child_name))
        else {
            bail!("{child_name} has no descriptor for itself");
        };
        let child_type = child_descriptor.type_name();

        match (parent_descriptor, child_descriptor) {
            (Descriptor::Hash(pd), Descriptor::Hash(cd)) => {
                *pd = cd.clone();
            }
            (Descriptor::HashTree(pd), Descriptor::HashTree(cd)) => {
                *pd = cd.clone();
            }
            _ => {
                bail!(
                    "{child_name} descriptor ({child_type}) does not match entry in {parent_name} ({parent_type})"
                );
            }
        }
    } else {
        // vbmeta is signed; Use a chain descriptor.
        match parent_descriptor {
            Descriptor::ChainPartition(pd) => {
                child_header.public_key.clone_into(&mut pd.public_key);
            }
            _ => {
                bail!(
                    "{child_name} descriptor ({parent_type}) in {parent_name} must be a chain descriptor"
                );
            }
        }
    }

    Ok(())
}

/// Get the text before the first equal sign in the kernel command line if it is
/// not empty.
fn cmdline_prefix(cmdline: &str) -> Option<&str> {
    let (prefix, _) = cmdline.split_once('=')?;
    if prefix.is_empty() {
        return None;
    }

    Some(prefix)
}

/// Merge property descriptors and kernel command line descriptors from the
/// child into the parent. The property descriptors are matched based on the
/// entire property key. The kernel command line descriptors are matched based
/// on the non-empty text left of the first equal sign (if it exists).
///
/// This is a no-op if the child is signed because it is expected to be chain
/// loaded by the parent.
fn update_metadata_descriptors(parent_header: &mut Header, child_header: &Header) {
    if !child_header.public_key.is_empty() {
        return;
    }

    for child_descriptor in &child_header.descriptors {
        match child_descriptor {
            Descriptor::Property(cd) => {
                let parent_property = parent_header.descriptors.iter_mut().find_map(|d| match d {
                    Descriptor::Property(p) if p.key == cd.key => Some(p),
                    _ => None,
                });

                if let Some(pd) = parent_property {
                    cd.value.clone_into(&mut pd.value);
                } else {
                    parent_header
                        .descriptors
                        .push(Descriptor::Property(cd.clone()));
                }
            }
            Descriptor::KernelCmdline(cd) => {
                let Some(prefix) = cmdline_prefix(&cd.cmdline) else {
                    continue;
                };

                let parent_property = parent_header.descriptors.iter_mut().find_map(|d| match d {
                    Descriptor::KernelCmdline(p) if cmdline_prefix(&p.cmdline) == Some(prefix) => {
                        Some(p)
                    }
                    _ => None,
                });

                if let Some(pd) = parent_property {
                    cd.cmdline.clone_into(&mut pd.cmdline);
                } else {
                    parent_header
                        .descriptors
                        .push(Descriptor::KernelCmdline(cd.clone()));
                }
            }
            _ => {}
        }
    }
}

/// Get the VABC parameters from the payload header. This will fail if an
/// unsupported VABC algorithm or CoW version is specified, but not if VABC is
/// disabled.
fn get_vabc_params(header: &PayloadHeader) -> Result<Option<VabcParams>> {
    // Only CoW v2 seems to exist in the wild currently, so that is all we
    // support.
    let Some(dpm) = &header.manifest.dynamic_partition_metadata else {
        return Ok(None);
    };

    if !dpm.vabc_enabled() {
        return Ok(None);
    }

    let cow_version = match dpm.cow_version() {
        2 => CowVersion::V2,
        3 => {
            let Some(compression_factor) = dpm.compression_factor else {
                bail!("No CoW compression factor specified");
            };
            let Ok(compression_factor) = u32::try_from(compression_factor) else {
                bail!("CoW compression factor is too large: {compression_factor}");
            };

            CowVersion::V3 { compression_factor }
        }
        v => bail!("Unsupported CoW version: {v}"),
    };

    let compression = dpm.vabc_compression_param();
    let Ok(vabc_algo) = VabcAlgo::from_str(compression) else {
        bail!("Unsupported VABC compression: {compression}");
    };

    let vabc_params = VabcParams {
        version: cow_version,
        algo: vabc_algo,
    };

    Ok(Some(vabc_params))
}

/// Set the VABC algorithm in the payload header and return whether it was
/// changed. This will fail if VABC was originally disabled. Returns whether the
/// new algorithm is different from the old algorithm.
fn set_vabc_algo(header: &mut PayloadHeader, vabc_algo: VabcAlgo) -> Result<bool> {
    let Some(dpm) = &mut header.manifest.dynamic_partition_metadata else {
        bail!("Dynamic partition metadata is missing");
    };

    if !dpm.vabc_enabled() {
        bail!("Cannot change VABC algorithm when VABC is disabled");
    }

    let compression = dpm.vabc_compression_param();
    let Ok(old_vabc_algo) = VabcAlgo::from_str(compression) else {
        bail!("Unsupported VABC compression: {compression}");
    };

    if vabc_algo == old_vabc_algo {
        return Ok(false);
    }

    dpm.vabc_compression_param = Some(vabc_algo.to_string());

    Ok(true)
}

/// Update vbmeta headers.
///
/// * If [`Header::flags`] is non-zero, then an error is returned because the
///   value renders AVB useless. If `clear_vbmeta_flags` is set to true, then
///   the value is set to 0 instead.
/// * [`Header::descriptors`] is updated for each dependency listed in `order`.
/// * [`Header::algorithm_type`] is updated with an algorithm type that matches
///   `key`. This is not a factor when determining if a header is changed.
///
/// If changes were made to a vbmeta header, then the image in `images` will be
/// replaced with a new in-memory reader containing the new image. Otherwise,
/// the image is removed from `images` entirely to avoid needing to repack it.
fn update_vbmeta_headers(
    images: &mut HashMap<String, InputFile>,
    headers: &mut HashMap<String, Header>,
    order: &mut [(String, HashSet<String>)],
    clear_vbmeta_flags: bool,
    key: &RsaSigningKey,
    block_size: u64,
) -> Result<()> {
    info!(
        "Patching vbmeta images: {}",
        util::join(order.iter().map(|(n, _)| n), ", "),
    );

    for (name, deps) in order {
        let parent_header = headers.get_mut(name).unwrap();
        let orig_parent_header = parent_header.clone();

        if parent_header.flags != 0 {
            if clear_vbmeta_flags {
                parent_header.flags = 0;
            } else {
                bail!(
                    "Verified boot is disabled by {name}'s header flags: {:#x}",
                    parent_header.flags,
                );
            }
        }

        for dep in deps.iter() {
            let input_file = images.get_mut(dep).unwrap();
            let (header, _, _) = avb::load_image(&mut input_file.file)
                .with_context(|| format!("Failed to load vbmeta footer from image: {dep}"))?;

            update_security_descriptors(parent_header, &header, name, dep)?;
            update_metadata_descriptors(parent_header, &header);
        }

        // Only sign and rewrite the image if we need to. Some vbmeta images may
        // have no dependencies and are only being processed to ensure that the
        // flags are set to a sane value.
        //
        // The root vbmeta image is always signed because it is possible to
        // invoke avbroot is a way that no modifications are made (rootless +
        // skipping recovery otacerts.zip patch). We still want the result to be
        // bootable.
        if parent_header != &orig_parent_header || name == "vbmeta" {
            parent_header
                .set_algo_for_key(key)
                .with_context(|| format!("Failed to set signature algorithm: {name}"))?;
            parent_header
                .sign(key)
                .with_context(|| format!("Failed to sign vbmeta header for image: {name}"))?;

            let mut writer = tempfile::tempfile()
                .with_context(|| format!("Failed to create temp file for: {name}"))?;
            parent_header
                .to_writer(&mut writer)
                .with_context(|| format!("Failed to write vbmeta image: {name}"))?;

            padding::write_zeros(&mut writer, block_size)
                .with_context(|| format!("Failed to write vbmeta padding: {name}"))?;

            let input_file = images.get_mut(name).unwrap();
            input_file.file = Arc::new(writer);
            input_file.state = InputFileState::Modified;
        }
    }

    Ok(())
}

/// Compress an image and update the OTA manifest partition entry appropriately.
/// If `ranges` is [`None`], then the entire file is compressed. Otherwise, only
/// the chunks containing the specified ranges are compressed. In the latter
/// scenario, unmodified chunks must be copied from the original payload.
pub fn compress_image(
    name: &str,
    file: &mut Arc<File>,
    header: &mut PayloadHeader,
    ranges: Option<&[Range<u64>]>,
    cancel_signal: &AtomicBool,
) -> Result<Vec<Range<usize>>> {
    let _span = debug_span!("image", name).entered();

    file.rewind()?;

    let writer =
        tempfile::tempfile().with_context(|| format!("Failed to create temp file for: {name}"))?;

    let vabc_params = get_vabc_params(header)?;
    let block_size = header.manifest.block_size();
    let partition = header
        .manifest
        .partitions
        .iter_mut()
        .find(|p| p.partition_name == name)
        .unwrap();

    // If VABC is enabled, we need to update the CoW size estimate or else the
    // CoW block device may run out of space during flashing.
    let vabc_params = if partition.estimate_cow_size.is_some() {
        let Some(vabc_params) = vabc_params else {
            bail!("Partition has CoW estimate, but VABC is disabled: {name}");
        };

        info!(
            "Needs updated {} CoW size estimate: {name}",
            vabc_params.algo,
        );

        Some(vabc_params)
    } else {
        None
    };

    if let Some(r) = ranges {
        info!("Compressing partial image: {name}: {r:?}");

        match payload::compress_modified_image(
            &*file,
            &writer,
            block_size,
            partition.new_partition_info.as_mut().unwrap(),
            &mut partition.operations,
            r,
            cancel_signal,
        ) {
            Ok(indices) => {
                // The changes we make usually aren't any less compressible, but
                // we'll still recompute the CoW size estimate to handle the
                // case where the user requested a different algorithm.
                if let Some(vabc_params) = vabc_params {
                    let cow_estimate = payload::compute_cow_estimate(
                        &*file,
                        partition.operations.len() as u64,
                        name,
                        block_size,
                        vabc_params,
                        cancel_signal,
                    )?;

                    partition.estimate_cow_size = Some(cow_estimate.size);
                    partition.estimate_op_count_max =
                        matches!(vabc_params.version, CowVersion::V3 { .. })
                            .then_some(cow_estimate.num_ops);
                }

                *file = Arc::new(writer);

                return Ok(indices);
            }
            // If we can't take advantage of the optimization, we can still
            // compress the whole image.
            Err(payload::Error::ExtentsNotInOrder) => {
                warn!("Cannot use optimization for {name}: extents not in order");
            }
            Err(e) => return Err(e.into()),
        }
    }

    info!("Compressing full image: {name}");

    let (partition_info, operations, cow_estimate) =
        payload::compress_image(file, &writer, name, block_size, vabc_params, cancel_signal)?;

    partition.new_partition_info = Some(partition_info);
    partition.operations = operations;
    partition.estimate_cow_size = cow_estimate.map(|e| e.size);
    let is_v3 = vabc_params.is_some_and(|p| matches!(p.version, CowVersion::V3 { .. }));
    partition.estimate_op_count_max = cow_estimate.and_then(|e| is_v3.then_some(e.num_ops));

    *file = Arc::new(writer);

    #[allow(clippy::single_range_in_vec_init)]
    Ok(vec![0..partition.operations.len()])
}

/// Recompute the CoW estimate for an image and update the OTA manifest
/// partition entry appropriately. The input file is not modified.
pub fn recow_image(
    name: &str,
    file: &File,
    header: &mut PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let _span = debug_span!("image", name).entered();

    (&*file).rewind()?;

    let vabc_params = get_vabc_params(header)?;
    let block_size = header.manifest.block_size();
    let partition = header
        .manifest
        .partitions
        .iter_mut()
        .find(|p| p.partition_name == name)
        .unwrap();

    if partition.estimate_cow_size.is_none() {
        bail!("Partition has no original CoW estimate: {name}");
    }

    let Some(vabc_params) = vabc_params else {
        bail!("Partition has CoW estimate, but VABC is disabled: {name}");
    };

    info!("Recomputing {} CoW size estimate: {name}", vabc_params.algo);

    let cow_estimate = payload::compute_cow_estimate(
        file,
        partition.operations.len() as u64,
        name,
        block_size,
        vabc_params,
        cancel_signal,
    )?;

    partition.estimate_cow_size = Some(cow_estimate.size);
    partition.estimate_op_count_max =
        matches!(vabc_params.version, CowVersion::V3 { .. }).then_some(cow_estimate.num_ops);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn patch_ota_payload(
    payload: &(dyn ReadAt + Sync),
    writer: impl Write,
    external_images: &HashMap<String, PathBuf>,
    boot_patchers: &[Box<dyn BootImagePatch + Sync>],
    skip_system_ota_cert: bool,
    clear_vbmeta_flags: bool,
    vabc_algo_override: Option<VabcAlgo>,
    key_avb: &RsaSigningKey,
    key_ota: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<(String, u64)> {
    let mut header = PayloadHeader::from_reader(UserPosFile::new(payload))
        .context("Failed to load OTA payload header")?;
    if !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
    }

    let mut required_flags = RequiredFlags::empty();
    if !skip_system_ota_cert {
        required_flags |= RequiredFlags::SYSTEM;
    }
    if let Some(vabc_algo) = vabc_algo_override
        && set_vabc_algo(&mut header, vabc_algo)?
    {
        required_flags |= RequiredFlags::ALL_COW;
    }

    let all_partitions = header
        .manifest
        .partitions
        .iter()
        .map(|p| p.partition_name.as_str())
        .collect::<HashSet<_>>();

    // Use external partition images if provided. This may be a larger set than
    // what's needed for our patches.
    for (name, path) in external_images {
        if !all_partitions.contains(name.as_str()) {
            bail!("Cannot replace non-existent {name} partition with {path:?}");
        }
    }

    let required_images = get_required_images(&header.manifest, required_flags);
    let vbmeta_images = required_images
        .iter()
        .filter(|(_, flags)| flags.contains(PartitionFlags::VBMETA))
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();
    let cow_images = required_images
        .iter()
        .filter(|(_, flags)| flags.contains(PartitionFlags::COW))
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();

    // The set of source images to be inserted into the new payload, replacing
    // what was in the original payload. Initially, this refers to either user
    // specified files (--replace option) or temporary files (extracted from the
    // old payload). The values will be replaced later if the images need to be
    // patched (eg. boot or vbmeta image).
    let mut input_files = open_input_files(
        payload,
        &required_images,
        external_images,
        &header,
        cancel_signal,
    )?;

    patch_boot_images(
        &required_images,
        &mut input_files,
        boot_patchers,
        key_avb,
        cancel_signal,
    )?;

    let system_result = if skip_system_ota_cert {
        None
    } else {
        Some(patch_system_image(
            &required_images,
            &mut input_files,
            cert_ota,
            key_avb,
            cancel_signal,
        )?)
    };

    let mut vbmeta_headers = load_vbmeta_images(&mut input_files, &vbmeta_images)?;

    ensure_partitions_protected(&required_images, &vbmeta_headers)?;

    let mut vbmeta_order = get_vbmeta_patch_order(&input_files, &vbmeta_headers)?;

    update_vbmeta_headers(
        &mut input_files,
        &mut vbmeta_headers,
        &mut vbmeta_order,
        clear_vbmeta_flags,
        key_avb,
        header.manifest.block_size().into(),
    )?;

    // Recompute CoW estimates for partitions we don't modify.
    input_files
        .iter_mut()
        .filter(|(name, f)| {
            f.state == InputFileState::Extracted && cow_images.contains(name.as_str())
        })
        .try_for_each(|(name, input_file)| {
            recow_image(name, &input_file.file, &mut header, cancel_signal)
        })?;

    // Drop all unmodified images. We only want to compress modified images.
    // For recowed images, the payload header was already updated with the new
    // estimate. The actual data can be copied from the original payload.
    input_files.retain(|_, f| f.state != InputFileState::Extracted);

    let mut compressed_files = input_files
        .into_iter()
        .map(|(name, mut input_file)| {
            let modified_operations = compress_image(
                &name,
                &mut input_file.file,
                &mut header,
                // We can only perform the optimization of avoiding
                // recompression if the image came from the original payload.
                if let Some((system_target, system_ranges)) = &system_result {
                    if name == *system_target && !external_images.contains_key(&name) {
                        Some(system_ranges)
                    } else {
                        None
                    }
                } else {
                    None
                },
                cancel_signal,
            )
            .with_context(|| format!("Failed to compress image: {name}"))?;

            Ok((name, (input_file, modified_operations)))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    info!("Generating new OTA payload");

    let mut payload_writer = PayloadWriter::new(writer, header.clone(), key_ota.clone())
        .context("Failed to write payload header")?;
    let mut orig_payload_reader = UserPosFile::new(payload);

    while payload_writer
        .begin_next_operation()
        .context("Failed to begin next payload blob entry")?
    {
        let name = payload_writer.partition().unwrap().partition_name.clone();
        let operation = payload_writer.operation().unwrap();

        let Some(data_length) = operation.data_length else {
            // Otherwise, this is a ZERO/DISCARD operation.
            continue;
        };

        let pi = payload_writer.partition_index().unwrap();
        let oi = payload_writer.operation_index().unwrap();
        let orig_partition = &header.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];
        let data_offset = orig_operation
            .data_offset
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        // Try to copy from our replacement image. The compressed chunks are
        // laid out sequentially and data_offset is set to the offset within
        // that file.
        if let Some((input_file, modified_operations)) = compressed_files.get_mut(&name)
            && util::ranges_contains(modified_operations, &oi)
        {
            input_file
                .file
                .seek(SeekFrom::Start(data_offset))
                .with_context(|| format!("Failed to seek image: {name}"))?;

            stream::copy_n(
                &mut input_file.file,
                &mut payload_writer,
                data_length,
                cancel_signal,
            )
            .with_context(|| format!("Failed to copy from replacement image: {name}"))?;

            continue;
        }

        // Otherwise, copy from the original payload.
        let data_offset = data_offset
            .checked_add(header.blob_offset)
            .ok_or_else(|| anyhow!("data_offset overflow in partition #{pi} operation #{oi}"))?;

        orig_payload_reader
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek original payload to {data_offset}"))?;

        stream::copy_n(
            &mut orig_payload_reader,
            &mut payload_writer,
            data_length,
            cancel_signal,
        )
        .with_context(|| format!("Failed to copy from original payload: {name}"))?;
    }

    let (_, _, properties, metadata_size) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((properties, metadata_size))
}

#[allow(clippy::too_many_arguments)]
fn patch_ota_zip(
    raw_reader: &File,
    zip_reader: &ZipArchive<ReaderAtWrapper<&File>>,
    zip_writer: &mut ZipArchiveWriter<impl Write>,
    external_images: &HashMap<String, PathBuf>,
    boot_patchers: &[Box<dyn BootImagePatch + Sync>],
    skip_system_ota_cert: bool,
    clear_vbmeta_flags: bool,
    vabc_algo_override: Option<VabcAlgo>,
    zip_mode: ZipMode,
    key_avb: &RsaSigningKey,
    key_ota: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<(OtaMetadata, u64)> {
    struct InputEntry {
        compression_method: CompressionMethod,
        is_zip64: bool,
        // We can't store the rawzip::ZipEntry directly because of the lifetime
        // generic parameter. We'll need to read the local headers again later.
        wayfinder: ZipArchiveEntryWayfinder,
    }

    let mut missing = BTreeSet::from([ota::PATH_OTACERT, ota::PATH_PAYLOAD, ota::PATH_PROPERTIES]);
    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let mut input_entries_iter = zip_reader.entries_safe(&mut buffer);
    // Keep in sorted order for reproducibility and to guarantee that the
    // payload is processed before its properties file.
    let mut input_entries = BTreeMap::new();

    while let Some((cd_entry, _)) = input_entries_iter
        .next_entry()
        .context("Failed to list zip entries")?
    {
        let path = cd_entry
            .file_path_utf8()
            .context("Zip contains non-UTF-8 paths")?;

        missing.remove(path);

        input_entries.insert(
            path.to_owned(),
            InputEntry {
                compression_method: cd_entry.compression_method(),
                // We only check for the sizes here instead of the presence of
                // the ZIP64 extra field. The central header's extra fields may
                // have ZIP64 only for the local header offset.
                is_zip64: cd_entry.compressed_size_hint() >= 0xffffffff
                    || cd_entry.uncompressed_size_hint() >= 0xffffffff,
                wayfinder: cd_entry.wayfinder(),
            },
        );
    }

    if !missing.is_empty() {
        bail!("Missing entries in OTA zip: {}", util::join(missing, ", "));
    } else if !input_entries.contains_key(ota::PATH_METADATA)
        && !input_entries.contains_key(ota::PATH_METADATA_PB)
    {
        bail!(
            "Neither legacy nor protobuf OTA metadata files exist: {:?}, {:?}",
            ota::PATH_METADATA,
            ota::PATH_METADATA_PB,
        )
    }

    let mut metadata = None;
    let mut properties = None;
    let mut payload_metadata_size = None;
    let mut metadata_entries = vec![];

    for (path, input_entry) in &input_entries {
        let _span = debug_span!("zip", entry = path).entered();

        let entry = zip_reader
            .get_entry(input_entry.wayfinder)
            .with_context(|| format!("Failed to open zip entry: {path}"))?;
        let mut reader = zip::verifying_reader(&entry, input_entry.compression_method)
            .with_context(|| format!("Failed to open zip entry: {path}"))?;

        // Processed at the end after all other entries are written.
        match path.as_str() {
            // Convert legacy metadata from Android 11 to the modern protobuf
            // structure. Note that although we can read legacy-only OTAs, we
            // always produce both the legacy and protobuf representations in
            // the output.
            ota::PATH_METADATA => {
                let mut buf = String::new();
                reader
                    .read_to_string(&mut buf)
                    .with_context(|| format!("Failed to read OTA metadata: {path}"))?;
                metadata = Some(
                    ota::parse_legacy_metadata(&buf)
                        .with_context(|| format!("Failed to parse OTA metadata: {path}"))?,
                );
                continue;
            }
            // This takes precedence due to sorted iteration order.
            ota::PATH_METADATA_PB => {
                let mut buf = vec![];
                reader
                    .read_to_end(&mut buf)
                    .with_context(|| format!("Failed to read OTA metadata: {path}"))?;
                metadata = Some(
                    ota::parse_protobuf_metadata(&buf)
                        .with_context(|| format!("Failed to parse OTA metadata: {path}"))?,
                );
                continue;
            }
            _ => {}
        }

        // Android's libziparchive parser is broken and only reads data
        // descriptor size fields as 64-bit integers if the central directory
        // says the file size is >= 2^32 - 1. APPNOTE 4.3.9.2 mentions that the
        // parser should be reading 64-bit integers from the data descriptor if
        // the ZIP64 extra field is present. Luckily, we don't have to do
        // anything to work around this because rawzip's threshold when writing
        // is the same as what libziparchive expects.
        let mut builder = zip_writer
            .new_file(path)
            .compression_method(input_entry.compression_method);

        if zip_mode == ZipMode::Seekable && input_entry.is_zip64 {
            // We need to reserve space for the ZIP64 extra field when doing the
            // post-processing to convert a streaming zip to a seekable one.
            builder = builder.extra_field(
                ExtraFieldId::ANDROID_ZIP_ALIGNMENT,
                &[0u8; 16],
                rawzip::Header::LOCAL,
            )?;
        }

        let (entry_writer, data_config) = builder
            .start()
            .with_context(|| format!("Failed to begin new zip entry: {path}"))?;
        let offset = entry_writer.stream_offset();
        let compressed_writer =
            zip::compressed_writer(entry_writer, input_entry.compression_method)
                .with_context(|| format!("Failed to begin new zip entry: {path}"))?;
        let mut data_writer = data_config.wrap(compressed_writer);

        // All remaining entries are written immediately.
        match path.as_str() {
            ota::PATH_OTACERT => {
                // Use the user's certificate
                info!("Replacing zip entry: {path}");

                crypto::write_pem_cert(Path::new(path), &mut data_writer, cert_ota)
                    .with_context(|| format!("Failed to write entry: {path}"))?;
            }
            ota::PATH_PAYLOAD => {
                info!("Patching zip entry: {path}");

                if input_entry.compression_method != CompressionMethod::Store {
                    bail!("{path} is not stored uncompressed");
                }

                // The zip library doesn't provide us with a seekable reader, so
                // we make our own from the underlying file.
                let payload_range = entry.compressed_data_range();
                let payload_reader = SectionReaderAt::new(
                    raw_reader,
                    payload_range.0,
                    payload_range.1 - payload_range.0,
                )?;

                let (p, m) = patch_ota_payload(
                    &payload_reader,
                    &mut data_writer,
                    external_images,
                    boot_patchers,
                    skip_system_ota_cert,
                    clear_vbmeta_flags,
                    vabc_algo_override,
                    key_avb,
                    key_ota,
                    cert_ota,
                    cancel_signal,
                )
                .with_context(|| format!("Failed to patch payload: {path}"))?;

                properties = Some(p);
                payload_metadata_size = Some(m);
            }
            ota::PATH_PROPERTIES => {
                info!("Patching zip entry: {path}");

                // payload.bin is guaranteed to be patched first.
                data_writer
                    .write_all(properties.as_ref().unwrap().as_bytes())
                    .with_context(|| format!("Failed to write payload properties: {path}"))?;
            }
            _ => {
                info!("Copying zip entry: {path}");

                stream::copy(&mut reader, &mut data_writer, cancel_signal)
                    .with_context(|| format!("Failed to copy zip entry: {path}"))?;
            }
        }

        let size = data_writer
            .finish()
            .and_then(|(w, d)| w.finish()?.finish(d))
            .with_context(|| format!("Failed to finalize zip entry: {path}"))?;

        metadata_entries.push(ZipEntry {
            path: path.clone(),
            offset,
            size,
        });
    }

    info!("Generating new OTA metadata");

    let metadata = ota::add_metadata(
        &metadata_entries,
        zip_writer,
        // Offset where next entry would begin.
        zip_writer.stream_offset(),
        &metadata.unwrap(),
        payload_metadata_size.unwrap(),
    )
    .context("Failed to write new OTA metadata")?;

    Ok((metadata, payload_metadata_size.unwrap()))
}

pub fn extract_payload(
    raw_reader: &File,
    directory: &Path,
    payload_offset: u64,
    payload_size: u64,
    header: &PayloadHeader,
    images: &BTreeSet<String>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    info!("Extracting from the payload: {}", util::join(images, ", "));

    // Pre-open all output files.
    let output_files = images
        .iter()
        .map(|name| {
            let path = util::path_join_single(directory, format!("{name}.img"))?;
            let file = File::create(&path)
                .map(Arc::new)
                .with_context(|| format!("Failed to open for writing: {path:?}"))?;
            Ok((name.as_str(), file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    let payload_reader = SectionReaderAt::new(raw_reader, payload_offset, payload_size)?;

    // Extract the images.
    payload::extract_images(
        &payload_reader,
        images.iter().map(|n| {
            (
                n.as_str(),
                &output_files[n.as_str()] as &(dyn WriteAt + Sync),
            )
        }),
        header,
        cancel_signal,
    )
    .context("Failed to extract images from payload")?;

    info!("Successfully extracted images from payload");

    Ok(())
}

fn verify_partition_hashes(
    directory: &Path,
    header: &PayloadHeader,
    images: &BTreeSet<String>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    images.par_iter().try_for_each(|name| -> Result<()> {
        let partition = header
            .manifest
            .partitions
            .iter()
            .find(|p| p.partition_name == name.as_str())
            .ok_or_else(|| anyhow!("Partition not found in header: {name}"))?;
        let expected_digest = partition
            .new_partition_info
            .as_ref()
            .and_then(|info| info.hash.as_ref())
            .ok_or_else(|| anyhow!("Hash not found for partition: {name}"))?;

        let path = util::path_join_single(directory, format!("{name}.img"))?;
        let file =
            File::open(&path).with_context(|| format!("Failed to open for reading: {path:?}"))?;

        let mut writer = HashingWriter::new(
            io::sink(),
            ring::digest::Context::new(&ring::digest::SHA256),
        );

        stream::copy(file, &mut writer, cancel_signal)?;

        let digest = writer.finish().1.finish();

        if digest.as_ref() != expected_digest {
            bail!(
                "Expected sha256 {}, but have {} for partition {name}",
                hex::encode(expected_digest),
                hex::encode(digest),
            );
        }

        Ok(())
    })
}

pub fn patch_subcommand(cli: &PatchCli, cancel_signal: &AtomicBool) -> Result<()> {
    if cli.boot_partition.is_some() {
        warn!("Ignoring --boot-partition: deprecated and no longer needed");
    }

    let output = cli.output.as_ref().map_or_else(
        || {
            let mut s = cli.input.clone().into_os_string();
            s.push(".patched");
            Cow::Owned(PathBuf::from(s))
        },
        Cow::Borrowed,
    );

    let source_avb = PassphraseSource::new(
        &cli.key_avb,
        cli.pass_avb_file.as_deref(),
        cli.pass_avb_env_var.as_deref(),
    );
    let source_ota = PassphraseSource::new(
        &cli.key_ota,
        cli.pass_ota_file.as_deref(),
        cli.pass_ota_env_var.as_deref(),
    );

    let (key_avb, key_ota) = if let Some(helper) = &cli.signing_helper {
        let public_key_avb = crypto::read_pem_public_key_file(&cli.key_avb)
            .with_context(|| format!("Failed to load key: {:?}", cli.key_avb))?;
        let public_key_ota = crypto::read_pem_public_key_file(&cli.key_ota)
            .with_context(|| format!("Failed to load key: {:?}", cli.key_ota))?;

        let key_avb = RsaSigningKey::External {
            program: helper.clone(),
            public_key_file: cli.key_avb.clone(),
            public_key: public_key_avb,
            passphrase_source: source_avb,
        };
        let key_ota = RsaSigningKey::External {
            program: helper.clone(),
            public_key_file: cli.key_ota.clone(),
            public_key: public_key_ota,
            passphrase_source: source_ota,
        };

        (key_avb, key_ota)
    } else {
        let private_key_avb = crypto::read_pem_key_file(&cli.key_avb, &source_avb)
            .with_context(|| format!("Failed to load key: {:?}", cli.key_avb))?;
        let private_key_ota = crypto::read_pem_key_file(&cli.key_ota, &source_ota)
            .with_context(|| format!("Failed to load key: {:?}", cli.key_ota))?;

        let key_avb = RsaSigningKey::Internal(private_key_avb);
        let key_ota = RsaSigningKey::Internal(private_key_ota);

        (key_avb, key_ota)
    };

    let cert_ota = crypto::read_pem_cert_file(&cli.cert_ota)
        .with_context(|| format!("Failed to load certificate: {:?}", cli.cert_ota))?;

    if !crypto::cert_matches_key(&cert_ota, &key_ota)? {
        bail!(
            "Private key {:?} does not match certificate {:?}",
            cli.key_ota,
            cli.cert_ota,
        );
    }

    let mut external_images = HashMap::new();

    for item in cli.replace.chunks_exact(2) {
        let name = item[0]
            .to_str()
            .ok_or_else(|| anyhow!("Invalid partition name: {:?}", item[0]))?;
        let path = Path::new(&item[1]);

        external_images.insert(name.to_owned(), path.to_owned());
    }

    let mut boot_patchers = Vec::<Box<dyn BootImagePatch + Sync>>::new();

    if let Some(magisk) = &cli.root.magisk {
        boot_patchers.push(Box::new(
            MagiskRootPatcher::new(
                magisk,
                cli.magisk_preinit_device.as_deref(),
                cli.magisk_random_seed,
                cli.ignore_magisk_warnings,
            )
            .context("Failed to create Magisk boot image patcher")?,
        ));
    } else if let Some(prepatched) = &cli.root.prepatched {
        // NOTE: This patcher must run first! Otherwise, it'll wipe out any
        // ramdisk changes made by other patchers.
        boot_patchers.push(Box::new(PrepatchedImagePatcher::new(
            prepatched,
            cli.ignore_prepatched_compat + 1,
        )));
    } else {
        assert!(cli.root.rootless);
    }

    if cli.skip_system_ota_cert {
        warn!("Not inserting OTA cert into system image; sideloading further updates may fail");
    }

    if cli.skip_recovery_ota_cert {
        warn!("Not inserting OTA cert into recovery image; sideloading further updates may fail");
    } else {
        boot_patchers.push(Box::new(OtaCertPatcher::new(cert_ota.clone())));
    }

    if cli.dsu {
        boot_patchers.push(Box::new(DsuPubKeyPatcher::new(key_avb.to_public_key())));
    }

    let raw_reader = File::open(&cli.input)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let zip_reader = ZipArchive::from_read_at(&raw_reader, &mut buffer)
        .with_context(|| format!("Failed to read zip: {:?}", cli.input))?;

    // Open the output file for reading too, so we can verify offsets later.
    let temp_writer = NamedTempFile::with_prefix_in(
        output
            .file_name()
            .unwrap_or_else(|| OsStr::new("avbroot.tmp")),
        util::parent_path(&output),
    )
    .context("Failed to open temporary output file")?;
    let temp_path = temp_writer.path().to_owned();
    let signing_writer = match cli.zip_mode {
        ZipMode::Streaming => SigningWriter::new_streaming(temp_writer),
        ZipMode::Seekable => SigningWriter::new_seekable(temp_writer),
    };
    let mut zip_writer = ZipArchiveWriter::new(signing_writer);

    let (metadata, payload_metadata_size) = patch_ota_zip(
        &raw_reader,
        &zip_reader,
        &mut zip_writer,
        &external_images,
        &boot_patchers,
        cli.skip_system_ota_cert,
        cli.clear_vbmeta_flags,
        cli.vabc_algo,
        cli.zip_mode,
        &key_avb,
        &key_ota,
        &cert_ota,
        cancel_signal,
    )
    .context("Failed to patch OTA zip")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let mut temp_writer = signing_writer
        .finish(&key_ota, &cert_ota, cancel_signal)
        .context("Failed to sign output zip")?;
    temp_writer.flush().context("Failed to flush output zip")?;

    // We do a lot of low-level hackery. Reopen and verify offsets.
    info!("Verifying metadata offsets");
    temp_writer.rewind().context("Failed to seek output zip")?;
    ota::verify_metadata(
        BufReader::new(&mut temp_writer),
        &metadata,
        payload_metadata_size,
    )
    .context("Failed to verify OTA metadata offsets")?;

    info!("Successfully patched OTA");

    // NamedTempFile forces 600 permissions on temp files because it's the safe
    // option for a shared /tmp. Since we're writing to the output file's
    // directory, just mimic umask.
    #[cfg(unix)]
    {
        use std::{fs::Permissions, os::unix::prelude::PermissionsExt};

        use rustix::{fs::Mode, process::umask};

        let mask = umask(Mode::empty());
        umask(mask);

        // Mac uses a 16-bit value.
        #[allow(clippy::useless_conversion)]
        let mode = u32::from(0o666 & !mask.bits());

        temp_writer
            .as_file()
            .set_permissions(Permissions::from_mode(mode))
            .with_context(|| format!("Failed to set permissions to {mode:o}: {temp_path:?}"))?;
    }

    temp_writer.persist(output.as_ref()).with_context(|| {
        format!("Failed to move temporary file to output path: {temp_path:?} -> {output:?}")
    })?;

    Ok(())
}

pub fn extract_subcommand(cli: &ExtractCli, cancel_signal: &AtomicBool) -> Result<()> {
    if cli.boot_partition.is_some() {
        warn!("Ignoring --boot-partition: deprecated and no longer needed");
    }

    let raw_reader = File::open(&cli.input)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let zip = ZipArchive::from_read_at(&raw_reader, &mut buffer)
        .with_context(|| format!("Failed to read zip: {:?}", cli.input))?;

    let mut entry_payload = None;
    let mut entry_metadata_pb = None;

    {
        let mut entries = zip.entries_safe(&mut buffer);

        while let Some((cd_entry, _)) =
            entries.next_entry().context("Failed to list zip entries")?
        {
            let path = cd_entry
                .file_path_utf8()
                .context("Zip contains non-UTF-8 paths")?;

            if path == ota::PATH_PAYLOAD {
                entry_payload = Some((cd_entry.wayfinder(), cd_entry.compression_method()));
            } else if path == ota::PATH_METADATA_PB {
                entry_metadata_pb = Some((cd_entry.wayfinder(), cd_entry.compression_method()));
            }
        }
    }

    let (payload_offset, payload_size) = {
        let (wf, _) = entry_payload
            .ok_or_else(|| anyhow!("Failed to find zip entry: {}", ota::PATH_PAYLOAD))?;
        let entry = zip
            .get_entry(wf)
            .with_context(|| format!("Failed to open zip entry: {}", ota::PATH_PAYLOAD))?;
        let range = entry.compressed_data_range();

        (range.0, range.1 - range.0)
    };

    // Open the payload data directly.
    let payload_reader = SectionReaderAt::new(&raw_reader, payload_offset, payload_size)
        .context("Failed to directly open payload section")?;

    let header = PayloadHeader::from_reader(UserPosFile::new(&payload_reader))
        .context("Failed to load OTA payload header")?;
    if !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
    }

    let mut unique_images = BTreeSet::new();

    if cli.extract.all {
        unique_images.extend(
            header
                .manifest
                .partitions
                .iter()
                .map(|p| &p.partition_name)
                .cloned(),
        );
    } else if !cli.extract.partition.is_empty() {
        // We check this later too, but also do it here so we don't create a
        // bunch of empty files before failing.
        let valid_images = header
            .manifest
            .partitions
            .iter()
            .map(|p| &p.partition_name)
            .collect::<BTreeSet<_>>();
        let missing_images = cli
            .extract
            .partition
            .iter()
            .filter(|p| !valid_images.contains(p))
            .collect::<Vec<_>>();

        if !missing_images.is_empty() {
            bail!("Invalid partitions: {}", util::join(missing_images, ", "));
        }

        unique_images.extend(cli.extract.partition.iter().cloned());
    } else if !cli.extract.none {
        let images = get_required_images(&header.manifest, RequiredFlags::SYSTEM)
            .into_iter()
            .filter(|(_, flags)| !cli.extract.boot_only || flags.contains(PartitionFlags::BOOT))
            .map(|(name, _)| name);

        unique_images.extend(images);
    }

    if let Some(path) = &cli.cert_ota {
        info!("Extracting embedded OTA certificate from zip signature");

        let ota_sig = ota::parse_ota_sig(&raw_reader)?;

        crypto::write_pem_cert_file(path, &ota_sig.cert)
            .with_context(|| format!("Failed to write OTA certificate: {path:?}"))?;
    }

    if let Some(path) = &cli.public_key_avb {
        info!("Extracting AVB public key from vbmeta image");

        let data = MutexFile::new(Cursor::new(Vec::new()));

        payload::extract_image(&payload_reader, &data, &header, "vbmeta", cancel_signal)
            .context("Failed to extract vbmeta image")?;

        let (header, _, _) =
            avb::load_image(UserPosFile::new(&data)).context("Failed to parse vbmeta image")?;

        fs::write(path, header.public_key)
            .with_context(|| format!("Failed to write AVB public key: {path:?}"))?;
    }

    if unique_images.is_empty() {
        info!("No partition images to extract");
        return Ok(());
    }

    fs::create_dir_all(&cli.directory)
        .with_context(|| format!("Failed to create directory: {:?}", cli.directory))?;

    extract_payload(
        &raw_reader,
        &cli.directory,
        payload_offset,
        payload_size,
        &header,
        &unique_images,
        cancel_signal,
    )?;

    if cli.fastboot {
        const ANDROID_INFO: &str = "android-info.txt";
        const FASTBOOT_INFO: &str = "fastboot-info.txt";

        // Generate android-info.txt, which is always required for fastboot's
        // flashall subcommand. We only add a basic device check to avoid
        // accidental flashes on the wrong device.

        let metadata = {
            let (wf, cm) = entry_metadata_pb
                .ok_or_else(|| anyhow!("Failed to find zip entry: {}", ota::PATH_METADATA_PB))?;
            let mut metadata_reader = zip
                .get_entry(wf)
                .and_then(|e| zip::verifying_reader(&e, cm))
                .with_context(|| format!("Failed to open zip entry: {}", ota::PATH_METADATA_PB))?;

            let mut metadata_raw = vec![];
            metadata_reader
                .read_to_end(&mut metadata_raw)
                .with_context(|| {
                    format!("Failed to read OTA metadata: {}", ota::PATH_METADATA_PB)
                })?;

            ota::parse_protobuf_metadata(&metadata_raw).with_context(|| {
                format!("Failed to parse OTA metadata: {}", ota::PATH_METADATA_PB)
            })?
        };

        let device = metadata
            .precondition
            .as_ref()
            .and_then(|p| p.device.first())
            .ok_or_else(|| anyhow!("Device codename not found in OTA metadata"))?;

        let android_info_path = util::path_join_single(&cli.directory, ANDROID_INFO)?;
        fs::write(&android_info_path, format!("require board={device}\n"))
            .with_context(|| format!("Failed to write file: {android_info_path:?}"))?;

        // Find out which images can be flashed with fastboot. The bootloader
        // (and potentially modem) partitions need to be flashed as a whole and
        // an OTA doesn't contain sufficient information to generate the
        // required combined file.
        let mut flashable_images = BTreeSet::new();

        for name in &unique_images {
            let path = util::path_join_single(&cli.directory, format!("{name}.img"))?;
            let file = File::open(&path)
                .with_context(|| format!("Failed to open image for reading: {path:?}"))?;

            match avb::load_image(file) {
                Ok(_) => {
                    flashable_images.insert(name);
                }
                // Treat images without AVB metadata as bootloader partitions.
                Err(avb::Error::InvalidHeaderMagic(_)) => continue,
                Err(e) => return Err(e).with_context(|| format!("Failed to load image: {path:?}")),
            }
        }

        // Generate fastboot-info.txt to be able to control how exactly the
        // images are flashed. This solves two problems:
        //
        // 1. fastboot flashall, by default, expects super_empty.img to exist
        //    for A/B devices. If it doesn't exist, it assumes that all images
        //    are meant for non-dynamic partitions and skips the fastbootd
        //    reboot. We cannot generate a proper super_empty.img because it
        //    requires knowing the number of super partitions along with their
        //    names and sizes. This information is not available in an OTA. The
        //    fastboot info file allows us to control when to reboot to
        //    fastbootd and flash each partition.
        //
        //    This approach is a bit slower because we have to reboot into
        //    fastbootd. When the device only has a single super partition,
        //    fastboot will normally locally combine super_empty.img with the
        //    individual partitions to form a full super image and then flash it
        //    via the bootloader's fastboot mode.
        //
        //    Also, because we can't generate super_empty.img, if the super
        //    partition metadata on the device somehow becomes corrupted,
        //    running fastboot flash all using avbroot's extracted images isn't
        //    sufficient for recovering the device. The user will need to copy
        //    that file from the factory image into the output directory and add
        //    an `update-super` line after `reboot fastboot` the fastboot info
        //    file.
        //
        // 2. fastboot flashall does not look at all .img files in a directory.
        //    Instead, it has a hardcoded list of partitions known to AOSP. This
        //    means obscure OEM-specific partitions are just silently ignored.
        //    Using a fastboot info file with explicit flash instructions avoids
        //    this problem entirely.

        let mut dynamic = BTreeSet::new();

        if let Some(dpm) = &header.manifest.dynamic_partition_metadata {
            for group in &dpm.groups {
                for name in &group.partition_names {
                    if unique_images.contains(name) {
                        dynamic.insert(name);
                    }
                }
            }
        }

        let flash_command = |name| {
            let (prefix, suffix) = if flashable_images.contains(name) {
                ("", "")
            } else {
                ("#", " # Bootloader/modem images cannot be flashed")
            };

            let extra_arg = if *name == "vbmeta" {
                "--apply-vbmeta "
            } else {
                ""
            };

            format!("{prefix}flash {extra_arg}{name}{suffix}\n")
        };

        let mut fastboot_info = String::new();

        fastboot_info.push_str("# Generated by avbroot\n");
        fastboot_info.push_str("version 1\n");

        fastboot_info.push_str("# Flash non-dynamic partitions\n");
        for name in &unique_images {
            if !dynamic.contains(name) {
                fastboot_info.push_str(&flash_command(name));
            }
        }

        fastboot_info.push_str("# Reboot to fastbootd\n");
        fastboot_info.push_str("reboot fastboot\n");

        fastboot_info.push_str("# Flash dynamic partitions\n");
        for name in &dynamic {
            fastboot_info.push_str(&flash_command(name));
        }

        fastboot_info.push_str("# Wipe data when -w flag is used\n");
        fastboot_info.push_str("if-wipe erase userdata\n");
        fastboot_info.push_str("if-wipe erase metadata\n");

        let fastboot_info_path = util::path_join_single(&cli.directory, FASTBOOT_INFO)?;
        fs::write(&fastboot_info_path, fastboot_info)
            .with_context(|| format!("Failed to write file: {fastboot_info_path:?}"))?;
    }

    Ok(())
}

pub fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let mut errors = 0;

    macro_rules! fail_later {
        ($($arg:tt)+) => {
            error!($($arg)+);
            errors += 1;
        };
    }

    let mut reader = File::open(&cli.input)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;

    info!("Verifying whole-file signature");

    let ota_sig = ota::parse_ota_sig(&mut reader).context("Failed to parse OTA signature")?;

    if let Err(e) = ota_sig
        .verify_ota(&mut reader, cancel_signal)
        .context("Failed to verify OTA against embedded certificate")
    {
        fail_later!("{e:?}");
    }

    let (metadata, ota_cert, header, properties) =
        ota::parse_zip_ota_info(&mut reader).context("Failed to parse OTA metadata")?;
    if ota_cert != ota_sig.cert {
        fail_later!(
            "{} does not match CMS embedded certificate",
            ota::PATH_OTACERT,
        );
    } else if let Some(p) = &cli.cert_ota {
        let verify_cert = crypto::read_pem_cert_file(p)
            .with_context(|| format!("Failed to load certificate: {p:?}"))?;

        if ota_sig.cert != verify_cert {
            fail_later!("OTA has a valid signature, but was not signed with: {p:?}");
        }
    } else {
        warn!("Whole-file signature is valid, but its trust is unknown");
    }

    if let Err(e) = ota::verify_metadata(&mut reader, &metadata, header.blob_offset)
        .context("Failed to verify OTA metadata offsets")
    {
        fail_later!("{e:?}");
    }

    info!("Verifying payload");

    let pfs_raw = metadata
        .property_files
        .get(ota::PF_NAME)
        .ok_or_else(|| anyhow!("Missing property files: {}", ota::PF_NAME))?;
    let pfs = ota::parse_property_files(pfs_raw)
        .with_context(|| format!("Failed to parse property files: {}", ota::PF_NAME))?;
    let pf_payload = pfs
        .iter()
        .find(|pf| pf.name() == ota::PATH_PAYLOAD)
        .ok_or_else(|| anyhow!("Missing property files entry: {}", ota::PATH_PAYLOAD))?;

    let mut section_reader = SectionReader::new(&mut reader, pf_payload.offset, pf_payload.size)
        .context("Failed to directly open payload section")?;

    if let Err(e) = payload::verify_payload(
        &mut section_reader,
        &ota_sig.cert,
        &properties,
        cancel_signal,
    )
    .context("Failed to verify payload signatures and digests")
    {
        fail_later!("{e:?}");
    }

    info!("Extracting partition images to temporary directory");

    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let raw_reader = reader.into_inner();
    let unique_images = header
        .manifest
        .partitions
        .iter()
        .map(|p| &p.partition_name)
        .cloned()
        .collect::<BTreeSet<_>>();

    extract_payload(
        &raw_reader,
        temp_dir.path(),
        pf_payload.offset,
        pf_payload.size,
        &header,
        &unique_images,
        cancel_signal,
    )?;

    info!("Verifying partition hashes");

    if let Err(e) = verify_partition_hashes(temp_dir.path(), &header, &unique_images, cancel_signal)
    {
        fail_later!("{e:?}");
    }

    info!("Verifying AVB signatures");

    let trust_method = if let Some(p) = &cli.public_key_avb {
        let data = fs::read(p).with_context(|| format!("Failed to read file: {p:?}"))?;
        let key = avb::decode_public_key(&data)
            .with_context(|| format!("Failed to decode public key: {p:?}"))?;

        TrustMethod::Key(key)
    } else {
        TrustMethod::Anything
    };

    let opener = ImageOpener::with_dir(temp_dir.path());
    let mut seen = HashSet::<String>::new();
    let mut descriptors = HashMap::<String, Descriptor>::new();

    if let Err(e) = cli::avb::verify_headers(
        &opener,
        "vbmeta",
        &trust_method,
        &mut seen,
        &mut descriptors,
    )
    .context("Failed to verify AVB signatures")
    {
        fail_later!("{e:?}");
    }

    if let Err(e) = cli::avb::verify_descriptors(
        &opener,
        &descriptors,
        false,
        !cli.fail_if_missing,
        cancel_signal,
    )
    .context("Failed to verify images against AVB descriptors")
    {
        fail_later!("{e:?}");
    }

    info!("Checking recovery ramdisk's otacerts.zip");

    let required_images = get_required_images(&header.manifest, RequiredFlags::empty());
    let boot_image_names = required_images
        .iter()
        .filter(|(_, flags)| flags.contains(PartitionFlags::BOOT))
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();

    struct Opener<'a>(&'a Path);

    impl BootImageOpener for Opener<'_> {
        fn open_original(&self, name: &str) -> io::Result<Box<dyn ReadSeek + Sync>> {
            let path = util::path_join_single(self.0, format!("{name}.img"))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            Ok(Box::new(File::open(path)?))
        }
    }

    let (boot_images, layout) = boot::load_boot_images(&boot_image_names, &Opener(temp_dir.path()))
        .context("Failed to load all boot images")?;
    let targets = OtaCertPatcher::new(ota_cert.clone())
        .find_targets(layout, &boot_images, cancel_signal)
        .context("Failed to find boot image containing otacerts.zip")?;

    if targets.is_empty() {
        let msg = "No boot image contains otacerts.zip";

        if cli.skip_recovery_ota_cert {
            warn!("{msg}");
        } else {
            fail_later!("{msg}");
        }
    }

    for target in targets {
        let boot_image = &boot_images[target].boot_image;
        let ramdisk_certs = OtaCertPatcher::get_certificates(boot_image, cancel_signal)
            .with_context(|| format!("Failed to read {target}'s otacerts.zip"))?;

        if !ramdisk_certs.contains(&ota_cert) {
            let msg = format!(
                "{target}'s otacerts.zip does not contain the certificate that signed the OTA"
            );

            if cli.skip_recovery_ota_cert {
                warn!("{msg}");
            } else {
                fail_later!("{msg}");
            }
        }
    }

    if errors == 0 {
        info!("OK!");
    } else {
        bail!("Encountered {errors} error(s) during verification");
    }

    Ok(())
}

pub fn ota_main(cli: &OtaCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        OtaCommand::Patch(c) => patch_subcommand(c, cancel_signal),
        OtaCommand::Extract(c) => extract_subcommand(c, cancel_signal),
        OtaCommand::Verify(c) => verify_subcommand(c, cancel_signal),
    }
}

// We currently use the `conflicts_with_all` option instead of `requires`
// because the latter currently doesn't work when the dependent is an argument
// inside a group: https://github.com/clap-rs/clap/issues/4707. Even if that
// were fixed, the former option's error message is much more user friendly.

const HEADING_PATH: &str = "Path options";
const HEADING_KEY: &str = "Key options";
const HEADING_MAGISK: &str = "Magisk patch options";
const HEADING_PREPATCHED: &str = "Prepatched boot image options";
const HEADING_OTHER: &str = "Other patch options";

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct RootGroup {
    /// Path to Magisk APK.
    #[arg(long, value_name = "FILE", value_parser, help_heading = HEADING_MAGISK)]
    pub magisk: Option<PathBuf>,

    /// Path to prepatched boot image.
    #[arg(long, value_name = "FILE", value_parser, help_heading = HEADING_PREPATCHED)]
    pub prepatched: Option<PathBuf>,

    /// Skip applying root patch.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub rootless: bool,
}

/// Patch a full OTA.
#[derive(Debug, Parser)]
pub struct PatchCli {
    /// Patch to original OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser, help_heading = HEADING_PATH)]
    pub input: PathBuf,

    /// Path to new OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser, help_heading = HEADING_PATH)]
    pub output: Option<PathBuf>,

    /// Signing key for vbmeta headers.
    ///
    /// This should normally be a private key. However, if --signing-helper is
    /// used, then it should be a public key instead.
    #[arg(
        long,
        alias = "privkey-avb",
        value_name = "FILE",
        value_parser,
        help_heading = HEADING_KEY,
    )]
    pub key_avb: PathBuf,

    /// Signing key for the OTA.
    ///
    /// This should normally be a private key. However, if --signing-helper is
    /// used, then it should be a public key instead.
    #[arg(
        long,
        alias = "privkey-ota",
        value_name = "FILE",
        value_parser,
        help_heading = HEADING_KEY,
    )]
    pub key_ota: PathBuf,

    /// Certificate for OTA signing key.
    #[arg(long, value_name = "FILE", value_parser, help_heading = HEADING_KEY)]
    pub cert_ota: PathBuf,

    /// Environment variable containing AVB private key passphrase.
    #[arg(
        long,
        alias = "passphrase-avb-env-var",
        value_name = "ENV_VAR",
        value_parser,
        group = "pass_avb",
        help_heading = HEADING_KEY,
    )]
    pub pass_avb_env_var: Option<OsString>,

    /// File containing AVB private key passphrase.
    #[arg(
        long,
        alias = "passphrase-avb-file",
        value_name = "FILE",
        value_parser,
        group = "pass_avb",
        help_heading = HEADING_KEY,
    )]
    pub pass_avb_file: Option<PathBuf>,

    /// Environment variable containing OTA private key passphrase.
    #[arg(
        long,
        alias = "passphrase-ota-env-var",
        value_name = "ENV_VAR",
        value_parser,
        group = "pass_ota",
        help_heading = HEADING_KEY,
    )]
    pub pass_ota_env_var: Option<OsString>,

    /// File containing OTA private key passphrase.
    #[arg(
        long,
        alias = "passphrase-ota-file",
        value_name = "FILE",
        value_parser,
        group = "pass_ota",
        help_heading = HEADING_KEY,
    )]
    pub pass_ota_file: Option<PathBuf>,

    /// External program for signing.
    ///
    /// If this option is specified, then --key-avb and --key-ota must refer to
    /// public keys. The program will be invoked as:
    ///
    /// <program> <algo> <public key> [file <pass file>|env <pass env>]
    #[arg(long, value_name = "PROGRAM", value_parser, help_heading = HEADING_KEY)]
    pub signing_helper: Option<PathBuf>,

    /// Use partition image from a file instead of the original payload.
    #[arg(
        long,
        value_names = ["PARTITION", "FILE"],
        value_parser = value_parser!(OsString),
        num_args = 2,
        help_heading = HEADING_PATH,
    )]
    pub replace: Vec<OsString>,

    #[command(flatten)]
    pub root: RootGroup,

    /// Magisk preinit block device (version >=25211 only).
    #[arg(
        long,
        value_name = "PARTITION",
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK,
    )]
    pub magisk_preinit_device: Option<String>,

    /// Magisk random seed (version >=25211, <26103 only).
    #[arg(
        long,
        value_name = "NUMBER",
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK,
    )]
    pub magisk_random_seed: Option<u64>,

    /// Ignore Magisk compatibility/version warnings.
    #[arg(
        long,
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK,
    )]
    pub ignore_magisk_warnings: bool,

    /// Ignore compatibility issues with prepatched boot images.
    #[arg(
        long,
        action = ArgAction::Count,
        conflicts_with_all = ["magisk", "rootless"],
        help_heading = HEADING_PREPATCHED,
    )]
    pub ignore_prepatched_compat: u8,

    /// Skip adding OTA certificate to system image.
    ///
    /// DO NOT USE THIS unless you've manually added the certificate to the
    /// system image already. Otherwise, installing further updates via a custom
    /// OTA updater app while booted into Android will not be possible.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub skip_system_ota_cert: bool,

    /// Skip adding OTA certificate to recovery image.
    ///
    /// DO NOT USE THIS unless you've manually added the certificate to the
    /// recovery image already. Otherwise, sideloading further updates while
    /// booted into recovery mode will not be possible.
    ///
    /// When this option is used with --rootless, the boot images in the OTA
    /// will not be modified.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub skip_recovery_ota_cert: bool,

    /// Add AVB public key to trusted keys for DSU.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub dsu: bool,

    /// Forcibly clear vbmeta flags if they disable AVB.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub clear_vbmeta_flags: bool,

    /// Override the virtual A/B CoW compression algorithm.
    ///
    /// This will slow down the patching process because every dynamic partition
    /// needs to be extracted to recompute the CoW size estimate. However, if a
    /// faster algorithm is chosen, then OTA installation using an OTA updater
    /// app will be faster. This does not affect sideloading from recovery mode.
    ///
    /// Note that selecting a newer algorithm will prevent upgrading from older
    /// Android versions before support for the algorithm was introduced.
    #[arg(long, value_name = "ALGO", help_heading = HEADING_OTHER)]
    pub vabc_algo: Option<VabcAlgo>,

    /// Zip creation mode for the output OTA zip.
    ///
    /// The streaming mode produces zip files that contain data descriptors.
    /// The zip file is hashed as it is being written. This mode is the default
    /// and works with the vast majority of devices.
    ///
    /// The seekable mode produces zip files that do not use data descriptors.
    /// The zip file is reread and hashed after it has been fully written. The
    /// output file is more likely to be compatible with devices that have
    /// broken zip file parsers.
    #[arg(
        long,
        value_name = "MODE",
        default_value_t = ZipMode::Streaming,
        help_heading = HEADING_OTHER,
    )]
    pub zip_mode: ZipMode,

    /// (Deprecated: no longer needed)
    #[arg(
        long,
        value_name = "PARTITION",
        hide = true,
        help_heading = HEADING_OTHER,
    )]
    pub boot_partition: Option<String>,
}

#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct ExtractGroup {
    /// Extract all images from the payload.
    ///
    /// By default, only images that could potentially be patched by avbroot are
    /// extracted.
    #[arg(short, long)]
    pub all: bool,

    /// Don't extract anything from the payload.
    ///
    /// This is useful for using --cert-ota and --public-key-avb without
    /// extracting any partition images.
    #[arg(short, long)]
    pub none: bool,

    /// (Deprecated: Specify an exact partition name instead.)
    #[arg(long, hide = true)]
    pub boot_only: bool,

    /// Extract specific images from the payload.
    #[arg(short, long)]
    pub partition: Vec<String>,
}

/// Extract a full OTA.
#[derive(Debug, Parser)]
pub struct ExtractCli {
    /// Path to OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub input: PathBuf,

    /// Output directory for extracted images.
    #[arg(short, long, value_parser, default_value = ".")]
    pub directory: PathBuf,

    #[command(flatten)]
    pub extract: ExtractGroup,

    /// (Deprecated: no longer needed)
    #[arg(long, value_name = "PARTITION", hide = true)]
    pub boot_partition: Option<String>,

    /// Generate fastboot info files.
    #[arg(long)]
    pub fastboot: bool,

    /// Extract OTA certificate to file.
    ///
    /// This is not extracted by default.
    #[arg(long, value_name = "FILE", value_parser)]
    pub cert_ota: Option<PathBuf>,

    /// Extract AVB public key to file.
    ///
    /// This is not extracted by default.
    #[arg(long, value_name = "FILE", value_parser)]
    pub public_key_avb: Option<PathBuf>,
}

/// Verify signatures of an OTA.
///
/// This includes both the whole-file signature and the payload signature.
#[derive(Debug, Parser)]
pub struct VerifyCli {
    /// Path to OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub input: PathBuf,

    /// Certificate for verifying the OTA signatures.
    ///
    /// If this is omitted, the check only verifies that the signatures are
    /// valid, not that they are trusted.
    #[arg(long, value_name = "FILE", value_parser)]
    pub cert_ota: Option<PathBuf>,

    /// Public key for verifying the vbmeta signatures.
    ///
    /// If this is omitted, the check only verifies that the signatures are
    /// valid, not that they are trusted.
    #[arg(long, value_name = "FILE", value_parser)]
    pub public_key_avb: Option<PathBuf>,

    /// Skip verifying OTA certificate in recovery image.
    ///
    /// This should not be used unless the OTA uses a special boot image format
    /// that avbroot cannot parse. This certificate check ensures that the OTA
    /// is configured properly to allow sideloading further OTAs signed by the
    /// same key.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub skip_recovery_ota_cert: bool,

    /// Fail if a referenced image is missing.
    ///
    /// Missing images are ignored by default because some OTAs contain vbmeta
    /// images referencing partitions that only exist on the real device.
    #[arg(long)]
    fail_if_missing: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum OtaCommand {
    Patch(PatchCli),
    Extract(ExtractCli),
    Verify(VerifyCli),
}

/// Patch or extract OTA images.
#[derive(Debug, Parser)]
pub struct OtaCli {
    #[command(subcommand)]
    command: OtaCommand,
}
