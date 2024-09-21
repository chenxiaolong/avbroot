/*
 * SPDX-FileCopyrightText: 2022-2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fmt::Display,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    mem,
    ops::Range,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Mutex},
};

use anyhow::{anyhow, bail, Context, Result};
use cap_std::{ambient_authority, fs::Dir};
use cap_tempfile::TempDir;
use clap::{value_parser, ArgAction, Args, Parser, Subcommand};
use rayon::{iter::IntoParallelRefIterator, prelude::ParallelIterator};
use tempfile::NamedTempFile;
use topological_sort::TopologicalSort;
use tracing::{debug_span, info, warn};
use x509_cert::Certificate;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    cli,
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::{
        avb::{self, Descriptor, Header},
        ota::{self, SigningWriter, ZipEntry, ZipMode},
        padding,
        payload::{self, PayloadHeader, PayloadWriter, VabcAlgo},
    },
    patch::{
        boot::{
            self, BootImagePatch, DsuPubKeyPatcher, MagiskRootPatcher, OtaCertPatcher,
            PrepatchedImagePatcher,
        },
        system,
    },
    protobuf::{
        build::tools::releasetools::OtaMetadata, chromeos_update_engine::DeltaArchiveManifest,
    },
    stream::{
        self, CountingWriter, FromReader, HashingWriter, PSeekFile, ReadSeekReopen, Reopen,
        SectionReader, ToWriter, WriteSeekReopen,
    },
    util,
};

fn joined(into_iter: impl IntoIterator<Item = impl Display>) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    for (i, item) in into_iter.into_iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }

        write!(result, "{item}").expect("Failed to allocate");
    }

    result
}

fn sorted<T: Ord>(iter: impl Iterator<Item = T>) -> Vec<T> {
    let mut items = iter.collect::<Vec<_>>();
    items.sort();
    items
}

pub struct RequiredImages(HashSet<String>);

impl RequiredImages {
    pub fn new(manifest: &DeltaArchiveManifest) -> Self {
        let partitions = manifest
            .partitions
            .iter()
            .map(|p| p.partition_name.clone())
            .filter(|n| Self::is_boot(n) || Self::is_system(n) || Self::is_vbmeta(n))
            .collect();

        Self(partitions)
    }

    pub fn is_boot(name: &str) -> bool {
        name == "boot" || name == "init_boot" || name == "recovery" || name == "vendor_boot"
    }

    pub fn is_system(name: &str) -> bool {
        name == "system"
    }

    pub fn is_vbmeta(name: &str) -> bool {
        name.starts_with("vbmeta")
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|n| n.as_str())
    }

    pub fn iter_boot(&self) -> impl Iterator<Item = &str> {
        self.iter().filter(|n| Self::is_boot(n))
    }

    pub fn iter_system(&self) -> impl Iterator<Item = &str> {
        self.iter().filter(|n| Self::is_system(n))
    }

    pub fn iter_vbmeta(&self) -> impl Iterator<Item = &str> {
        self.iter().filter(|n| Self::is_vbmeta(n))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputFileState {
    External,
    Extracted,
    Modified,
}

struct InputFile {
    file: PSeekFile,
    state: InputFileState,
}

/// Open all input files listed in `required_images`. If an image has a path
/// in `external_images`, that file is opened. Otherwise, the image is extracted
/// from the payload into a temporary file (that is unnamed if supported by the
/// operating system).
fn open_input_files(
    payload: &(dyn ReadSeekReopen + Sync),
    required_images: &RequiredImages,
    external_images: &HashMap<String, PathBuf>,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<HashMap<String, InputFile>> {
    let mut input_files = HashMap::<String, InputFile>::new();

    // We always include replacement images that the user specifies, even if
    // they don't need to be patched.
    let all_images = required_images
        .iter()
        .chain(external_images.keys().map(|k| k.as_str()))
        .collect::<HashSet<_>>();

    for name in all_images {
        let _span = debug_span!("image", name).entered();

        if let Some(path) = external_images.get(name) {
            info!("Opening external image: {name}: {path:?}");

            let file = File::open(path)
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to open external image: {path:?}"))?;
            input_files.insert(
                name.to_owned(),
                InputFile {
                    file,
                    state: InputFileState::External,
                },
            );
        } else {
            info!("Extracting from original payload: {name}");

            let file = tempfile::tempfile()
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to create temp file for: {name}"))?;

            payload::extract_image(payload, &file, header, name, cancel_signal)
                .with_context(|| format!("Failed to extract from original payload: {name}"))?;
            input_files.insert(
                name.to_owned(),
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
fn patch_boot_images<'a, 'b: 'a>(
    required_images: &'b RequiredImages,
    input_files: &mut HashMap<String, InputFile>,
    boot_patchers: Vec<Box<dyn BootImagePatch + Sync>>,
    key_avb: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let input_files = Mutex::new(input_files);
    let boot_partitions = required_images.iter_boot().collect::<Vec<_>>();

    info!(
        "Patching boot images: {}",
        joined(sorted(boot_partitions.iter())),
    );

    boot::patch_boot_images(
        &boot_partitions,
        |name| {
            let locked = input_files.lock().unwrap();
            ReadSeekReopen::reopen_boxed(&locked[name].file)
        },
        |name| {
            let mut locked = input_files.lock().unwrap();
            let input_file = locked.get_mut(name).unwrap();
            input_file.file = tempfile::tempfile().map(PSeekFile::new)?;
            input_file.state = InputFileState::Modified;
            WriteSeekReopen::reopen_boxed(&input_file.file)
        },
        key_avb,
        &boot_patchers,
        cancel_signal,
    )
    .with_context(|| {
        format!(
            "Failed to patch boot images: {}",
            joined(sorted(boot_partitions.iter())),
        )
    })?;

    Ok(())
}

/// Patch the single system image listed in `required_images` to replace the
/// `otacerts.zip` contents.
fn patch_system_image<'a, 'b: 'a>(
    required_images: &'b RequiredImages,
    input_files: &mut HashMap<String, InputFile>,
    cert_ota: &Certificate,
    key_avb: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<(&'b str, Vec<Range<u64>>)> {
    let Some(target) = required_images.iter_system().next() else {
        bail!("No system partition found");
    };

    let _span = debug_span!("image", name = target).entered();

    info!("Patching system image: {target}");

    let input_file = input_files.get_mut(target).unwrap();

    // We can't modify external files in place.
    if input_file.state == InputFileState::External {
        let mut reader = input_file.file.reopen()?;
        let mut writer = tempfile::tempfile()
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to create temp file for: {target}"))?;

        stream::copy(&mut reader, &mut writer, cancel_signal)?;

        input_file.file = writer;
        input_file.state = InputFileState::Extracted;
    }

    let (mut ranges, other_ranges) = system::patch_system_image(
        &input_file.file,
        &input_file.file,
        cert_ota,
        key_avb,
        cancel_signal,
    )
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
    required_images: &RequiredImages,
    vbmeta_headers: &HashMap<String, Header>,
) -> Result<()> {
    let critical_partitions = required_images
        .iter_boot()
        .chain(required_images.iter_vbmeta())
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
            joined(missing),
        );
    }

    Ok(())
}

/// From the set of input images (modified partitions + all vbmeta partitions),
/// determine the order to patch the vbmeta images so that it can be done in a
/// single pass.
fn get_vbmeta_patch_order(
    images: &mut HashMap<String, InputFile>,
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
                missing.remove(partition_name);
            }
        }
    }

    if !missing.is_empty() {
        warn!("Partitions aren't protected by AVB: {}", joined(missing));
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
        bail!("Found multiple root vbmeta images: {}", joined(roots));
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
                bail!("{child_name} descriptor ({child_type}) does not match entry in {parent_name} ({parent_type})");
            }
        }
    } else {
        // vbmeta is signed; Use a chain descriptor.
        match parent_descriptor {
            Descriptor::ChainPartition(pd) => {
                child_header.public_key.clone_into(&mut pd.public_key);
            }
            _ => {
                bail!("{child_name} descriptor ({parent_type}) in {parent_name} must be a chain descriptor");
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
        if parent_header != &orig_parent_header {
            parent_header.set_algo_for_key(key)?;
            parent_header
                .sign(key)
                .with_context(|| format!("Failed to sign vbmeta header for image: {name}"))?;

            let mut writer = tempfile::tempfile()
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to create temp file for: {name}"))?;
            parent_header
                .to_writer(&mut writer)
                .with_context(|| format!("Failed to write vbmeta image: {name}"))?;

            padding::write_zeros(&mut writer, block_size)
                .with_context(|| format!("Failed to write vbmeta padding: {name}"))?;

            let input_file = images.get_mut(name).unwrap();
            input_file.file = writer;
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
    file: &mut PSeekFile,
    header: &mut PayloadHeader,
    ranges: Option<&[Range<u64>]>,
    cancel_signal: &AtomicBool,
) -> Result<Vec<Range<usize>>> {
    let _span = debug_span!("image", name).entered();

    file.rewind()?;

    let writer = tempfile::tempfile()
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to create temp file for: {name}"))?;

    let block_size = header.manifest.block_size();
    let partition = header
        .manifest
        .partitions
        .iter_mut()
        .find(|p| p.partition_name == name)
        .unwrap();

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
                *file = writer;
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

    // Otherwise, compress the entire image. If VABC is enabled, we need to
    // update the CoW size estimate or else the CoW block device may run out of
    // space during flashing.
    let vabc_algo = if partition.estimate_cow_size.is_some() {
        info!("Needs updated CoW size estimate: {name}");

        // Only CoW v2 seems to exist in the wild currently, so that is all we
        // support.
        let Some(dpm) = &header.manifest.dynamic_partition_metadata else {
            bail!("Dynamic partition metadata is missing");
        };

        if !dpm.vabc_enabled() {
            bail!("Partition has CoW estimate, but VABC is disabled: {name}");
        }

        let cow_version = dpm.cow_version();
        if dpm.cow_version() != 2 {
            bail!("Unsupported CoW version: {cow_version}");
        }

        let compression = dpm.vabc_compression_param();
        let Some(vabc_algo) = VabcAlgo::new(compression) else {
            bail!("Unsupported VABC compression: {compression}");
        };

        Some(vabc_algo)
    } else {
        None
    };

    let (partition_info, operations, cow_estimate) =
        payload::compress_image(&*file, &writer, name, block_size, vabc_algo, cancel_signal)?;

    partition.new_partition_info = Some(partition_info);
    partition.operations = operations;
    partition.estimate_cow_size = cow_estimate;

    *file = writer;

    #[allow(clippy::single_range_in_vec_init)]
    Ok(vec![0..partition.operations.len()])
}

#[allow(clippy::too_many_arguments)]
fn patch_ota_payload(
    payload: &(dyn ReadSeekReopen + Sync),
    writer: impl Write,
    external_images: &HashMap<String, PathBuf>,
    boot_patchers: Vec<Box<dyn BootImagePatch + Sync>>,
    clear_vbmeta_flags: bool,
    key_avb: &RsaSigningKey,
    key_ota: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<(String, u64)> {
    let mut header = PayloadHeader::from_reader(payload.reopen_boxed()?)
        .context("Failed to load OTA payload header")?;
    if !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
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

    // Determine what images need to be patched. For simplicity, we pre-read all
    // vbmeta images since they're tiny. They're discarded later if the they
    // don't need to be modified.
    let required_images = RequiredImages::new(&header.manifest);
    let vbmeta_images = required_images.iter_vbmeta().collect::<HashSet<_>>();

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

    // Main patching operation is done. Unmodified boot images no longer need to
    // be kept around.
    input_files
        .retain(|n, f| !(f.state == InputFileState::Extracted && RequiredImages::is_boot(n)));

    let (system_target, system_ranges) = patch_system_image(
        &required_images,
        &mut input_files,
        cert_ota,
        key_avb,
        cancel_signal,
    )?;

    let mut vbmeta_headers = load_vbmeta_images(&mut input_files, &vbmeta_images)?;

    ensure_partitions_protected(&required_images, &vbmeta_headers)?;

    let mut vbmeta_order = get_vbmeta_patch_order(&mut input_files, &vbmeta_headers)?;

    info!(
        "Patching vbmeta images: {}",
        joined(vbmeta_order.iter().map(|(n, _)| n)),
    );

    update_vbmeta_headers(
        &mut input_files,
        &mut vbmeta_headers,
        &mut vbmeta_order,
        clear_vbmeta_flags,
        key_avb,
        header.manifest.block_size().into(),
    )?;

    // Unmodified vbmeta images no longer need to be kept around either.
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
                if name == system_target && !external_images.contains_key(&name) {
                    Some(&system_ranges)
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
    let mut orig_payload_reader = payload.reopen_boxed().context("Failed to open payload")?;

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
        if let Some((input_file, modified_operations)) = compressed_files.get_mut(&name) {
            if util::ranges_contains(modified_operations, &oi) {
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
    raw_reader: &PSeekFile,
    zip_reader: &mut ZipArchive<impl Read + Seek>,
    mut zip_writer: &mut ZipWriter<impl Write>,
    external_images: &HashMap<String, PathBuf>,
    mut boot_patchers: Vec<Box<dyn BootImagePatch + Sync>>,
    clear_vbmeta_flags: bool,
    zip_mode: ZipMode,
    key_avb: &RsaSigningKey,
    key_ota: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<(OtaMetadata, u64)> {
    let mut missing = BTreeSet::from([ota::PATH_OTACERT, ota::PATH_PAYLOAD, ota::PATH_PROPERTIES]);

    // Keep in sorted order for reproducibility and to guarantee that the
    // payload is processed before its properties file.
    let paths = zip_reader
        .file_names()
        .map(|p| p.to_owned())
        .collect::<BTreeSet<_>>();

    for path in &paths {
        missing.remove(path.as_str());
    }

    if !missing.is_empty() {
        bail!("Missing entries in OTA zip: {}", joined(missing));
    } else if !paths.contains(ota::PATH_METADATA) && !paths.contains(ota::PATH_METADATA_PB) {
        bail!(
            "Neither legacy nor protobuf OTA metadata files exist: {:?}, {:?}",
            ota::PATH_METADATA,
            ota::PATH_METADATA_PB,
        )
    }

    let mut metadata = None;
    let mut properties = None;
    let mut payload_metadata_size = None;
    let mut entries = vec![];
    let mut last_entry_used_zip64 = false;

    for path in &paths {
        let _span = debug_span!("zip", entry = path).entered();

        let mut reader = zip_reader
            .by_name(path)
            .with_context(|| format!("Failed to open zip entry: {path}"))?;

        // Android's libarchive parser is broken and only reads data descriptor
        // size fields as 64-bit integers if the central directory says the file
        // size is >= 2^32 - 1. We'll turn on zip64 if the input is above this
        // threshold. This should be sufficient since the output file is likely
        // to be larger.
        let use_zip64 = reader.size() >= 0xffffffff;
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(use_zip64);

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

        // All remaining entries are written immediately.
        zip_writer
            .start_file_with_extra_data(path, options)
            .with_context(|| format!("Failed to begin new zip entry: {path}"))?;
        let offset = zip_writer
            .end_extra_data()
            .with_context(|| format!("Failed to end new zip entry: {path}"))?;
        let mut writer = CountingWriter::new(&mut zip_writer);

        match path.as_str() {
            ota::PATH_OTACERT => {
                // Use the user's certificate
                info!("Replacing zip entry: {path}");

                crypto::write_pem_cert(&mut writer, cert_ota)
                    .with_context(|| format!("Failed to write entry: {path}"))?;
            }
            ota::PATH_PAYLOAD => {
                info!("Patching zip entry: {path}");

                if reader.compression() != CompressionMethod::Stored {
                    bail!("{path} is not stored uncompressed");
                }

                // The zip library doesn't provide us with a seekable reader, so
                // we make our own from the underlying file.
                let payload_reader = SectionReader::new(
                    BufReader::new(raw_reader.reopen()?),
                    reader.data_start(),
                    reader.size(),
                )?;

                let (p, m) = patch_ota_payload(
                    &payload_reader,
                    &mut writer,
                    external_images,
                    // There's only one payload in the OTA.
                    mem::take(&mut boot_patchers),
                    clear_vbmeta_flags,
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
                writer
                    .write_all(properties.as_ref().unwrap().as_bytes())
                    .with_context(|| format!("Failed to write payload properties: {path}"))?;
            }
            _ => {
                info!("Copying zip entry: {path}");

                stream::copy(&mut reader, &mut writer, cancel_signal)
                    .with_context(|| format!("Failed to copy zip entry: {path}"))?;
            }
        }

        // Cannot fail.
        let size = writer.stream_position()?;

        entries.push(ZipEntry {
            name: path.clone(),
            offset,
            size,
        });

        last_entry_used_zip64 = use_zip64;
    }

    info!("Generating new OTA metadata");

    let data_descriptor_size = match zip_mode {
        ZipMode::Streaming => {
            if last_entry_used_zip64 {
                24
            } else {
                16
            }
        }
        ZipMode::Seekable => 0,
    };
    let metadata = ota::add_metadata(
        &entries,
        zip_writer,
        // Offset where next entry would begin.
        entries.last().map(|e| e.offset + e.size).unwrap() + data_descriptor_size,
        &metadata.unwrap(),
        payload_metadata_size.unwrap(),
        zip_mode,
    )
    .context("Failed to write new OTA metadata")?;

    Ok((metadata, payload_metadata_size.unwrap()))
}

pub fn extract_payload(
    raw_reader: &PSeekFile,
    directory: &Dir,
    payload_offset: u64,
    payload_size: u64,
    header: &PayloadHeader,
    images: &BTreeSet<String>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    for name in images {
        if Path::new(name).file_name() != Some(OsStr::new(name)) {
            bail!("Unsafe partition name: {name}");
        }
    }

    info!("Extracting from the payload: {}", joined(images));

    // Pre-open all output files.
    let output_files = images
        .iter()
        .map(|name| {
            let path = format!("{name}.img");
            let file = directory
                .create(&path)
                .map(|f| PSeekFile::new(f.into_std()))
                .with_context(|| format!("Failed to open for writing: {path:?}"))?;
            Ok((name.as_str(), file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    let payload_reader = SectionReader::new(
        BufReader::new(raw_reader.reopen()?),
        payload_offset,
        payload_size,
    )?;

    // Extract the images. Each time we're asked to open a new file, we just
    // clone the relevant PSeekFile. We only ever have one actual kernel file
    // descriptor for each file.
    payload::extract_images(
        &payload_reader,
        |name| Ok(Box::new(BufWriter::new(output_files[name].reopen()?))),
        header,
        images.iter().map(|n| n.as_str()),
        cancel_signal,
    )
    .context("Failed to extract images from payload")?;

    info!("Successfully extracted OTA");

    Ok(())
}

fn verify_partition_hashes(
    directory: &Dir,
    header: &PayloadHeader,
    images: &BTreeSet<String>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    images
        .par_iter()
        .map(|name| -> Result<()> {
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

            let path = format!("{name}.img");
            let file = directory
                .open(&path)
                .with_context(|| format!("Failed to open for reading: {path:?}"))?;

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
        .collect()
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
    };

    boot_patchers.push(Box::new(OtaCertPatcher::new(cert_ota.clone())));

    if cli.dsu {
        boot_patchers.push(Box::new(DsuPubKeyPatcher::new(key_avb.to_public_key())));
    }

    let raw_reader = File::open(&cli.input)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut zip_reader = ZipArchive::new(BufReader::new(raw_reader.reopen()?))
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
    let mut zip_writer = match cli.zip_mode {
        ZipMode::Streaming => {
            let signing_writer = SigningWriter::new_streaming(temp_writer);
            ZipWriter::new_streaming(signing_writer)
        }
        ZipMode::Seekable => {
            let signing_writer = SigningWriter::new_seekable(temp_writer);
            ZipWriter::new(signing_writer)
        }
    };

    let (metadata, payload_metadata_size) = patch_ota_zip(
        &raw_reader,
        &mut zip_reader,
        &mut zip_writer,
        &external_images,
        boot_patchers,
        cli.clear_vbmeta_flags,
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
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut zip = ZipArchive::new(BufReader::new(raw_reader.reopen()?))
        .with_context(|| format!("Failed to read zip: {:?}", cli.input))?;
    let (payload_offset, payload_size) = {
        let entry = zip
            .by_name(ota::PATH_PAYLOAD)
            .with_context(|| format!("Failed to open zip entry: {}", ota::PATH_PAYLOAD))?;
        (entry.data_start(), entry.size())
    };

    // Open the payload data directly.
    let mut payload_reader = SectionReader::new(
        BufReader::new(raw_reader.reopen()?),
        payload_offset,
        payload_size,
    )
    .context("Failed to directly open payload section")?;

    let header = PayloadHeader::from_reader(&mut payload_reader)
        .context("Failed to load OTA payload header")?;
    if !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
    }

    let mut unique_images = BTreeSet::new();

    if cli.all {
        unique_images.extend(
            header
                .manifest
                .partitions
                .iter()
                .map(|p| &p.partition_name)
                .cloned(),
        );
    } else {
        let images = RequiredImages::new(&header.manifest);

        if cli.boot_only {
            unique_images.extend(images.iter_boot().map(|n| n.to_owned()));
        } else {
            unique_images.extend(images.iter().map(|n| n.to_owned()));
        }
    }

    let authority = ambient_authority();
    Dir::create_ambient_dir_all(&cli.directory, authority)
        .with_context(|| format!("Failed to create directory: {:?}", cli.directory))?;
    let directory = Dir::open_ambient_dir(&cli.directory, authority)
        .with_context(|| format!("Failed to open directory: {:?}", cli.directory))?;

    extract_payload(
        &raw_reader,
        &directory,
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

        let mut metadata_entry = zip
            .by_name(ota::PATH_METADATA_PB)
            .with_context(|| format!("Failed to open zip entry: {:?}", ota::PATH_METADATA_PB))?;
        let mut metadata_raw = vec![];
        metadata_entry
            .read_to_end(&mut metadata_raw)
            .with_context(|| format!("Failed to read OTA metadata: {}", ota::PATH_METADATA_PB))?;
        let metadata = ota::parse_protobuf_metadata(&metadata_raw)
            .with_context(|| format!("Failed to parse OTA metadata: {}", ota::PATH_METADATA_PB))?;

        let device = metadata
            .precondition
            .as_ref()
            .and_then(|p| p.device.first())
            .ok_or_else(|| anyhow!("Device codename not found in OTA metadata"))?;

        directory
            .write(ANDROID_INFO, format!("require board={device}\n"))
            .with_context(|| format!("Failed to write file: {ANDROID_INFO}"))?;

        // Find out which images can be flashed with fastboot. The bootloader
        // (and potentially modem) partitions need to be flashed as a whole and
        // an OTA doesn't contain sufficient information to generate the
        // required combined file.
        let mut flashable_images = BTreeSet::new();

        for name in &unique_images {
            let file = directory
                .open(format!("{name}.img"))
                .with_context(|| format!("Failed to open image for reading: {name}"))?;

            match avb::load_image(file) {
                Ok(_) => {
                    flashable_images.insert(name);
                }
                // Treat images without AVB metadata as bootloader partitions.
                Err(avb::Error::InvalidHeaderMagic(_)) => continue,
                Err(e) => return Err(e).with_context(|| format!("Failed to load image: {name}")),
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

        directory
            .write(FASTBOOT_INFO, fastboot_info)
            .with_context(|| format!("Failed to write file: {FASTBOOT_INFO}"))?;
    }

    Ok(())
}

pub fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let raw_reader = File::open(&cli.input)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut reader = BufReader::new(raw_reader);

    info!("Verifying whole-file signature");

    let embedded_cert = ota::verify_ota(&mut reader, cancel_signal)?;

    let (metadata, ota_cert, header, properties) = ota::parse_zip_ota_info(&mut reader)?;
    if embedded_cert != ota_cert {
        bail!(
            "CMS embedded certificate does not match {}",
            ota::PATH_OTACERT,
        );
    } else if let Some(p) = &cli.cert_ota {
        let verify_cert = crypto::read_pem_cert_file(p)
            .with_context(|| format!("Failed to load certificate: {:?}", p))?;

        if embedded_cert != verify_cert {
            bail!("OTA has a valid signature, but was not signed with: {p:?}");
        }
    } else {
        warn!("Whole-file signature is valid, but its trust is unknown");
    }

    ota::verify_metadata(&mut reader, &metadata, header.blob_offset)
        .context("Failed to verify OTA metadata offsets")?;

    info!("Verifying payload");

    let pfs_raw = metadata
        .property_files
        .get(ota::PF_NAME)
        .ok_or_else(|| anyhow!("Missing property files: {}", ota::PF_NAME))?;
    let pfs = ota::parse_property_files(pfs_raw)
        .with_context(|| format!("Failed to parse property files: {}", ota::PF_NAME))?;
    let pf_payload = pfs
        .iter()
        .find(|pf| pf.name == ota::PATH_PAYLOAD)
        .ok_or_else(|| anyhow!("Missing property files entry: {}", ota::PATH_PAYLOAD))?;

    let section_reader = SectionReader::new(&mut reader, pf_payload.offset, pf_payload.size)
        .context("Failed to directly open payload section")?;

    payload::verify_payload(section_reader, &ota_cert, &properties, cancel_signal)?;

    info!("Extracting partition images to temporary directory");

    let authority = ambient_authority();
    let temp_dir = TempDir::new(authority).context("Failed to create temporary directory")?;
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
        &temp_dir,
        pf_payload.offset,
        pf_payload.size,
        &header,
        &unique_images,
        cancel_signal,
    )?;

    info!("Verifying partition hashes");

    verify_partition_hashes(&temp_dir, &header, &unique_images, cancel_signal)?;

    info!("Checking ramdisk's otacerts.zip");

    {
        let required_images = RequiredImages::new(&header.manifest);
        let boot_images =
            boot::load_boot_images(&required_images.iter_boot().collect::<Vec<_>>(), |name| {
                Ok(Box::new(
                    temp_dir
                        .open(format!("{name}.img"))
                        .map(|f| PSeekFile::new(f.into_std()))?,
                ))
            })
            .context("Failed to load all boot images")?;
        let targets = OtaCertPatcher::new(ota_cert.clone())
            .find_targets(&boot_images, cancel_signal)
            .context("Failed to find boot image containing otacerts.zip")?;

        if targets.is_empty() {
            bail!("No boot image contains otacerts.zip");
        }

        for target in targets {
            let boot_image = &boot_images[target].boot_image;
            let ramdisk_certs = OtaCertPatcher::get_certificates(boot_image, cancel_signal)
                .context("Failed to read {target}'s otacerts.zip")?;

            if !ramdisk_certs.contains(&ota_cert) {
                bail!("{target}'s otacerts.zip does not contain OTA certificate");
            }
        }
    }

    info!("Verifying AVB signatures");

    let public_key = if let Some(p) = &cli.public_key_avb {
        let data = fs::read(p).with_context(|| format!("Failed to read file: {p:?}"))?;
        let key = avb::decode_public_key(&data)
            .with_context(|| format!("Failed to decode public key: {p:?}"))?;

        Some(key)
    } else {
        None
    };

    let mut seen = HashSet::<String>::new();
    let mut descriptors = HashMap::<String, Descriptor>::new();

    cli::avb::verify_headers(
        &temp_dir,
        "vbmeta",
        public_key.as_ref(),
        &mut seen,
        &mut descriptors,
    )?;
    cli::avb::verify_descriptors(&temp_dir, &descriptors, false, cancel_signal)?;

    info!("Signatures are all valid!");

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

/// Patch a full OTA zip.
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
        help_heading = HEADING_KEY
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
        help_heading = HEADING_KEY
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
        help_heading = HEADING_KEY
    )]
    pub pass_avb_env_var: Option<OsString>,

    /// File containing AVB private key passphrase.
    #[arg(
        long,
        alias = "passphrase-avb-file",
        value_name = "FILE",
        value_parser,
        group = "pass_avb",
        help_heading = HEADING_KEY
    )]
    pub pass_avb_file: Option<PathBuf>,

    /// Environment variable containing OTA private key passphrase.
    #[arg(
        long,
        alias = "passphrase-ota-env-var",
        value_name = "ENV_VAR",
        value_parser,
        group = "pass_ota",
        help_heading = HEADING_KEY
    )]
    pub pass_ota_env_var: Option<OsString>,

    /// File containing OTA private key passphrase.
    #[arg(
        long,
        alias = "passphrase-ota-file",
        value_name = "FILE",
        value_parser,
        group = "pass_ota",
        help_heading = HEADING_KEY
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
        help_heading = HEADING_PATH
    )]
    pub replace: Vec<OsString>,

    #[command(flatten)]
    pub root: RootGroup,

    /// Magisk preinit block device (version >=25211 only).
    #[arg(
        long,
        value_name = "PARTITION",
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK
    )]
    pub magisk_preinit_device: Option<String>,

    /// Magisk random seed (version >=25211, <26103 only).
    #[arg(
        long,
        value_name = "NUMBER",
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK
    )]
    pub magisk_random_seed: Option<u64>,

    /// Ignore Magisk compatibility/version warnings.
    #[arg(
        long,
        conflicts_with_all = ["prepatched", "rootless"],
        help_heading = HEADING_MAGISK
    )]
    pub ignore_magisk_warnings: bool,

    /// Ignore compatibility issues with prepatched boot images.
    #[arg(
        long,
        action = ArgAction::Count,
        conflicts_with_all = ["magisk", "rootless"],
        help_heading = HEADING_PREPATCHED
    )]
    pub ignore_prepatched_compat: u8,

    /// Add AVB public key to trusted keys for DSU.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub dsu: bool,

    /// Forcibly clear vbmeta flags if they disable AVB.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub clear_vbmeta_flags: bool,

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
        help_heading = HEADING_OTHER
    )]
    pub zip_mode: ZipMode,

    /// (Deprecated: no longer needed)
    #[arg(
        long,
        value_name = "PARTITION",
        hide = true,
        help_heading = HEADING_OTHER
    )]
    pub boot_partition: Option<String>,
}

/// Extract partition images from an OTA zip's payload.
#[derive(Debug, Parser)]
pub struct ExtractCli {
    /// Path to OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub input: PathBuf,

    /// Output directory for extracted images.
    #[arg(short, long, value_parser, default_value = ".")]
    pub directory: PathBuf,

    /// Extract all images from the payload.
    #[arg(short, long, group = "extract")]
    pub all: bool,

    /// Extract only the boot image.
    #[arg(long, group = "extract")]
    pub boot_only: bool,

    /// (Deprecated: no longer needed)
    #[arg(long, value_name = "PARTITION", hide = true)]
    pub boot_partition: Option<String>,

    /// Generate fastboot info files.
    #[arg(long)]
    pub fastboot: bool,
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
