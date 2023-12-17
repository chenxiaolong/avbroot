/*
 * SPDX-FileCopyrightText: 2022-2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fmt::Display,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Mutex},
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use cap_std::{ambient_authority, fs::Dir};
use cap_tempfile::TempDir;
use clap::{value_parser, ArgAction, Args, Parser, Subcommand};
use phf::phf_map;
use rayon::{
    iter::IntoParallelRefIterator,
    prelude::{IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
};
use rsa::RsaPrivateKey;
use tempfile::NamedTempFile;
use topological_sort::TopologicalSort;
use x509_cert::Certificate;
use zip::{write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    boot::{self, BootImagePatcher, MagiskRootPatcher, OtaCertPatcher, PrepatchedImagePatcher},
    cli::{self, status, warning},
    crypto::{self, PassphraseSource},
    format::{
        avb::Header,
        avb::{self, Descriptor},
        bootimage::BootImage,
        ota::{self, SigningWriter, ZipEntry},
        padding,
        payload::{self, PayloadHeader, PayloadWriter},
    },
    protobuf::{
        build::tools::releasetools::OtaMetadata, chromeos_update_engine::DeltaArchiveManifest,
    },
    stream::{
        self, CountingWriter, FromReader, HashingWriter, HolePunchingWriter, PSeekFile,
        ReadSeekReopen, Reopen, SectionReader, ToWriter,
    },
    util,
};

static PARTITION_PRIORITIES: phf::Map<&'static str, &[&'static str]> = phf_map! {
    // The kernel is always in boot
    "@gki_kernel" => &["boot"],
    // Devices launching with Android 13 use a GKI init_boot ramdisk
    "@gki_ramdisk" => &["init_boot", "boot"],
    // OnePlus devices have a recovery image
    "@otacerts" => &["recovery", "vendor_boot", "boot"],
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

/// Get the set of partitions, grouped by type, based on the priorities listed
/// in [`PARTITION_PRIORITIES`]. The result also includes every vbmeta partition
/// prefixed with `@vbmeta:`.
pub fn get_partitions_by_type(manifest: &DeltaArchiveManifest) -> Result<HashMap<String, String>> {
    let all_partitions = manifest
        .partitions
        .iter()
        .map(|p| p.partition_name.as_str())
        .collect::<HashSet<_>>();
    let mut by_type = HashMap::new();

    for (&t, candidates) in &PARTITION_PRIORITIES {
        let &partition = candidates
            .iter()
            .find(|p| all_partitions.contains(*p))
            .ok_or_else(|| anyhow!("Cannot find partition of type: {t}"))?;

        by_type.insert(t.to_owned(), partition.to_owned());
    }

    for &partition in &all_partitions {
        if partition.contains("vbmeta") {
            by_type.insert(format!("@vbmeta:{partition}"), partition.to_owned());
        }
    }

    Ok(by_type)
}

/// Get the list of partitions, grouped by type, that need to be patched. For
/// the @vbmeta: type, this may include more partitions than necessary because
/// it's not yet known which vbmeta partitions cover the contents of the other
/// partitions.
pub fn get_required_images(
    manifest: &DeltaArchiveManifest,
    rootpatch_partition: Option<&str>,
    otacerts_partition: Option<&str>,
) -> Result<HashMap<String, String>> {
    let all_partitions = manifest
        .partitions
        .iter()
        .map(|p| p.partition_name.as_str())
        .collect::<HashSet<_>>();
    let by_type = get_partitions_by_type(manifest)?;
    let mut images = HashMap::new();

    for (k, v) in &by_type {
        if k == "@otacerts" || k.starts_with("@vbmeta:") {
            images.insert(k.clone(), v.clone());
        }
    }

    for (k, v) in [
        ("@rootpatch", rootpatch_partition),
        ("@otacerts", otacerts_partition),
    ] {
        if let Some(name) = v {
            if by_type.contains_key(name) {
                images.insert(k.to_owned(), by_type[name].clone());
            } else if all_partitions.contains(name) {
                images.insert(k.to_owned(), name.to_owned());
            } else {
                bail!("{k} partition not found: {name}");
            }
        }
    }

    Ok(images)
}

/// Open all input files listed in `required_images`. If an image has a path
/// in `external_images`, that file is opened. Otherwise, the image is extracted
/// from the payload into a temporary file (that is unnamed if supported by the
/// operating system).
fn open_input_files(
    payload: &(dyn ReadSeekReopen + Sync),
    required_images: &HashMap<String, String>,
    external_images: &HashMap<String, PathBuf>,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<HashMap<String, PSeekFile>> {
    let mut input_files = HashMap::<String, PSeekFile>::new();

    // We always include replacement images that the user specifies, even if
    // they don't need to be patched.
    let all_images = required_images
        .values()
        .chain(external_images.keys())
        .collect::<HashSet<_>>();

    for name in all_images {
        if let Some(path) = external_images.get(name) {
            status!("Opening external image: {name}: {path:?}");

            let file = File::open(path)
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to open external image: {path:?}"))?;
            input_files.insert(name.clone(), file);
        } else {
            status!("Extracting from original payload: {name}");

            let file = tempfile::tempfile()
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to create temp file for: {name}"))?;

            payload::extract_image(payload, &file, header, name, cancel_signal)
                .with_context(|| format!("Failed to extract from original payload: {name}"))?;
            input_files.insert(name.clone(), file);
        }
    }

    Ok(input_files)
}

/// Patch the boot images listed in `required_images`. An [`OtaCertPatcher`] is
/// always applied to the `@otacerts` image to insert `cert_ota` into the
/// trusted certificate list. If `root_patcher` is specified, then it is used to
/// patch the `@rootpatch` image. If the original image is signed, then it will
/// be re-signed with `key_avb`.
fn patch_boot_images(
    required_images: &HashMap<String, String>,
    input_files: &mut HashMap<String, PSeekFile>,
    root_patcher: Option<Box<dyn BootImagePatcher + Send>>,
    key_avb: &RsaPrivateKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let mut boot_patchers = HashMap::<&str, Vec<Box<dyn BootImagePatcher + Send>>>::new();
    boot_patchers
        .entry(&required_images["@otacerts"])
        .or_default()
        .push(Box::new(OtaCertPatcher::new(cert_ota.clone())));

    if let Some(p) = root_patcher {
        boot_patchers
            .entry(&required_images["@rootpatch"])
            .or_default()
            .push(p);
    }

    status!(
        "Patching boot images: {}",
        joined(sorted(boot_patchers.keys()))
    );

    // Temporarily take the files out of input_files so we can easily run the
    // patchers in parallel.
    let patchers_list = boot_patchers
        .into_iter()
        .map(|(n, p)| (n, p, input_files.remove(n).unwrap()))
        .collect::<Vec<_>>();

    // Patch the boot images. The original readers are dropped.
    let patched = patchers_list
        .into_par_iter()
        .map(|(n, p, f)| -> Result<(&str, PSeekFile)> {
            let mut new_file = tempfile::tempfile()
                .map(PSeekFile::new)
                .with_context(|| format!("Failed to create temp file for: {n}"))?;

            boot::patch_boot(f, &mut new_file, key_avb, &p, cancel_signal)
                .with_context(|| format!("Failed to patch boot image: {n}"))?;

            Ok((n, new_file))
        })
        .collect::<Result<Vec<_>>>()?;

    // Put the patched images back into input_files.
    for (name, file) in patched {
        input_files.insert(name.to_owned(), file);
    }

    Ok(())
}

/// Load the specified vbmeta image headers. If an image has a vbmeta footer,
/// then an error is returned because the vbmeta patching logic only ever writes
/// root vbmeta images.
fn load_vbmeta_images(
    images: &mut HashMap<String, PSeekFile>,
    vbmeta_images: &HashSet<String>,
) -> Result<HashMap<String, Header>> {
    let mut result = HashMap::new();

    for name in vbmeta_images {
        let reader = images.get_mut(name).unwrap();
        let (header, footer, _) = avb::load_image(reader)
            .with_context(|| format!("Failed to load vbmeta image: {name}"))?;

        if let Some(f) = footer {
            bail!("{name} is a vbmeta partition, but has a footer: {f:?}");
        }

        result.insert(name.clone(), header);
    }

    Ok(result)
}

/// Check if a partition is critical to AVB's chain of trust and is meant to be
/// validated by the bootloader instead of Android. dm-verity partitions cannot
/// be statically checked without causing false positives because the fstab
/// might be using the avb_keys=/path/to/pubkey option.
fn is_critical_to_avb(name: &str) -> bool {
    name.ends_with("boot") || name.starts_with("vbmeta")
}

/// Check that all critical partitions within the payload are protected by a
/// vbmeta image in `vbmeta_headers`.
fn ensure_partitions_protected(
    manifest: &DeltaArchiveManifest,
    vbmeta_headers: &HashMap<String, Header>,
) -> Result<()> {
    let critical_partitions = manifest
        .partitions
        .iter()
        .map(|p| &p.partition_name)
        .filter(|n| is_critical_to_avb(n))
        .cloned()
        .collect::<BTreeSet<_>>();

    // vbmeta partitions first.
    let mut avb_partitions = vbmeta_headers.keys().cloned().collect::<BTreeSet<_>>();

    // Then, everything referred to by the descriptors.
    for header in vbmeta_headers.values() {
        let partition_names = header
            .descriptors
            .iter()
            .filter_map(|d| d.partition_name())
            .map(|n| n.to_owned());

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
    images: &mut HashMap<String, PSeekFile>,
    vbmeta_headers: &HashMap<String, Header>,
) -> Result<Vec<(String, HashSet<String>)>> {
    let mut dep_graph = HashMap::<&str, HashSet<String>>::new();
    let mut missing = images.keys().cloned().collect::<BTreeSet<_>>();

    for (name, header) in vbmeta_headers {
        dep_graph.insert(name, HashSet::new());
        missing.remove(name);

        for descriptor in &header.descriptors {
            let Some(partition_name) = descriptor.partition_name() else {
                continue;
            };

            // Ignore partitions that are guaranteed to not be modified.
            if images.contains_key(partition_name) {
                dep_graph
                    .get_mut(name.as_str())
                    .unwrap()
                    .insert(partition_name.to_owned());
                missing.remove(partition_name);
            }
        }
    }

    if !missing.is_empty() {
        warning!("Partitions aren't protected by AVB: {:?}", joined(missing));
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
                pd.public_key = child_header.public_key.clone();
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
    let Some((prefix, _)) = cmdline.split_once('=') else {
        return None;
    };
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
                    pd.value = cd.value.clone();
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
                    pd.cmdline = cd.cmdline.clone();
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
    images: &mut HashMap<String, PSeekFile>,
    headers: &mut HashMap<String, Header>,
    order: &mut [(String, HashSet<String>)],
    clear_vbmeta_flags: bool,
    key: &RsaPrivateKey,
    block_size: u64,
) -> Result<()> {
    let mut unchanged = HashSet::new();

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
            let reader = images.get_mut(dep).unwrap();
            let (header, _, _) = avb::load_image(reader)
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

            *images.get_mut(name).unwrap() = writer;
        } else {
            unchanged.insert(name.as_str());
        }
    }

    // No need to package a replacement image if it's unchanged.
    for name in unchanged {
        images.remove(name);
    }

    Ok(())
}

/// Compress an image and update the OTA manifest partition entry appropriately.
fn compress_image(
    name: &str,
    file: &mut PSeekFile,
    header: &Mutex<PayloadHeader>,
    block_size: u32,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    file.rewind()?;

    let writer = tempfile::tempfile()
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to create temp file for: {name}"))?;

    let (partition_info, operations) =
        payload::compress_image(&*file, &writer, name, block_size, cancel_signal)?;

    let mut header_locked = header.lock().unwrap();
    let partition = header_locked
        .manifest
        .partitions
        .iter_mut()
        .find(|p| p.partition_name == name)
        .unwrap();

    partition.new_partition_info = Some(partition_info);
    partition.operations = operations;

    *file = writer;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn patch_ota_payload(
    payload: &(dyn ReadSeekReopen + Sync),
    writer: impl Write,
    external_images: &HashMap<String, PathBuf>,
    rootpatch_partition: Option<&str>,
    otacerts_partition: Option<&str>,
    root_patcher: Option<Box<dyn BootImagePatcher + Send>>,
    clear_vbmeta_flags: bool,
    key_avb: &RsaPrivateKey,
    key_ota: &RsaPrivateKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<(String, u64)> {
    let header = PayloadHeader::from_reader(payload.reopen_boxed()?)
        .context("Failed to load OTA payload header")?;
    if !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
    }

    let header = Mutex::new(header);
    let header_locked = header.lock().unwrap();
    let all_partitions = header_locked
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
    let required_images = get_required_images(
        &header_locked.manifest,
        rootpatch_partition,
        otacerts_partition,
    )?;
    let vbmeta_images = required_images
        .iter()
        .filter(|(n, _)| n.starts_with("@vbmeta:"))
        .map(|(_, p)| p.clone())
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
        &header_locked,
        cancel_signal,
    )?;

    patch_boot_images(
        &required_images,
        &mut input_files,
        root_patcher,
        key_avb,
        cert_ota,
        cancel_signal,
    )?;

    let mut vbmeta_headers = load_vbmeta_images(&mut input_files, &vbmeta_images)?;

    ensure_partitions_protected(&header_locked.manifest, &vbmeta_headers)?;

    let mut vbmeta_order = get_vbmeta_patch_order(&mut input_files, &vbmeta_headers)?;

    status!(
        "Patching vbmeta images: {}",
        joined(vbmeta_order.iter().map(|(n, _)| n)),
    );

    // Get rid of input readers for vbmeta partitions we don't need to modify.
    for name in &vbmeta_images {
        // Linear search is fast enough.
        if !vbmeta_order.iter().any(|v| v.0 == *name) {
            input_files.remove(name);
        }
    }

    update_vbmeta_headers(
        &mut input_files,
        &mut vbmeta_headers,
        &mut vbmeta_order,
        clear_vbmeta_flags,
        key_avb,
        header_locked.manifest.block_size().into(),
    )?;

    status!(
        "Compressing replacement images: {}",
        joined(sorted(input_files.keys())),
    );

    let block_size = header_locked.manifest.block_size();
    drop(header_locked);

    input_files
        .par_iter_mut()
        .map(|(name, file)| -> Result<()> {
            compress_image(name, file, &header, block_size, cancel_signal)
                .with_context(|| format!("Failed to compress image: {name}"))
        })
        .collect::<Result<()>>()?;

    status!("Generating new OTA payload");

    let header_locked = header.lock().unwrap();
    let mut payload_writer = PayloadWriter::new(writer, header_locked.clone(), key_ota.clone())
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
        let orig_partition = &header_locked.manifest.partitions[pi];
        let orig_operation = &orig_partition.operations[oi];
        let data_offset = orig_operation
            .data_offset
            .ok_or_else(|| anyhow!("Missing data_offset in partition #{pi} operation #{oi}"))?;

        if let Some(reader) = input_files.get_mut(&name) {
            // Copy from our replacement image. The compressed chunks are laid
            // out sequentially and data_offset is set to the offset within that
            // file.
            reader
                .seek(SeekFrom::Start(data_offset))
                .with_context(|| format!("Failed to seek image: {name}"))?;

            stream::copy_n(reader, &mut payload_writer, data_length, cancel_signal)
                .with_context(|| format!("Failed to copy from replacement image: {name}"))?;
        } else {
            // Copy from the original payload.
            let data_offset = data_offset
                .checked_add(header_locked.blob_offset)
                .ok_or_else(|| {
                    anyhow!("data_offset overflow in partition #{pi} operation #{oi}")
                })?;

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
    }

    let (_, properties, metadata_size) = payload_writer
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
    rootpatch_partition: Option<&str>,
    otacerts_partition: Option<&str>,
    mut root_patch: Option<Box<dyn BootImagePatcher + Send>>,
    clear_vbmeta_flags: bool,
    key_avb: &RsaPrivateKey,
    key_ota: &RsaPrivateKey,
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
        bail!("Missing entries in OTA zip: {:?}", joined(missing));
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
                status!("Replacing zip entry: {path}");

                crypto::write_pem_cert(&mut writer, cert_ota)
                    .with_context(|| format!("Failed to write entry: {path}"))?;
            }
            ota::PATH_PAYLOAD => {
                status!("Patching zip entry: {path}");

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
                    rootpatch_partition,
                    otacerts_partition,
                    // There's only one payload in the OTA.
                    root_patch.take(),
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
                status!("Patching zip entry: {path}");

                // payload.bin is guaranteed to be patched first.
                writer
                    .write_all(properties.as_ref().unwrap().as_bytes())
                    .with_context(|| format!("Failed to write payload properties: {path}"))?;
            }
            _ => {
                status!("Copying zip entry: {path}");

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

    status!("Generating new OTA metadata");

    let data_descriptor_size = if last_entry_used_zip64 { 24 } else { 16 };
    let metadata = ota::add_metadata(
        &entries,
        zip_writer,
        // Offset where next entry would begin.
        entries.last().map(|e| e.offset + e.size).unwrap() + data_descriptor_size,
        &metadata.unwrap(),
        payload_metadata_size.unwrap(),
    )
    .context("Failed to write new OTA metadata")?;

    Ok((metadata, payload_metadata_size.unwrap()))
}

fn extract_ota_zip(
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

    status!("Extracting from the payload: {}", joined(images));

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

    let key_avb = crypto::read_pem_key_file(&cli.key_avb, &source_avb)
        .with_context(|| format!("Failed to load key: {:?}", cli.key_avb))?;
    let key_ota = crypto::read_pem_key_file(&cli.key_ota, &source_ota)
        .with_context(|| format!("Failed to load key: {:?}", cli.key_ota))?;
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

    let root_patcher: Option<Box<dyn BootImagePatcher + Send>> = if cli.root.rootless {
        None
    } else if let Some(magisk) = &cli.root.magisk {
        let patcher = MagiskRootPatcher::new(
            magisk,
            cli.magisk_preinit_device.as_deref(),
            cli.magisk_random_seed,
            cli.ignore_magisk_warnings,
            move |s| warning!("{s}"),
        )
        .context("Failed to create Magisk boot image patcher")?;

        Some(Box::new(patcher))
    } else if let Some(prepatched) = &cli.root.prepatched {
        let patcher =
            PrepatchedImagePatcher::new(prepatched, cli.ignore_prepatched_compat + 1, move |s| {
                warning!("{s}");
            });

        Some(Box::new(patcher))
    } else {
        unreachable!()
    };

    let start = Instant::now();

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
    let hole_punching_writer = HolePunchingWriter::new(temp_writer);
    let buffered_writer = BufWriter::new(hole_punching_writer);
    let signing_writer = SigningWriter::new(buffered_writer);
    let mut zip_writer = ZipWriter::new_streaming(signing_writer);

    let (metadata, payload_metadata_size) = patch_ota_zip(
        &raw_reader,
        &mut zip_reader,
        &mut zip_writer,
        &external_images,
        Some(&cli.boot_partition),
        cli.otacerts_partition.as_deref(),
        root_patcher,
        cli.clear_vbmeta_flags,
        &key_avb,
        &key_ota,
        &cert_ota,
        cancel_signal,
    )
    .context("Failed to patch OTA zip")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let buffered_writer = signing_writer
        .finish(&key_ota, &cert_ota)
        .context("Failed to sign output zip")?;
    let hole_punching_writer = buffered_writer
        .into_inner()
        .context("Failed to flush output zip")?;
    let mut temp_writer = hole_punching_writer.into_inner();
    temp_writer.flush().context("Failed to flush output zip")?;

    // We do a lot of low-level hackery. Reopen and verify offsets.
    status!("Verifying metadata offsets");
    temp_writer.rewind().context("Failed to seek output zip")?;
    ota::verify_metadata(
        BufReader::new(&mut temp_writer),
        &metadata,
        payload_metadata_size,
    )
    .context("Failed to verify OTA metadata offsets")?;

    status!("Completed after {:.1}s", start.elapsed().as_secs_f64());

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
    let raw_reader = File::open(&cli.input)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut zip = ZipArchive::new(BufReader::new(raw_reader.reopen()?))
        .with_context(|| format!("Failed to read zip: {:?}", cli.input))?;
    let payload_entry = zip
        .by_name(ota::PATH_PAYLOAD)
        .with_context(|| format!("Failed to open zip entry: {:?}", ota::PATH_PAYLOAD))?;
    let payload_offset = payload_entry.data_start();
    let payload_size = payload_entry.size();

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
        let images = get_required_images(
            &header.manifest,
            Some(&cli.boot_partition),
            cli.otacerts_partition.as_deref(),
        )?;

        if cli.boot_only {
            unique_images.insert(images["@rootpatch"].clone());
        } else {
            unique_images.extend(images.into_values());
        }
    }

    let authority = ambient_authority();
    Dir::create_ambient_dir_all(&cli.directory, authority)
        .with_context(|| format!("Failed to create directory: {:?}", cli.directory))?;
    let directory = Dir::open_ambient_dir(&cli.directory, authority)
        .with_context(|| format!("Failed to open directory: {:?}", cli.directory))?;

    extract_ota_zip(
        &raw_reader,
        &directory,
        payload_offset,
        payload_size,
        &header,
        &unique_images,
        cancel_signal,
    )?;

    Ok(())
}

pub fn verify_subcommand(cli: &VerifyCli, cancel_signal: &AtomicBool) -> Result<()> {
    let raw_reader = File::open(&cli.input)
        .map(PSeekFile::new)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.input))?;
    let mut reader = BufReader::new(raw_reader);

    status!("Verifying whole-file signature");

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
        warning!("Whole-file signature is valid, but its trust is unknown");
    }

    ota::verify_metadata(&mut reader, &metadata, header.blob_offset)
        .context("Failed to verify OTA metadata offsets")?;

    status!("Verifying payload");

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

    status!("Extracting partition images to temporary directory");

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

    extract_ota_zip(
        &raw_reader,
        &temp_dir,
        pf_payload.offset,
        pf_payload.size,
        &header,
        &unique_images,
        cancel_signal,
    )?;

    status!("Verifying partition hashes");

    verify_partition_hashes(&temp_dir, &header, &unique_images, cancel_signal)?;

    status!("Checking ramdisk's otacerts.zip");

    let boot_image = {
        let partitions_by_type =
            get_required_images(&header.manifest, None, cli.otacerts_partition.as_deref())?;
        let path = format!("{}.img", partitions_by_type["@otacerts"]);
        let file = temp_dir
            .open(&path)
            .with_context(|| format!("Failed to open for reading: {path:?}"))?;
        BootImage::from_reader(BufReader::new(file))
            .with_context(|| format!("Failed to read boot image: {path:?}"))?
    };

    let ramdisk_certs = OtaCertPatcher::get_certificates(&boot_image, cancel_signal)
        .context("Failed to read ramdisk's otacerts.zip")?;
    if !ramdisk_certs.contains(&ota_cert) {
        bail!("Ramdisk's otacerts.zip does not contain OTA certificate");
    }

    status!("Verifying AVB signatures");

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

    status!("Signatures are all valid!");

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

    /// Private key for signing vbmeta images.
    #[arg(
        long,
        alias = "privkey-avb",
        value_name = "FILE",
        value_parser,
        help_heading = HEADING_KEY
    )]
    pub key_avb: PathBuf,

    /// Private key for signing the OTA.
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

    /// Forcibly clear vbmeta flags if they disable AVB.
    #[arg(long, help_heading = HEADING_OTHER)]
    pub clear_vbmeta_flags: bool,

    /// Boot partition name.
    #[arg(
        long,
        value_name = "PARTITION",
        default_value = "@gki_ramdisk",
        help_heading = HEADING_OTHER
    )]
    pub boot_partition: String,

    /// OTA certificates partition name.
    #[arg(
        long,
        value_name = "PARTITION",
        help_heading = HEADING_OTHER
    )]
    pub otacerts_partition: Option<String>,
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

    /// Boot partition name.
    #[arg(long, value_name = "PARTITION", default_value = "@gki_ramdisk")]
    pub boot_partition: String,

    /// OTA certificates partition name.
    #[arg(long, value_name = "PARTITION")]
    pub otacerts_partition: Option<String>,
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

    /// OTA certificates partition name.
    #[arg(long, value_name = "PARTITION")]
    pub otacerts_partition: Option<String>,
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
