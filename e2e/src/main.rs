// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-FileCopyrightText: 2023 Pascal Roeleven
// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod config;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    cli::ota::{ExtractCli, PatchCli, VerifyCli},
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::{
        avb::{
            self, AlgorithmType, ChainPartitionDescriptor, Descriptor, Footer, HashDescriptor,
            HashTreeDescriptor, Header, PropertyDescriptor,
        },
        bootimage::{
            self, BootImage, BootImageV0Through2, BootImageV3Through4, RamdiskMeta, V1Extra,
            V2Extra, V4Extra, VendorBootImageV3Through4, VendorV4Extra,
        },
        compression::{CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{self, CpioEntry, CpioEntryData},
        ota::{self, SigningWriter, ZipEntry, ZipMode},
        padding,
        payload::{self, CowVersion, PayloadHeader, PayloadWriter, VabcParams},
    },
    patch::otacert::{self, OtaCertBuildFlags},
    protobuf::{
        build::tools::releasetools::{ota_metadata::OtaType, DeviceState, OtaMetadata},
        chromeos_update_engine::{
            DeltaArchiveManifest, DynamicPartitionGroup, DynamicPartitionMetadata, PartitionUpdate,
        },
    },
    stream::{self, CountingWriter, FromReader, HashingReader, PSeekFile, Reopen, ToWriter},
};
use clap::Parser;
use rsa::{rand_core::OsRng, traits::PublicKeyParts, BigUint};
use tempfile::TempDir;
use topological_sort::TopologicalSort;
use tracing::{info, info_span};
use x509_cert::Certificate;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

use crate::{
    cli::{Cli, Command, HelperCli, ListCli, PassSource, ProfileGroup, TestCli},
    config::{
        Avb, BootData, BootVersion, Config, Data, DmVerityContent, DmVerityData, OtaInfo,
        Partition, Profile, RamdiskContent, VbmetaData,
    },
};

fn hash_file(path: &Path, cancel_signal: &AtomicBool) -> Result<[u8; 32]> {
    info!("Calculating hash: {path:?}");

    let raw_reader =
        File::open(path).with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let buf_reader = BufReader::new(raw_reader);
    let context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut hashing_reader = HashingReader::new(buf_reader, context);

    stream::copy(&mut hashing_reader, io::sink(), cancel_signal)?;

    let (_, context) = hashing_reader.finish();
    let digest = context.finish();

    Ok(digest.as_ref().try_into().unwrap())
}

fn verify_hash(path: &Path, sha256: &[u8; 32], cancel_signal: &AtomicBool) -> Result<()> {
    let digest = hash_file(path, cancel_signal)?;

    if sha256 != digest.as_ref() {
        bail!(
            "Expected sha256 {}, but have {}: {path:?}",
            hex::encode(sha256),
            hex::encode(digest),
        );
    }

    Ok(())
}

fn append_avb(
    file: &mut PSeekFile,
    name: &str,
    avb: Avb,
    hash_tree: bool,
    ota_info: &OtaInfo,
    key_avb: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let image_size = file.seek(SeekFrom::End(0))?;
    let salt = ring::digest::digest(&ring::digest::SHA256, b"avbroot");
    let descriptors = vec![
        if hash_tree {
            let mut descriptor = HashTreeDescriptor {
                dm_verity_version: 1,
                image_size,
                tree_offset: 0,
                tree_size: 0,
                data_block_size: 4096,
                hash_block_size: 4096,
                fec_num_roots: 2,
                fec_offset: 0,
                fec_size: 0,
                hash_algorithm: "sha256".to_owned(),
                partition_name: name.to_owned(),
                salt: salt.as_ref().to_vec(),
                root_digest: Vec::new(),
                flags: 0,
                reserved: [0u8; 60],
            };

            descriptor.update(file, file, None, cancel_signal)?;

            Descriptor::HashTree(descriptor)
        } else {
            let mut descriptor = HashDescriptor {
                image_size,
                hash_algorithm: "sha256".to_owned(),
                partition_name: name.to_owned(),
                salt: salt.as_ref().to_vec(),
                root_digest: Vec::new(),
                flags: 0,
                reserved: [0u8; 60],
            };

            file.rewind()?;
            descriptor.update(&mut *file, cancel_signal)?;

            Descriptor::Hash(descriptor)
        },
        Descriptor::Property(PropertyDescriptor {
            key: format!("com.android.build.{name}.os_version"),
            value: ota_info.android_version.clone().into(),
        }),
        Descriptor::Property(PropertyDescriptor {
            key: format!("com.android.build.{name}.fingerprint"),
            value: ota_info.fingerprint.clone().into(),
        }),
        Descriptor::Property(PropertyDescriptor {
            key: format!("com.android.build.{name}.security_patch"),
            value: ota_info.security_patch_level.clone().into(),
        }),
    ];

    let mut header = Header {
        required_libavb_version_major: avb::VERSION_MAJOR,
        required_libavb_version_minor: avb::VERSION_MINOR,
        algorithm_type: AlgorithmType::None,
        hash: Vec::new(),
        signature: Vec::new(),
        public_key: Vec::new(),
        public_key_metadata: Vec::new(),
        descriptors,
        rollback_index: 0,
        flags: 0,
        rollback_index_location: 0,
        release_string: "avbroot".to_owned(),
        reserved: [0u8; 80],
    };

    if avb.signed {
        header.set_algo_for_key(key_avb)?;
        header.sign(key_avb)?;
    }

    let mut footer = Footer {
        version_major: avb::FOOTER_VERSION_MAJOR,
        version_minor: avb::FOOTER_VERSION_MINOR,
        original_image_size: image_size,
        vbmeta_offset: 0,
        vbmeta_size: 0,
        reserved: Default::default(),
    };

    let eof_size = file.seek(SeekFrom::End(0))?;
    let full_image_size = eof_size
        .checked_add(8192)
        .and_then(|s| padding::round(s, 4096))
        .ok_or_else(|| anyhow!("Image size {image_size} is too large"))?
        // Give enough free space for changes from patching.
        .max(1024 * 1024);

    avb::write_appended_image(file, &header, &mut footer, Some(full_image_size))?;

    Ok(())
}

fn ramdisk_add_init(entries: &mut Vec<CpioEntry>) {
    entries.push(CpioEntry::new_file(
        b"init",
        0o755,
        CpioEntryData::Data(vec![]),
    ));
}

fn ramdisk_add_otacerts(entries: &mut Vec<CpioEntry>, cert_ota: &Certificate) -> Result<()> {
    for path in [
        b"system".as_slice(),
        b"system/etc".as_slice(),
        b"system/etc/security".as_slice(),
    ] {
        entries.push(CpioEntry::new_directory(path, 0o755));
    }

    entries.push(CpioEntry::new_file(
        b"system/etc/security/otacerts.zip",
        0o644,
        CpioEntryData::Data(otacert::create_zip(cert_ota, OtaCertBuildFlags::empty())?),
    ));

    Ok(())
}

fn ramdisk_add_first_stage(entries: &mut Vec<CpioEntry>) {
    entries.push(CpioEntry::new_directory(b"first_stage_ramdisk", 0o755));
}

fn ramdisk_add_dsu_key_dir(entries: &mut Vec<CpioEntry>) {
    entries.push(CpioEntry::new_directory(b"first_stage_ramdisk/avb", 0o755));
}

fn ramdisk_add_dlkm(entries: &mut Vec<CpioEntry>) {
    for path in [b"lib".as_slice(), b"lib/modules".as_slice()] {
        entries.push(CpioEntry::new_directory(path, 0o755));
    }

    for path in [
        b"lib/modules/foo.ko".as_slice(),
        b"lib/modules/bar.ko".as_slice(),
    ] {
        entries.push(CpioEntry::new_file(
            path,
            0o644,
            CpioEntryData::Data(vec![]),
        ));
    }
}

fn create_ramdisk(
    content_list: &[RamdiskContent],
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<Vec<u8>> {
    let mut entries = vec![];

    for content in content_list {
        match content {
            RamdiskContent::Init => {
                ramdisk_add_init(&mut entries);
            }
            RamdiskContent::Otacerts => {
                ramdisk_add_otacerts(&mut entries, cert_ota)?;
            }
            RamdiskContent::FirstStage => {
                ramdisk_add_first_stage(&mut entries);
            }
            RamdiskContent::DsuKeyDir => {
                ramdisk_add_dsu_key_dir(&mut entries);
            }
            RamdiskContent::Dlkm => {
                ramdisk_add_dlkm(&mut entries);
            }
        }
    }

    cpio::sort(&mut entries);

    let raw_writer = Cursor::new(Vec::new());
    let mut writer = CompressedWriter::new(raw_writer, CompressedFormat::Lz4Legacy)?;

    cpio::save(&mut writer, &entries, false, cancel_signal)?;

    let raw_writer = writer.finish()?;

    Ok(raw_writer.into_inner())
}

#[allow(clippy::too_many_arguments)]
fn create_boot_image(
    file: &mut PSeekFile,
    name: &str,
    avb: Avb,
    boot_data: &BootData,
    ota_info: &OtaInfo,
    key_avb: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let kernel = if boot_data.kernel {
        b"kernel".to_vec()
    } else {
        Vec::new()
    };
    let ramdisks = boot_data
        .ramdisks
        .iter()
        .map(|c| create_ramdisk(c, cert_ota, cancel_signal))
        .collect::<Result<Vec<_>>>()?;

    let boot_image = match boot_data.version {
        BootVersion::V2 => {
            if ramdisks.len() > 1 {
                bail!("v2 boot images can have at most one ramdisk");
            }

            BootImage::V0Through2(BootImageV0Through2 {
                kernel_addr: 0,
                ramdisk_addr: 0,
                second_addr: 0,
                tags_addr: 0,
                page_size: 4096,
                os_version: 0,
                name: String::new(),
                cmdline: String::new(),
                id: Default::default(),
                extra_cmdline: String::new(),
                kernel,
                ramdisk: ramdisks.into_iter().next().unwrap_or_default(),
                second: Vec::new(),
                v1_extra: Some(V1Extra {
                    recovery_dtbo_offset: 0,
                    recovery_dtbo: Vec::new(),
                }),
                v2_extra: Some(V2Extra {
                    dtb_addr: 0,
                    dtb: Vec::new(),
                }),
            })
        }
        BootVersion::V3 | BootVersion::V4 => {
            if ramdisks.len() > 1 {
                bail!("v3/v4 boot images can have at most one ramdisk");
            }

            let v4_extra = if boot_data.version == BootVersion::V4 {
                Some(V4Extra { signature: None })
            } else {
                None
            };

            BootImage::V3Through4(BootImageV3Through4 {
                os_version: 0,
                reserved: Default::default(),
                cmdline: String::new(),
                v4_extra,
                kernel,
                ramdisk: ramdisks.into_iter().next().unwrap_or_default(),
            })
        }
        BootVersion::VendorV3 | BootVersion::VendorV4 => {
            if boot_data.version == BootVersion::VendorV3 && ramdisks.len() > 1 {
                bail!("Vendor v3 boot images can have at most one ramdisk");
            }

            let v4_extra = if boot_data.version == BootVersion::VendorV4 {
                Some(VendorV4Extra {
                    ramdisk_metas: boot_data
                        .ramdisks
                        .iter()
                        .map(|c_list| {
                            if c_list.iter().any(|c| *c == RamdiskContent::Dlkm) {
                                RamdiskMeta {
                                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_DLKM,
                                    ramdisk_name: "dlkm".to_owned(),
                                    board_id: Default::default(),
                                }
                            } else {
                                RamdiskMeta {
                                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_PLATFORM,
                                    ramdisk_name: String::new(),
                                    board_id: Default::default(),
                                }
                            }
                        })
                        .collect(),
                    bootconfig: String::new(),
                })
            } else {
                None
            };

            BootImage::VendorV3Through4(VendorBootImageV3Through4 {
                page_size: 2048,
                kernel_addr: 0,
                ramdisk_addr: 0,
                cmdline: String::new(),
                tags_addr: 0,
                name: String::new(),
                dtb: Vec::new(),
                dtb_addr: 0,
                ramdisks,
                v4_extra,
            })
        }
    };

    boot_image.to_writer(&mut *file)?;

    append_avb(file, name, avb, false, ota_info, key_avb, cancel_signal)
        .with_context(|| format!("Failed to append AVB metadata for {name}"))?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_dm_verity_image(
    file: &mut PSeekFile,
    name: &str,
    avb: Avb,
    dm_verity_data: DmVerityData,
    ota_info: &OtaInfo,
    key_avb: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    match dm_verity_data.content {
        DmVerityContent::SystemOtacerts => {
            file.write_all(b"arbitrary_prefix")?;

            let data = otacert::create_zip(cert_ota, OtaCertBuildFlags::empty())?;
            file.write_all(&data)?;

            file.write_all(b"arbitrary_suffix")?;
        }
    }

    padding::write_zeros(&mut *file, 4096)?;

    append_avb(file, name, avb, true, ota_info, key_avb, cancel_signal)
        .with_context(|| format!("Failed to append AVB metadata for {name}"))?;

    Ok(())
}

fn create_vbmeta_image(
    file: &mut PSeekFile,
    name: &str,
    avb: Avb,
    vbmeta_data: &VbmetaData,
    inputs: &BTreeMap<String, PSeekFile>,
    key: &RsaSigningKey,
) -> Result<()> {
    let mut descriptors = Vec::new();

    for dep in &vbmeta_data.deps {
        let reader = inputs[dep].reopen()?;
        let (child_header, _, _) =
            avb::load_image(reader).with_context(|| format!("Failed to parse AVB image: {dep}"))?;

        if child_header.public_key.is_empty() {
            descriptors.extend(child_header.descriptors);
        } else {
            descriptors.push(Descriptor::ChainPartition(ChainPartitionDescriptor {
                rollback_index_location: 0,
                partition_name: dep.to_owned(),
                public_key: child_header.public_key,
                flags: 0,
                reserved: [0u8; 60],
            }));
        }
    }

    let mut header = Header {
        required_libavb_version_major: avb::VERSION_MAJOR,
        required_libavb_version_minor: avb::VERSION_MINOR,
        algorithm_type: AlgorithmType::None,
        hash: Vec::new(),
        signature: Vec::new(),
        public_key: Vec::new(),
        public_key_metadata: Vec::new(),
        descriptors,
        rollback_index: 0,
        flags: 0,
        rollback_index_location: 0,
        release_string: String::new(),
        reserved: [0u8; 80],
    };

    if avb.signed {
        header.set_algo_for_key(key)?;
        header.sign(key)?;
    }

    avb::write_root_image(file, &header, 4096)
        .with_context(|| format!("Failed to create vbmeta image: {name}"))?;

    Ok(())
}

fn create_partition_images(
    partitions: &BTreeMap<String, Partition>,
    ota_info: &OtaInfo,
    key_avb: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<BTreeMap<String, PSeekFile>> {
    let mut topo = TopologicalSort::<&String>::new();

    for (name, partition) in partitions {
        if let Data::Vbmeta(data) = &partition.data {
            for dep in &data.deps {
                topo.add_dependency(dep, name);
            }
        }
    }

    let mut files = BTreeMap::new();

    while !topo.is_empty() {
        let Some(name) = topo.pop() else {
            bail!("vbmeta dependency graph has cycle: {topo:?}");
        };
        let partition = &partitions[name];

        let mut file = tempfile::tempfile()
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to create temp file for {name}"))?;

        match &partition.data {
            Data::Boot(data) => {
                create_boot_image(
                    &mut file,
                    name,
                    partition.avb,
                    data,
                    ota_info,
                    key_avb,
                    cert_ota,
                    cancel_signal,
                )
                .with_context(|| format!("Failed to create boot image: {name}"))?;
            }
            Data::DmVerity(data) => {
                create_dm_verity_image(
                    &mut file,
                    name,
                    partition.avb,
                    *data,
                    ota_info,
                    key_avb,
                    cert_ota,
                    cancel_signal,
                )
                .with_context(|| format!("Failed to create dm-verity image: {name}"))?;
            }
            Data::Vbmeta(data) => {
                create_vbmeta_image(&mut file, name, partition.avb, data, &files, key_avb)
                    .with_context(|| format!("Failed to create vbmeta image: {name}"))?;
            }
        }

        files.insert(name.clone(), file);
    }

    Ok(files)
}

fn create_payload(
    writer: impl Write,
    partitions: &BTreeMap<String, Partition>,
    inputs: &BTreeMap<String, PSeekFile>,
    ota_info: &OtaInfo,
    profile: &Profile,
    key_ota: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<(String, u64)> {
    const COMPRESSION_FACTOR: u32 = 64 * 1024;

    let dynamic_partitions_names = partitions
        .iter()
        .filter(|(_, p)| matches!(&p.data, Data::DmVerity(_)))
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>();

    let mut payload_partitions = vec![];
    let mut compressed = BTreeMap::<&String, PSeekFile>::new();

    for (name, file) in inputs {
        let writer = tempfile::tempfile()
            .map(PSeekFile::new)
            .with_context(|| format!("Failed to create temp file for: {name}"))?;

        let vabc_params = if dynamic_partitions_names.contains(name) {
            profile.vabc.map(|v| VabcParams {
                version: v.version,
                algo: v.algo,
                compression_factor: COMPRESSION_FACTOR,
            })
        } else {
            None
        };

        let (partition_info, operations, cow_estimate) =
            payload::compress_image(file, &writer, name, 4096, vabc_params, cancel_signal)?;

        compressed.insert(name, writer);

        let is_v3 = profile.vabc.is_some_and(|e| e.version == CowVersion::V3);

        payload_partitions.push(PartitionUpdate {
            partition_name: name.clone(),
            run_postinstall: None,
            postinstall_path: None,
            filesystem_type: None,
            new_partition_signature: vec![],
            old_partition_info: None,
            new_partition_info: Some(partition_info),
            operations,
            postinstall_optional: None,
            hash_tree_data_extent: None,
            hash_tree_extent: None,
            hash_tree_algorithm: None,
            hash_tree_salt: None,
            fec_data_extent: None,
            fec_extent: None,
            fec_roots: None,
            version: None,
            merge_operations: vec![],
            estimate_cow_size: cow_estimate.map(|e| e.size),
            estimate_op_count_max: cow_estimate.and_then(|e| is_v3.then_some(e.num_ops)),
        });
    }

    let header = PayloadHeader {
        version: 2,
        manifest: DeltaArchiveManifest {
            block_size: Some(4096),
            signatures_offset: None,
            signatures_size: None,
            minor_version: Some(0),
            partitions: payload_partitions,
            max_timestamp: None,
            dynamic_partition_metadata: Some(DynamicPartitionMetadata {
                groups: vec![DynamicPartitionGroup {
                    name: "avbroot_dynamic_partitions".to_string(),
                    size: Some(1024 * 1024 * 1024),
                    partition_names: dynamic_partitions_names,
                }],
                snapshot_enabled: Some(true),
                // Everything below is meant to be unset if VABC is not
                // supported.
                vabc_enabled: profile.vabc.map(|_| true),
                vabc_compression_param: profile.vabc.map(|v| v.algo.to_string()),
                cow_version: profile.vabc.map(|v| match v.version {
                    CowVersion::V2 => 2,
                    CowVersion::V3 => 3,
                }),
                vabc_feature_set: None,
                compression_factor: profile.vabc.map(|_| COMPRESSION_FACTOR.into()),
            }),
            partial_update: None,
            apex_info: vec![],
            security_patch_level: Some(ota_info.security_patch_level.clone()),
        },
        metadata_signature_size: 0,
        blob_offset: 0,
    };

    let mut payload_writer = PayloadWriter::new(writer, header.clone(), key_ota.clone())
        .context("Failed to write payload header")?;

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

        let file = compressed.get_mut(&name).unwrap();
        file.seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek image: {name}"))?;

        stream::copy_n(file, &mut payload_writer, data_length, cancel_signal)
            .with_context(|| format!("Failed to copy from image: {name}"))?;
    }

    let (_, _, properties, metadata_size) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    Ok((properties, metadata_size))
}

#[allow(clippy::too_many_arguments)]
fn create_ota(
    output: &Path,
    ota_info: &OtaInfo,
    profile: &Profile,
    zip_mode: ZipMode,
    key_avb: &RsaSigningKey,
    key_ota: &RsaSigningKey,
    cert_ota: &Certificate,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    info!("Generating OTA: {output:?}");

    let inputs = create_partition_images(
        &profile.partitions,
        ota_info,
        key_avb,
        cert_ota,
        cancel_signal,
    )?;

    let raw_writer = OpenOptions::new()
        .read(zip_mode == ZipMode::Seekable)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)
        .with_context(|| format!("Failed to open for writing: {output:?}"))?;
    let mut zip_writer = match zip_mode {
        ZipMode::Streaming => {
            let signing_writer = SigningWriter::new_streaming(raw_writer);
            ZipWriter::new_streaming(signing_writer)
        }
        ZipMode::Seekable => {
            let signing_writer = SigningWriter::new_seekable(raw_writer);
            ZipWriter::new(signing_writer)
        }
    };
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(false);

    let mut entries = vec![];
    let mut properties = None;
    let mut payload_metadata_size = None;

    for path in [ota::PATH_OTACERT, ota::PATH_PAYLOAD, ota::PATH_PROPERTIES] {
        // All remaining entries are written immediately.
        zip_writer
            .start_file_with_extra_data(path, options)
            .with_context(|| format!("Failed to begin new zip entry: {path}"))?;
        let offset = zip_writer
            .end_extra_data()
            .with_context(|| format!("Failed to end new zip entry: {path}"))?;
        let mut writer = CountingWriter::new(&mut zip_writer);

        match path {
            ota::PATH_OTACERT => {
                crypto::write_pem_cert(Path::new(path), &mut writer, cert_ota)
                    .with_context(|| format!("Failed to write entry: {path}"))?;
            }
            ota::PATH_PAYLOAD => {
                let (p, m) = create_payload(
                    &mut writer,
                    &profile.partitions,
                    &inputs,
                    ota_info,
                    profile,
                    key_ota,
                    cancel_signal,
                )
                .context("Failed to create payload")?;

                properties = Some(p);
                payload_metadata_size = Some(m);
            }
            ota::PATH_PROPERTIES => {
                writer
                    .write_all(properties.as_ref().unwrap().as_bytes())
                    .with_context(|| format!("Failed to write payload properties: {path}"))?;
            }
            _ => unreachable!(),
        }

        // Cannot fail.
        let size = writer.stream_position()?;

        entries.push(ZipEntry {
            name: path.to_owned(),
            offset,
            size,
        });
    }

    let metadata = OtaMetadata {
        r#type: OtaType::Ab.into(),
        wipe: false,
        downgrade: false,
        property_files: BTreeMap::new(),
        precondition: Some(DeviceState {
            device: vec![ota_info.device.clone()],
            build: vec![],
            build_incremental: String::new(),
            timestamp: 0,
            sdk_level: String::new(),
            security_patch_level: String::new(),
            partition_state: vec![],
        }),
        postcondition: Some(DeviceState {
            device: vec![ota_info.device.clone()],
            build: vec![ota_info.fingerprint.clone()],
            build_incremental: ota_info.incremental_version.clone(),
            timestamp: 0,
            sdk_level: ota_info.sdk_version.clone(),
            security_patch_level: ota_info.security_patch_level.clone(),
            partition_state: vec![],
        }),
        retrofit_dynamic_partitions: false,
        required_cache: 0,
        spl_downgrade: false,
    };

    let data_descriptor_size = match zip_mode {
        ZipMode::Streaming => 16,
        ZipMode::Seekable => 0,
    };
    ota::add_metadata(
        &entries,
        &mut zip_writer,
        // Offset where next entry would begin.
        entries.last().map(|e| e.offset + e.size).unwrap() + data_descriptor_size,
        &metadata,
        payload_metadata_size.unwrap(),
        zip_mode,
    )
    .context("Failed to write new OTA metadata")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let mut buffered_writer = signing_writer
        .finish(key_ota, cert_ota, cancel_signal)
        .context("Failed to sign output zip")?;
    buffered_writer
        .flush()
        .context("Failed to flush output zip")?;

    Ok(())
}

fn create_fake_magisk(output: &Path) -> Result<()> {
    let raw_writer =
        File::create(output).with_context(|| format!("Failed to open for writing: {output:?}"))?;
    let mut zip_writer = ZipWriter::new(raw_writer);

    for path in [
        "assets/stub.apk",
        "lib/arm64-v8a/libinit-ld.so",
        "lib/arm64-v8a/libmagisk64.so",
        "lib/arm64-v8a/libmagiskinit.so",
        "lib/armeabi-v7a/libinit-ld.so",
        "lib/armeabi-v7a/libmagisk32.so",
        "lib/armeabi-v7a/libmagiskinit.so",
        "lib/x86/libinit-ld.so",
        "lib/x86/libmagisk32.so",
        "lib/x86/libmagiskinit.so",
        "lib/x86_64/libinit-ld.so",
        "lib/x86_64/libmagisk64.so",
        "lib/x86_64/libmagiskinit.so",
    ] {
        zip_writer.start_file(path, FileOptions::default())?;
        write!(zip_writer, "dummy contents for {path}")?;
    }

    // avbroot looks for the version number in this file.
    zip_writer.start_file("assets/util_functions.sh", FileOptions::default())?;
    zip_writer.write_all(b"MAGISK_VER_CODE=27000\n")?;

    Ok(())
}

struct KeySet {
    avb_key: RsaSigningKey,
    ota_key: RsaSigningKey,
    ota_cert: Certificate,
    _key_dir: TempDir,
    avb_key_file: PathBuf,
    avb_public_key_file: PathBuf,
    avb_pass_file: PathBuf,
    avb_pkmd_file: PathBuf,
    ota_key_file: PathBuf,
    ota_public_key_file: PathBuf,
    ota_pass_file: PathBuf,
    ota_cert_file: PathBuf,
}

macro_rules! new_keys_with_prefix {
    ($name:ident, $prefix:expr) => {
        fn $name() -> Result<Self> {
            let avb_key = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "avb.key",
            ));
            let avb_pass = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "avb.passphrase",
            ));
            let avb_pkmd = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "avb_pkmd.bin",
            ));
            let ota_key = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "ota.key",
            ));
            let ota_pass = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "ota.passphrase",
            ));
            let ota_cert = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/keys/",
                $prefix,
                "ota.crt",
            ));

            Self::new_with_data(avb_key, avb_pass, avb_pkmd, ota_key, ota_pass, ota_cert)
        }
    };
}

impl KeySet {
    fn write(path: &Path, data: &[u8]) -> Result<()> {
        fs::write(path, data).with_context(|| format!("Failed to write test key data: {path:?}"))
    }

    fn new_with_data(
        avb_key: &[u8],
        avb_pass: &[u8],
        avb_pkmd: &[u8],
        ota_key: &[u8],
        ota_pass: &[u8],
        ota_cert: &[u8],
    ) -> Result<Self> {
        let key_dir = TempDir::new().context("Failed to create temp directory")?;
        let avb_key_file = key_dir.path().join("avb.key");
        let avb_public_key_file = key_dir.path().join("avb.public.key");
        let avb_pass_file = key_dir.path().join("avb.passphrase");
        let avb_pkmd_file = key_dir.path().join("avb_pkmd.bin");
        let ota_key_file = key_dir.path().join("ota.key");
        let ota_public_key_file = key_dir.path().join("ota.public.key");
        let ota_pass_file = key_dir.path().join("ota.passphrase");
        let ota_cert_file = key_dir.path().join("ota.crt");

        Self::write(&avb_key_file, avb_key)?;
        Self::write(&avb_pass_file, avb_pass)?;
        Self::write(&avb_pkmd_file, avb_pkmd)?;
        Self::write(&ota_key_file, ota_key)?;
        Self::write(&ota_pass_file, ota_pass)?;
        Self::write(&ota_cert_file, ota_cert)?;

        let avb_key = crypto::read_pem_key_file(
            &avb_key_file,
            &PassphraseSource::File(avb_pass_file.clone()),
        )
        .map(RsaSigningKey::Internal)
        .context("Failed to load AVB test key")?;

        let ota_key = crypto::read_pem_key_file(
            &ota_key_file,
            &PassphraseSource::File(ota_pass_file.clone()),
        )
        .map(RsaSigningKey::Internal)
        .context("Failed to load OTA test key")?;

        crypto::write_pem_public_key_file(&avb_public_key_file, &avb_key.to_public_key())?;
        crypto::write_pem_public_key_file(&ota_public_key_file, &ota_key.to_public_key())?;

        let ota_cert =
            crypto::read_pem_cert_file(&ota_cert_file).context("Failed to load OTA test cert")?;

        Ok(Self {
            avb_key,
            ota_key,
            ota_cert,
            _key_dir: key_dir,
            avb_key_file,
            avb_public_key_file,
            avb_pass_file,
            avb_pkmd_file,
            ota_key_file,
            ota_public_key_file,
            ota_pass_file,
            ota_cert_file,
        })
    }

    new_keys_with_prefix!(new_for_orig, "ORIG_KEY_DO_NOT_USE_");
    new_keys_with_prefix!(new_for_test, "TEST_KEY_DO_NOT_USE_");
}

#[allow(clippy::too_many_arguments)]
fn patch_image(
    input_file: &Path,
    output_file: &Path,
    system_image_file: &Path,
    zip_mode: ZipMode,
    extra_args: &[&OsStr],
    keys: &KeySet,
    signing_helper: bool,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    info!("Patching OTA: {input_file:?} -> {output_file:?}");

    let (avb_key_file, ota_key_file) = if signing_helper {
        (&keys.avb_public_key_file, &keys.ota_public_key_file)
    } else {
        (&keys.avb_key_file, &keys.ota_key_file)
    };

    let zip_mode_arg = zip_mode.to_string();

    // We're intentionally using the CLI interface.
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("patch"),
        OsStr::new("--input"),
        input_file.as_os_str(),
        OsStr::new("--output"),
        output_file.as_os_str(),
        OsStr::new("--replace"),
        OsStr::new("system"),
        system_image_file.as_os_str(),
        OsStr::new("--key-avb"),
        avb_key_file.as_os_str(),
        OsStr::new("--pass-avb-file"),
        keys.avb_pass_file.as_os_str(),
        OsStr::new("--key-ota"),
        ota_key_file.as_os_str(),
        OsStr::new("--pass-ota-file"),
        keys.ota_pass_file.as_os_str(),
        OsStr::new("--cert-ota"),
        keys.ota_cert_file.as_os_str(),
        OsStr::new("--dsu"),
        OsStr::new("--zip-mode"),
        OsStr::new(&zip_mode_arg),
    ];

    let argv0: OsString;
    if signing_helper {
        argv0 = env::args_os().next().unwrap();
        args.push(OsStr::new("--signing-helper"));
        args.push(&argv0);
    }

    args.extend_from_slice(extra_args);

    let cli = PatchCli::try_parse_from(args)?;
    avbroot::cli::ota::patch_subcommand(&cli, cancel_signal)?;

    Ok(())
}

fn extract_image(input_file: &Path, output_dir: &Path, cancel_signal: &AtomicBool) -> Result<()> {
    info!("Extracting AVB partitions: {input_file:?} -> {output_dir:?}");

    let cli = ExtractCli::try_parse_from([
        OsStr::new("extract"),
        OsStr::new("--input"),
        input_file.as_os_str(),
        OsStr::new("--directory"),
        output_dir.as_os_str(),
    ])?;
    avbroot::cli::ota::extract_subcommand(&cli, cancel_signal)?;

    Ok(())
}

fn verify_image(input_file: &Path, keys: &KeySet, cancel_signal: &AtomicBool) -> Result<()> {
    info!("Verifying signatures: {input_file:?}");

    let cli = VerifyCli::try_parse_from([
        OsStr::new("verify"),
        OsStr::new("--input"),
        input_file.as_os_str(),
        OsStr::new("--public-key-avb"),
        keys.avb_pkmd_file.as_os_str(),
        OsStr::new("--cert-ota"),
        keys.ota_cert_file.as_os_str(),
    ])?;
    avbroot::cli::ota::verify_subcommand(&cli, cancel_signal)?;

    Ok(())
}

fn clean_boot_image_certs(path: &Path, cancel_signal: &AtomicBool) -> Result<()> {
    info!("Removing OTA certs and DSU public keys: {path:?}");

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut boot_image = BootImage::from_reader(&mut file)?;

    let ramdisks = match &mut boot_image {
        BootImage::V0Through2(b) => slice::from_mut(&mut b.ramdisk),
        BootImage::V3Through4(b) => slice::from_mut(&mut b.ramdisk),
        BootImage::VendorV3Through4(b) => &mut b.ramdisks,
    };

    if ramdisks.is_empty() {
        bail!("No ramdisk found: {path:?}");
    }

    let raw_ramdisk_reader = Cursor::new(&ramdisks[0]);
    let ramdisk_reader = CompressedReader::new(raw_ramdisk_reader, false)?;
    let ramdisk_format = ramdisk_reader.format();
    let mut entries = cpio::load(ramdisk_reader, false, cancel_signal)?;

    // Wipe out OTA certificates.
    if let Some(entry) = entries
        .iter_mut()
        .find(|e| e.path == b"system/etc/security/otacerts.zip")
    {
        let mut zip_writer = ZipWriter::new(Cursor::new(Vec::new()));
        let empty_zip = zip_writer.finish()?.into_inner();

        entry.data = CpioEntryData::Data(empty_zip);
    }

    // Wipe out DSU public keys.
    entries.retain(|e| !e.path.starts_with(b"first_stage_ramdisk/avb/"));

    let raw_ramdisk_writer = Cursor::new(Vec::new());
    let mut ramdisk_writer = CompressedWriter::new(raw_ramdisk_writer, ramdisk_format)?;
    cpio::save(&mut ramdisk_writer, &entries, false, cancel_signal)?;

    let raw_ramdisk_writer = ramdisk_writer.finish()?;
    ramdisks[0] = raw_ramdisk_writer.into_inner();

    // We're creating an input for --prepatched, so no need for AVB metadata.
    file.set_len(0)?;
    file.rewind()?;
    boot_image.to_writer(&mut file)?;

    Ok(())
}

fn filter_profiles<'a>(config: &'a Config, cli: &'a ProfileGroup) -> Result<BTreeSet<&'a str>> {
    let mut profiles = config
        .profile
        .keys()
        .map(|n| n.as_str())
        .collect::<BTreeSet<_>>();

    if !cli.all {
        let invalid = cli
            .profile
            .iter()
            .filter(|d| !profiles.contains(d.as_str()))
            .collect::<BTreeSet<_>>();
        if !invalid.is_empty() {
            bail!("Invalid profiles: {invalid:?}");
        }

        profiles = cli.profile.iter().map(|d| d.as_str()).collect();
    }

    Ok(profiles)
}

fn test_subcommand(cli: &TestCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (config, _) = config::load_config(&cli.config.config)?;
    let profiles = filter_profiles(&config, &cli.profile)?;

    if profiles.is_empty() {
        bail!("No profiles selected");
    }

    let orig_keys = KeySet::new_for_orig()?;
    let test_keys = KeySet::new_for_test()?;

    let work_temp_dir = match &cli.config.work_dir {
        Some(_) => None,
        None => Some(TempDir::new().context("Failed to create temp directory")?),
    };
    #[allow(clippy::option_if_let_else)]
    let work_dir = match &cli.config.work_dir {
        Some(w) => w.as_path(),
        None => work_temp_dir.as_ref().unwrap().path(),
    };
    let magisk_file = work_dir.join("magisk.apk");

    fs::create_dir_all(work_dir)
        .with_context(|| format!("Failed to create directory: {work_dir:?}"))?;

    create_fake_magisk(&magisk_file).context("Failed to create fake Magisk APK")?;

    let args_magisk = [
        OsStr::new("--magisk"),
        magisk_file.as_os_str(),
        OsStr::new("--magisk-preinit-device"),
        OsStr::new("metadata"),
    ];

    for name in profiles {
        if Path::new(name).file_name() != Some(OsStr::new(name)) {
            bail!("Unsafe profile name: {name}");
        }

        let profile = &config.profile[name];

        for (zip_mode, hashes) in [
            (ZipMode::Streaming, &profile.hashes_streaming),
            (ZipMode::Seekable, &profile.hashes_seekable),
        ] {
            let _span = info_span!("profile", name, %zip_mode).entered();

            // Can't use NamedTempFile because avbroot does atomic replaces.
            let mut profile_dir = work_dir.join(name);
            profile_dir.push(zip_mode.to_string());
            let out_original = profile_dir.join("ota.zip");
            let out_magisk = profile_dir.join("ota_magisk.zip");
            let out_prepatched = profile_dir.join("ota_prepatched.zip");

            fs::create_dir_all(&profile_dir)
                .with_context(|| format!("Failed to create directory: {profile_dir:?}"))?;

            create_ota(
                &out_original,
                &config.ota_info,
                profile,
                zip_mode,
                &orig_keys.avb_key,
                &orig_keys.ota_key,
                &orig_keys.ota_cert,
                cancel_signal,
            )
            .with_context(|| format!("[{name}] Failed to create OTA"))?;

            verify_image(&out_original, &orig_keys, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify original OTA"))?;

            verify_hash(&out_original, &hashes.original.0, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify original OTA hash"))?;

            // Patch once using Magisk.
            extract_image(&out_original, &profile_dir, cancel_signal)
                .with_context(|| format!("[{name}] Failed to extract OTA"))?;

            let system_image = profile_dir.join("system.img");

            patch_image(
                &out_original,
                &out_magisk,
                &system_image,
                zip_mode,
                &args_magisk,
                &test_keys,
                false,
                cancel_signal,
            )
            .with_context(|| format!("[{name}] Failed to patch OTA"))?;

            verify_image(&out_magisk, &test_keys, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify patched OTA"))?;

            verify_hash(&out_magisk, &hashes.patched.0, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify patched OTA hash"))?;

            // Patch again, but this time, use the previously patched boot image
            // instead of applying the Magisk patch.
            extract_image(&out_magisk, &profile_dir, cancel_signal)
                .with_context(|| format!("[{name}] Failed to extract OTA"))?;

            let mut magisk_image = profile_dir.join("init_boot.img");
            if !magisk_image.exists() {
                magisk_image = profile_dir.join("boot.img");
            }

            // Wipe out changes that we expect to be made to prepatched images.
            clean_boot_image_certs(&magisk_image, cancel_signal)?;

            let args_prepatched = [OsStr::new("--prepatched"), magisk_image.as_os_str()];

            patch_image(
                &out_original,
                &out_prepatched,
                &system_image,
                zip_mode,
                &args_prepatched,
                &test_keys,
                true,
                cancel_signal,
            )
            .with_context(|| format!("[{name}] Failed to patch OTA"))?;

            verify_image(&out_prepatched, &test_keys, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify patched OTA"))?;

            verify_hash(&out_prepatched, &hashes.patched.0, cancel_signal)
                .with_context(|| format!("[{name}] Failed to verify patched OTA hash"))?;
        }
    }

    Ok(())
}

fn list_subcommand(cli: &ListCli) -> Result<()> {
    let (config, _) = config::load_config(&cli.config.config)?;

    for profile in config.profile.keys() {
        println!("{profile}");
    }

    Ok(())
}

/// A basic --signing-helper implementation that just signs via RustCrypto.
fn helper_mode() -> Result<()> {
    let cli = HelperCli::parse();

    let private_key_path = {
        let parent = cli.public_key.parent().unwrap_or_else(|| Path::new("."));
        let name = cli
            .public_key
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("Bad filename: {:?}", cli.public_key))?;

        parent.join(name.replace(".public", ""))
    };
    let source = match cli.pass_source {
        PassSource::Env => PassphraseSource::EnvVar(cli.pass_source_value),
        PassSource::File => PassphraseSource::File(cli.pass_source_value.into()),
    };
    let private_key = crypto::read_pem_key_file(&private_key_path, &source)
        .with_context(|| format!("Failed to load private key: {private_key_path:?}"))?;
    let public_key = crypto::read_pem_public_key_file(&cli.public_key)
        .with_context(|| format!("Failed to load public key: {:?}", cli.public_key))?;

    if private_key.to_public_key() != public_key {
        bail!("Private key does not match public key");
    }

    let (hash_algo, key_algo) = cli
        .algorithm
        .split_once('_')
        .ok_or_else(|| anyhow!("Unknown algorithm: {:?}", cli.algorithm))?;

    if key_algo != format!("RSA{}", private_key.size() * 8) {
        bail!(
            "{key_algo} does not match key size ({})",
            private_key.size() * 8
        );
    } else if hash_algo != "SHA256" && hash_algo != "SHA512" {
        bail!("Unknown hash algorithm: {hash_algo}");
    }

    let mut padded_digest = vec![];
    io::stdin()
        .read_to_end(&mut padded_digest)
        .context("Failed to read padded digest from stdin")?;

    if padded_digest.len() != private_key.size() {
        bail!(
            "Padded digest size ({}) bytes does not match key size ({})",
            padded_digest.len(),
            private_key.size()
        );
    }

    // The input is already padded, so perform a raw RSA signing operation.
    let mut signature = rsa::hazmat::rsa_decrypt_and_check(
        &private_key,
        None::<&mut OsRng>,
        &BigUint::from_bytes_be(&padded_digest),
    )
    .context("Failed to sign digest")?
    .to_bytes_le();
    signature.resize(private_key.size(), 0);
    signature.reverse();

    io::stdout()
        .write_all(&signature)
        .context("Failed to write signature to stdout")?;

    Ok(())
}

fn main() -> Result<()> {
    const ENV_HELPER_MODE: &str = "E2E_HELPER_MODE";

    // Re-invoking ourselves will execute as the helper script instead.
    if env::var_os(ENV_HELPER_MODE).is_some() {
        return helper_mode();
    }
    // SAFETY: No multithreading at this point.
    unsafe {
        env::set_var(ENV_HELPER_MODE, "true");
    }

    // Set up a cancel signal so we can properly clean up any temporary files.
    let cancel_signal = Arc::new(AtomicBool::new(false));
    {
        let signal = cancel_signal.clone();

        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set signal handler");
    }

    let cli = Cli::parse();

    avbroot::cli::args::init_logging(cli.log_level, cli.log_format);

    match cli.command {
        Command::Test(c) => test_subcommand(&c, &cancel_signal),
        Command::List(c) => list_subcommand(&c),
    }
}
