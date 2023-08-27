/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-FileCopyrightText: 2023 Pascal Roeleven
 * SPDX-License-Identifier: GPL-3.0-only
 */

mod cli;
mod config;
mod download;

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, BufReader, BufWriter, Seek, SeekFrom},
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use avbroot::{
    cli::ota::{ExtractCli, PatchCli, VerifyCli},
    format::{ota, payload::PayloadHeader},
    stream::{self, FromReader, HashingReader, PSeekFile, SectionReader},
};
use clap::Parser;
use tempfile::TempDir;
use zip::ZipArchive;

use crate::{
    cli::{AddCli, Cli, Command, DeviceGroup, DownloadCli, ListCli, StripCli, TestCli},
    config::{Config, Device, ImageHashes, OtaHashes, Sha256Hash},
};

const DOWNLOAD_TASKS: usize = 4;
const DOWNLOAD_RETRIES: u8 = 3;
const DOWNLOAD_PROGRESS_INTERVAL: Duration = Duration::from_millis(50);

/// Sort and merge overlapping intervals.
fn merge_overlapping(sections: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut sections = sections.to_vec();
    sections.sort_by_key(|r| (r.start, r.end));

    let mut result = Vec::<Range<u64>>::new();

    for section in sections {
        if let Some(last) = result.last_mut() {
            if section.start <= last.end {
                last.end = section.end;
                continue;
            }
        }

        result.push(section);
    }

    result
}

/// Convert an exclusion list into an inclusion list in the range [start, end).
fn exclusion_to_inclusion(holes: &[Range<u64>], file_range: Range<u64>) -> Result<Vec<Range<u64>>> {
    let exclusions = merge_overlapping(holes);

    if let (Some(first), Some(last)) = (exclusions.first(), exclusions.last()) {
        if first.start < file_range.start || last.end > file_range.end {
            bail!("Sections are outside of the range {file_range:?}");
        }
    }

    let flattened = exclusions.iter().flat_map(|p| [p.start, p.end]);
    let points = [file_range.start]
        .into_iter()
        .chain(flattened)
        .chain([file_range.end])
        .collect::<Vec<_>>();

    Ok(points.chunks_exact(2).map(|c| c[0]..c[1]).collect())
}

/// Convert a full OTA to a stripped OTA with all non-AVB-related partitions
/// removed from the payload. No headers are updated, so the output file will
/// have invalid hashes and signatures.
///
/// Returns the list of file sections and the sha256 digest.
fn strip_image(
    input: &Path,
    output: &Path,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<(Vec<Range<u64>>, [u8; 32])> {
    println!("Stripping {input:?} to {output:?}");

    let mut raw_reader = File::open(input)
        .map(PSeekFile::new)
        .with_context(|| anyhow!("Failed to open for reading: {input:?}"))?;
    let mut zip_reader = ZipArchive::new(BufReader::new(raw_reader.clone()))
        .with_context(|| anyhow!("Failed to read zip: {input:?}"))?;
    let payload_entry = zip_reader
        .by_name(ota::PATH_PAYLOAD)
        .with_context(|| anyhow!("Failed to open zip entry: {:?}", ota::PATH_PAYLOAD))?;
    let payload_offset = payload_entry.data_start();
    let payload_size = payload_entry.size();

    // Open the payload data directly.
    let mut payload_reader = SectionReader::new(
        BufReader::new(raw_reader.clone()),
        payload_offset,
        payload_size,
    )?;

    let header = PayloadHeader::from_reader(&mut payload_reader)
        .with_context(|| anyhow!("Failed to load OTA payload header"))?;

    let required_images =
        avbroot::cli::ota::get_required_images(&header.manifest, "@gki_ramdisk", true)?
            .into_values()
            .collect::<HashSet<_>>();
    let mut data_holes = vec![];

    use avbroot::protobuf::chromeos_update_engine::mod_InstallOperation::Type;

    for p in &header.manifest.partitions {
        if !required_images.contains(&p.partition_name) {
            for op in &p.operations {
                match op.type_pb {
                    Type::ZERO | Type::DISCARD => continue,
                    _ => {
                        let start = payload_offset
                            + header.blob_offset
                            + op.data_offset.expect("Missing data_offset");
                        let end = start + op.data_length.expect("Missing data_length");

                        data_holes.push(start..end);
                    }
                }
            }
        }
    }

    // Keep all sections outside of the partitions skipped.
    let file_size = raw_reader.seek(SeekFrom::End(0))?;
    let sections_to_keep = exclusion_to_inclusion(&data_holes, 0..file_size)?;

    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let raw_writer =
        File::create(output).with_context(|| anyhow!("Failed to open for writing: {output:?}"))?;
    raw_writer
        .set_len(file_size)
        .with_context(|| anyhow!("Failed to set file size: {output:?}"))?;
    let mut buf_writer = BufWriter::new(raw_writer);
    let mut buf_reader = BufReader::new(raw_reader);

    buf_reader.rewind()?;

    for section in &sections_to_keep {
        let offset = buf_reader.stream_position()?;

        // Hash holes as zeros.
        if offset != section.start {
            stream::copy_n_inspect(
                io::repeat(0),
                io::sink(),
                section.start - offset,
                |data| context.update(data),
                cancel_signal,
            )?;

            buf_reader.seek(SeekFrom::Start(section.start))?;
            buf_writer.seek(SeekFrom::Start(section.start))?;
        }

        stream::copy_n_inspect(
            &mut buf_reader,
            &mut buf_writer,
            section.end - section.start,
            |data| context.update(data),
            cancel_signal,
        )?;
    }

    // There can't be a hole at the end of a zip, so nothing left to hash.

    let digest = context.finish();
    Ok((sections_to_keep, digest.as_ref().try_into().unwrap()))
}

fn url_filename(url: &str) -> Result<&str> {
    url.rsplit_once('/')
        .map(|(_, name)| name)
        .ok_or_else(|| anyhow!("Failed to determine filename from URL: {url}"))
}

fn hash_file(path: &Path, cancel_signal: &Arc<AtomicBool>) -> Result<[u8; 32]> {
    println!("Calculating hash of {path:?}");

    let raw_reader =
        File::open(path).with_context(|| anyhow!("Failed to open for reading: {path:?}"))?;
    let buf_reader = BufReader::new(raw_reader);
    let context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut hashing_reader = HashingReader::new(buf_reader, context);

    stream::copy(&mut hashing_reader, io::sink(), cancel_signal)?;

    let (_, context) = hashing_reader.finish();
    let digest = context.finish();

    Ok(digest.as_ref().try_into().unwrap())
}

fn verify_hash(path: &Path, sha256: &[u8; 32], cancel_signal: &Arc<AtomicBool>) -> Result<()> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Validate {
    Always,
    IfNew,
    Never,
}

fn download_file(
    path: &Path,
    url: &str,
    sha256: &[u8; 32],
    sections: Option<&[Range<u64>]>,
    path_is_dir: bool,
    validate: Validate,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    let path = if path_is_dir {
        path.join(url_filename(url)?)
    } else {
        path.to_owned()
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| anyhow!("Failed to create directory: {parent:?}"))?;
    }

    let mut do_validate = validate != Validate::Never;

    if path.exists() && !download::state_path(&path).exists() {
        if validate == Validate::IfNew {
            do_validate = false;
        }
    } else {
        println!("Downloading {url} to {path:?}");

        let mut display = download::BasicProgressDisplay::new(DOWNLOAD_PROGRESS_INTERVAL);

        download::download(
            url,
            &path,
            sections,
            &mut display,
            DOWNLOAD_TASKS,
            DOWNLOAD_RETRIES,
        )?;
    }

    if do_validate {
        verify_hash(&path, sha256, cancel_signal)?;
    }

    Ok(path)
}

fn download_magisk(
    config: &Config,
    work_dir: &Path,
    revalidate: bool,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    download_file(
        &work_dir.join("magisk"),
        &config.magisk.url,
        &config.magisk.hash.0,
        None,
        true,
        if revalidate {
            Validate::Always
        } else {
            Validate::IfNew
        },
        cancel_signal,
    )
}

fn download_image(
    config: &Config,
    device: &str,
    work_dir: &Path,
    stripped: bool,
    revalidate: bool,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<PathBuf> {
    let info = &config.device[device];
    let mut path = work_dir.join(device);
    path.push(url_filename(&info.url)?);
    let mut sha256 = &info.hash.original.full.0;
    let mut sections = None;

    if stripped {
        path.as_mut_os_string().push(".stripped");
        sha256 = &info.hash.original.stripped.0;
        sections = Some(info.sections.as_slice());
    }

    download_file(
        &path,
        &info.url,
        sha256,
        sections,
        false,
        if revalidate {
            Validate::Always
        } else {
            Validate::IfNew
        },
        cancel_signal,
    )
}

#[rustfmt::skip]
fn test_keys() -> Result<(TempDir, Vec<OsString>, Vec<OsString>)> {
    let avb_key = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_avb.key",
    ));
    let avb_pass = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_avb.passphrase",
    ));
    let avb_pkmd = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_avb_pkmd.bin",
    ));
    let ota_key = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_ota.key",
    ));
    let ota_pass = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_ota.passphrase",
    ));
    let ota_cert = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/keys/TEST_KEY_DO_NOT_USE_ota.crt",
    ));

    let temp_dir = TempDir::new().context("Failed to create temporary directory for test keys")?;
    let mut patch_args = Vec::<OsString>::new();
    let mut verify_args = Vec::<OsString>::new();

    for (name, data, patch_arg, verify_arg) in [
        ("avb.key", &avb_key[..], Some("--key-avb"), None),
        ("avb.pass", &avb_pass[..], Some("--pass-avb-file"), None),
        ("avb.pkmd", &avb_pkmd[..], None, Some("--public-key-avb")),
        ("ota.key", &ota_key[..], Some("--key-ota"), None),
        ("ota.pass", &ota_pass[..], Some("--pass-ota-file"), None),
        ("ota.crt", &ota_cert[..], Some("--cert-ota"), Some("--cert-ota")),
    ] {
        let path = temp_dir.path().join(name);
        fs::write(&path, data).with_context(|| anyhow!("Failed to write test key: {path:?}"))?;

        if let Some(arg) = patch_arg {
            patch_args.push(arg.into());
            patch_args.push(path.as_os_str().to_owned());
        }
        if let Some(arg) = verify_arg {
            verify_args.push(arg.into());
            verify_args.push(path.as_os_str().to_owned());
        }
    }

    Ok((temp_dir, patch_args, verify_args))
}

fn patch_image(
    input_file: &Path,
    output_file: &Path,
    extra_args: &[OsString],
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    println!("Patching {input_file:?}");

    let (_temp_key_dir, key_args, _) = test_keys()?;

    // We're intentionally using the CLI interface.
    let mut args: Vec<OsString> = vec![
        "patch".into(),
        "--input".into(),
        input_file.as_os_str().into(),
        "--output".into(),
        output_file.as_os_str().into(),
    ];
    args.extend(key_args);
    args.extend_from_slice(extra_args);

    if args.contains(&OsStr::new("--magisk").into()) {
        // This doesn't need to be correct. The test outputs aren't meant to
        // be booted on real devices.
        args.push("--magisk-preinit-device".into());
        args.push("metadata".into());
    }

    let cli = PatchCli::try_parse_from(args)?;
    avbroot::cli::ota::patch_subcommand(&cli, cancel_signal)?;

    Ok(())
}

fn extract_image(
    input_file: &Path,
    output_dir: &Path,
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    println!("Extracting AVB partitions from {input_file:?}");

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

fn verify_image(input_file: &Path, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    println!("Verifying signatures in {input_file:?}");

    let (_temp_key_dir, _, key_args) = test_keys()?;

    let mut args: Vec<OsString> = vec![
        "verify".into(),
        "--input".into(),
        input_file.as_os_str().into(),
    ];
    args.extend(key_args);

    let cli = VerifyCli::try_parse_from(args)?;
    avbroot::cli::ota::verify_subcommand(&cli, cancel_signal)?;

    Ok(())
}

fn get_magisk_partition(path: &Path) -> Result<String> {
    let raw_reader =
        File::open(path).with_context(|| anyhow!("Failed to open for reading: {path:?}"))?;
    let mut zip = ZipArchive::new(BufReader::new(raw_reader))
        .with_context(|| anyhow!("Failed to read zip: {path:?}"))?;
    let payload_entry = zip
        .by_name(ota::PATH_PAYLOAD)
        .with_context(|| anyhow!("Failed to open zip entry: {:?}", ota::PATH_PAYLOAD))?;
    let payload_offset = payload_entry.data_start();
    let payload_size = payload_entry.size();

    drop(payload_entry);
    let buf_reader = zip.into_inner();

    // Open the payload data directly.
    let mut payload_reader = SectionReader::new(buf_reader, payload_offset, payload_size)?;

    let header = PayloadHeader::from_reader(&mut payload_reader)
        .with_context(|| anyhow!("Failed to load OTA payload header"))?;
    let images = avbroot::cli::ota::get_partitions_by_type(&header.manifest)?;

    Ok(images["@gki_ramdisk"].clone())
}

fn filter_devices<'a>(config: &'a Config, cli: &'a DeviceGroup) -> Result<BTreeSet<&'a str>> {
    let mut devices = config
        .device
        .keys()
        .map(|d| d.as_str())
        .collect::<BTreeSet<_>>();

    if !cli.all {
        let invalid = cli
            .device
            .iter()
            .filter(|d| !devices.contains(d.as_str()))
            .collect::<BTreeSet<_>>();
        if !invalid.is_empty() {
            bail!("Invalid devices: {invalid:?}");
        }

        devices = cli.device.iter().map(|d| d.as_str()).collect();
    }

    Ok(devices)
}

fn strip_subcommand(cli: &StripCli, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    let (sections, sha256) = strip_image(&cli.input, &cli.output, cancel_signal)?;

    println!("Preserved sections:");
    for section in sections {
        println!("- {section:?}");
    }

    println!("SHA256: {}", hex::encode(sha256));

    Ok(())
}

fn add_subcommand(cli: &AddCli, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    let (config, mut document) = config::load_config(&cli.config.config)?;

    let image_dir = cli.config.work_dir.join(&cli.device);

    let full_ota = image_dir.join(url_filename(&cli.url)?);
    let mut full_ota_patched = full_ota.clone();
    full_ota_patched.as_mut_os_string().push(&cli.patch.suffix);
    let mut stripped_ota = full_ota.clone();
    stripped_ota.as_mut_os_string().push(".stripped");
    let mut stripped_ota_patched = stripped_ota.clone();
    stripped_ota_patched
        .as_mut_os_string()
        .push(&cli.patch.suffix);

    let full_ota_hash = cli.hash.as_ref().map(|h| h.0);

    download_file(
        &full_ota,
        &cli.url,
        &full_ota_hash.unwrap_or_default(),
        None,
        false,
        if full_ota_hash.is_some() {
            Validate::Always
        } else {
            Validate::Never
        },
        cancel_signal,
    )?;

    // Calculate the hash ourselves if one wasn't provided.
    let full_ota_hash = match full_ota_hash {
        Some(h) => h,
        None => hash_file(&full_ota, cancel_signal)?,
    };

    let magisk_file = download_magisk(&config, &cli.config.work_dir, true, cancel_signal)?;
    let magisk_args = [OsString::from("--magisk"), magisk_file.into_os_string()];

    // Patch the full image.
    patch_image(&full_ota, &full_ota_patched, &magisk_args, cancel_signal)?;
    let full_ota_patched_hash = hash_file(&full_ota_patched, cancel_signal)?;

    // Check that the patched full image looks good.
    if cli.skip_verify {
        println!("OTA and AVB signature validation skipped");
    } else {
        verify_image(&full_ota_patched, cancel_signal)?;
    }

    // Strip the full image.
    let (sections, stripped_ota_hash) = strip_image(&full_ota, &stripped_ota, cancel_signal)?;

    // Patch the stripped image. This doesn't fail zip's CRC checks because the
    // `ota patch` commands reads the payload directly from the raw backing
    // file.
    patch_image(
        &stripped_ota,
        &stripped_ota_patched,
        &magisk_args,
        cancel_signal,
    )?;
    let stripped_ota_patched_hash = hash_file(&stripped_ota_patched, cancel_signal)?;

    // Hash all of the AVB-related partition images so that `e2e test` can fail
    // fast if something goes wrong.
    let mut avb_images = BTreeMap::<String, Sha256Hash>::new();

    {
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        extract_image(&full_ota_patched, temp_dir.path(), cancel_signal)?;

        for entry in fs::read_dir(temp_dir.path())? {
            let entry = entry?;
            let hash = hash_file(&entry.path(), cancel_signal)?;

            avb_images.insert(entry.file_name().into_string().unwrap(), Sha256Hash(hash));
        }
    }

    println!("Adding {} to config file", cli.device);

    let device = Device {
        url: cli.url.clone(),
        sections,
        hash: ImageHashes {
            original: OtaHashes {
                full: Sha256Hash(full_ota_hash),
                stripped: Sha256Hash(stripped_ota_hash),
            },
            patched: OtaHashes {
                full: Sha256Hash(full_ota_patched_hash),
                stripped: Sha256Hash(stripped_ota_patched_hash),
            },
            avb_images,
        },
    };

    config::add_device(&mut document, &cli.device, &device)?;

    let config_serialized = document.to_string();
    fs::write(&cli.config.config, config_serialized)
        .with_context(|| anyhow!("Failed to write config: {:?}", cli.config.config))?;

    if cli.patch.delete_on_success {
        for path in [full_ota_patched, stripped_ota_patched] {
            fs::remove_file(&path).with_context(|| anyhow!("Failed to delete file: {path:?}"))?;
        }
    }

    Ok(())
}

fn download_subcommand(cli: &DownloadCli, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    let (config, _) = config::load_config(&cli.config.config)?;
    let devices = filter_devices(&config, &cli.device)?;

    if !cli.magisk && devices.is_empty() {
        bail!("No downloads selected");
    }

    if cli.magisk {
        download_magisk(
            &config,
            &cli.config.work_dir,
            cli.download.revalidate,
            cancel_signal,
        )?;
    }

    for device in devices {
        download_image(
            &config,
            device,
            &cli.config.work_dir,
            cli.download.stripped,
            cli.download.revalidate,
            cancel_signal,
        )?;
    }

    Ok(())
}

fn test_subcommand(cli: &TestCli, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
    let (config, _) = config::load_config(&cli.config.config)?;
    let devices = filter_devices(&config, &cli.device)?;

    if devices.is_empty() {
        bail!("No devices selected");
    }

    let magisk_file = download_magisk(
        &config,
        &cli.config.work_dir,
        cli.download.revalidate,
        cancel_signal,
    )?;
    let magisk_args = [OsString::from("--magisk"), magisk_file.into_os_string()];

    for device in devices {
        let info = &config.device[device];

        let image_file = download_image(
            &config,
            device,
            &cli.config.work_dir,
            cli.download.stripped,
            cli.download.revalidate,
            cancel_signal,
        )?;

        let mut patched_file = image_file.clone();
        patched_file.as_mut_os_string().push(&cli.patch.suffix);

        let patched_hash = if cli.download.stripped {
            &info.hash.patched.stripped.0
        } else {
            &info.hash.patched.full.0
        };

        patch_image(&image_file, &patched_file, &magisk_args, cancel_signal)?;

        let temp_dir = TempDir::new().context("Failed to create temp directory")?;

        // Check partitions first so we fail fast if the issue is with AVB.
        extract_image(&patched_file, temp_dir.path(), cancel_signal)?;

        let mut expected = info.hash.avb_images.keys().collect::<BTreeSet<_>>();

        for entry in fs::read_dir(temp_dir.path())? {
            let entry = entry?;
            let name = entry.file_name().into_string().unwrap();
            let hash = info
                .hash
                .avb_images
                .get(&name)
                .ok_or_else(|| anyhow!("Missing AVB image hash for {name}"))?;

            verify_hash(&entry.path(), &hash.0, cancel_signal)?;
            expected.remove(&name);
        }

        if !expected.is_empty() {
            bail!("Missing AVB images: {expected:?}");
        }

        // Then, validate the hash of everything.
        verify_hash(&patched_file, patched_hash, cancel_signal)?;

        // Patch again, but this time, use the previously patched boot image
        // instead of applying the Magisk patch.
        let magisk_partition = get_magisk_partition(&patched_file)?;
        let prepatched_args = [
            OsStr::new("--prepatched").to_owned(),
            temp_dir
                .path()
                .join(format!("{magisk_partition}.img"))
                .into_os_string(),
        ];

        fs::remove_file(&patched_file)
            .with_context(|| anyhow!("Failed to delete file: {patched_file:?}"))?;

        patch_image(&image_file, &patched_file, &prepatched_args, cancel_signal)?;

        verify_hash(&patched_file, patched_hash, cancel_signal)?;

        if cli.patch.delete_on_success {
            fs::remove_file(&patched_file)
                .with_context(|| anyhow!("Failed to delete file: {patched_file:?}"))?;
        }
    }

    Ok(())
}

fn list_subcommand(cli: &ListCli) -> Result<()> {
    let (config, _) = config::load_config(&cli.config.config)?;

    for device in config.device.keys() {
        println!("{device}");
    }

    Ok(())
}

fn main() -> Result<()> {
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

    match cli.command {
        Command::Strip(c) => strip_subcommand(&c, &cancel_signal),
        Command::Add(c) => add_subcommand(&c, &cancel_signal),
        Command::Download(c) => download_subcommand(&c, &cancel_signal),
        Command::Test(c) => test_subcommand(&c, &cancel_signal),
        Command::List(c) => list_subcommand(&c),
    }
}
