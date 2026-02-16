// SPDX-FileCopyrightText: 2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{BufReader, Seek},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use rawzip::{
    CompressionMethod, RECOMMENDED_BUFFER_SIZE, ZipArchive, ZipArchiveEntryWayfinder,
    ZipArchiveWriter, ZipDataWriter, ZipEntryWriter, extra_fields::ExtraFieldId,
};
use serde::{Deserialize, Serialize};
use tracing::warn;
use x509_cert::Certificate;

use crate::{
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::{
        ota::{self, SigningWriter, ZipEntry, ZipMode},
        payload::PayloadHeader,
        zip::{
            self, ReaderAtWrapper, ZipArchiveReadAtExt, ZipEntriesSafeExt, ZipFileHeaderRecordExt,
        },
    },
    protobuf::build::tools::releasetools::OtaMetadata,
    stream::{self, FromReader},
    util,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OtaInfo {
    metadata: OtaMetadata,
    files: Vec<String>,
}

struct InputEntry {
    compression_method: CompressionMethod,
    is_zip64: bool,
    wayfinder: ZipArchiveEntryWayfinder,
}

fn is_excluded_path(path: &str) -> bool {
    path == ota::PATH_METADATA || path == ota::PATH_METADATA_PB || path == ota::PATH_OTACERT
}

#[allow(clippy::type_complexity)]
fn open_reader(
    path: &Path,
) -> Result<(
    ZipArchive<ReaderAtWrapper<File>>,
    OtaMetadata,
    BTreeMap<String, InputEntry>,
)> {
    let mut reader =
        File::open(path).with_context(|| format!("Failed to open OTA for reading: {path:?}"))?;

    let (metadata, _, _, _) = ota::parse_zip_ota_info(&mut reader)
        .with_context(|| format!("Failed to parse OTA metadata: {path:?}"))?;

    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let zip_reader =
        ZipArchive::from_read_at(reader, &mut buffer).context("Failed to read OTA zip")?;

    let mut entries = zip_reader.entries_safe(&mut buffer);
    let mut input_entries = BTreeMap::new();

    while let Some((cd_entry, _)) = entries.next_entry().context("Failed to list zip entries")? {
        if cd_entry.is_dir() {
            continue;
        }

        let path = cd_entry
            .file_path_utf8()
            .context("Zip contains non-UTF-8 paths")?;

        if is_excluded_path(path) {
            // OTA metadata is never copied from the input file.
            continue;
        }

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

    Ok((zip_reader, metadata, input_entries))
}

fn open_writer(path: &Path, zip_mode: ZipMode) -> Result<ZipArchiveWriter<SigningWriter<File>>> {
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("Failed to open OTA for writing: {path:?}"))?;

    let signing_writer = match zip_mode {
        ZipMode::Streaming => SigningWriter::new_streaming(writer),
        ZipMode::Seekable => SigningWriter::new_seekable(writer),
    };
    let zip_writer = ZipArchiveWriter::new(signing_writer);

    Ok(zip_writer)
}

fn read_info(path: &Path) -> Result<OtaInfo> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read OTA info TOML: {path:?}"))?;
    let info = toml::de::from_str(&data)
        .with_context(|| format!("Failed to parse OTA info TOML: {path:?}"))?;

    Ok(info)
}

fn write_info(path: &Path, info: &OtaInfo) -> Result<()> {
    let data = toml::ser::to_string_pretty(info)
        .with_context(|| format!("Failed to serialize OTA info TOML: {path:?}"))?;
    fs::write(path, data).with_context(|| format!("Failed to write OTA info TOML: {path:?}"))?;

    Ok(())
}

fn display_info(cli: &ZipCli, info: &OtaInfo) {
    if !cli.quiet {
        println!("{info:#?}");
    }
}

fn load_key(group: &KeyGroup) -> Result<(RsaSigningKey, Certificate)> {
    let source = PassphraseSource::new(
        &group.key,
        group.pass_file.as_deref(),
        group.pass_env_var.as_deref(),
    );
    let signing_key = if let Some(helper) = &group.signing_helper {
        let public_key = crypto::read_pem_public_key_file(&group.key)
            .with_context(|| format!("Failed to load key: {:?}", group.key))?;

        RsaSigningKey::External {
            program: helper.clone(),
            public_key_file: group.key.clone(),
            public_key,
            passphrase_source: source,
        }
    } else {
        let private_key = crypto::read_pem_key_file(&group.key, &source)
            .with_context(|| format!("Failed to load key: {:?}", group.key))?;

        RsaSigningKey::Internal(private_key)
    };

    let cert = crypto::read_pem_cert_file(&group.cert)
        .with_context(|| format!("Failed to load certificate: {:?}", group.cert))?;

    Ok((signing_key, cert))
}

fn start_entry<'a>(
    zip_writer: &'a mut ZipArchiveWriter<SigningWriter<File>>,
    path: &str,
    zip_mode: ZipMode,
    is_zip64: bool,
) -> Result<(u64, ZipDataWriter<ZipEntryWriter<'a, SigningWriter<File>>>)> {
    let mut builder = zip_writer
        .new_file(path)
        .compression_method(CompressionMethod::Store);

    if zip_mode == ZipMode::Seekable && is_zip64 {
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
    let data_writer = data_config.wrap(entry_writer);

    Ok((offset, data_writer))
}

fn finalize_entry(
    path: &str,
    offset: u64,
    data_writer: ZipDataWriter<ZipEntryWriter<SigningWriter<File>>>,
    metadata_entries: &mut Vec<ZipEntry>,
) -> Result<()> {
    let size = data_writer
        .finish()
        .and_then(|(w, d)| w.finish(d))
        .with_context(|| format!("Failed to finalize zip entry: {path}"))?;

    metadata_entries.push(ZipEntry {
        path: path.to_owned(),
        offset,
        size,
    });

    Ok(())
}

fn add_otacert_entry(
    zip_writer: &mut ZipArchiveWriter<SigningWriter<File>>,
    zip_mode: ZipMode,
    cert: &Certificate,
    metadata_entries: &mut Vec<ZipEntry>,
) -> Result<()> {
    let (offset, mut data_writer) = start_entry(zip_writer, ota::PATH_OTACERT, zip_mode, false)?;

    crypto::write_pem_cert(Path::new(ota::PATH_OTACERT), &mut data_writer, cert)
        .with_context(|| format!("Failed to write entry: {}", ota::PATH_OTACERT))?;

    finalize_entry(ota::PATH_OTACERT, offset, data_writer, metadata_entries)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finalize_ota(
    key: &RsaSigningKey,
    cert: &Certificate,
    mut zip_writer: ZipArchiveWriter<SigningWriter<File>>,
    zip_mode: ZipMode,
    metadata_entries: &mut Vec<ZipEntry>,
    payload_metadata_size: Option<u64>,
    metadata: &mut OtaMetadata,
    cancel_signal: &AtomicBool,
) -> Result<File> {
    add_otacert_entry(&mut zip_writer, zip_mode, cert, metadata_entries)?;

    let payload_metadata_size =
        payload_metadata_size.ok_or_else(|| anyhow!("Missing payload metadata size"))?;
    let metadata_offset = zip_writer.stream_offset();

    *metadata = ota::add_metadata(
        metadata_entries,
        &mut zip_writer,
        // Offset where next entry would begin.
        metadata_offset,
        metadata,
        payload_metadata_size,
    )
    .context("Failed to write new OTA metadata")?;

    let signing_writer = zip_writer
        .finish()
        .context("Failed to finalize output zip")?;
    let mut raw_writer = signing_writer
        .finish(key, cert, cancel_signal)
        .context("Failed to sign output zip")?;

    raw_writer.rewind().context("Failed to seek output zip")?;
    ota::verify_metadata(
        BufReader::new(&mut raw_writer),
        metadata,
        payload_metadata_size,
    )
    .context("Failed to verify OTA metadata offsets")?;

    Ok(raw_writer)
}

fn unpack_subcommand(zip_cli: &ZipCli, cli: &UnpackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (zip_reader, metadata, input_entries) = open_reader(&cli.input)?;

    if !cli.no_output_files {
        for (path, input_entry) in &input_entries {
            let entry = zip_reader
                .get_entry(input_entry.wayfinder)
                .with_context(|| format!("Failed to open zip entry: {path}"))?;
            let mut entry_reader = zip::verifying_reader(&entry, input_entry.compression_method)
                .with_context(|| format!("Failed to open zip entry: {path}"))?;

            let output_path = util::path_join(&cli.output_files, path)?;
            let output_parent = output_path.parent().expect("No parent path");

            fs::create_dir_all(output_parent)
                .with_context(|| format!("Failed to create directory: {output_parent:?}"))?;

            let mut output_file = File::create(&output_path)
                .with_context(|| format!("Failed to open for writing: {output_path:?}"))?;

            stream::copy(&mut entry_reader, &mut output_file, cancel_signal)
                .with_context(|| format!("Failed to extract zip entry: {path}"))?;
        }
    }

    let info = OtaInfo {
        metadata,
        files: input_entries.into_keys().collect(),
    };

    display_info(zip_cli, &info);
    write_info(&cli.output_info, &info)?;

    Ok(())
}

fn pack_subcommand(zip_cli: &ZipCli, cli: &PackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (signing_key, cert) = load_key(&cli.key)?;
    let mut info = read_info(&cli.input_info)?;
    let mut zip_writer = open_writer(&cli.output, cli.zip_mode.zip_mode)?;

    let mut input_entries = BTreeMap::new();

    for path in &info.files {
        if is_excluded_path(path) {
            warn!("Ignoring input file: {path}");
            continue;
        }

        let input_path = util::path_join(&cli.input_files, path)?;
        let input_size = fs::metadata(&input_path)
            .map(|m| m.len())
            .with_context(|| format!("Failed to get file size: {input_path:?}"))?;

        input_entries.insert(path, input_size >= 0xffffffff);
    }

    let mut payload_metadata_size = None;
    let mut metadata_entries = vec![];

    for (&path, &is_zip64) in &input_entries {
        let (offset, mut data_writer) =
            start_entry(&mut zip_writer, path, cli.zip_mode.zip_mode, is_zip64)?;

        let input_path = util::path_join(&cli.input_files, path)?;
        let mut input_file = File::open(&input_path)
            .with_context(|| format!("Failed to open for reading: {input_path:?}"))?;

        if path == ota::PATH_PAYLOAD {
            let header = PayloadHeader::from_reader(&mut input_file)
                .with_context(|| format!("Failed to read payload header: {input_path:?}"))?;

            payload_metadata_size = Some(header.blob_offset);

            input_file
                .rewind()
                .with_context(|| format!("Failed to seek file: {input_path:?}"))?;
        }

        stream::copy(&mut input_file, &mut data_writer, cancel_signal)
            .with_context(|| format!("Failed to copy zip entry: {path}"))?;

        finalize_entry(path, offset, data_writer, &mut metadata_entries)?;
    }

    finalize_ota(
        &signing_key,
        &cert,
        zip_writer,
        cli.zip_mode.zip_mode,
        &mut metadata_entries,
        payload_metadata_size,
        &mut info.metadata,
        cancel_signal,
    )?;

    drop(input_entries);
    info.files.retain(|p| !is_excluded_path(p));
    info.files.sort();

    display_info(zip_cli, &info);

    if let Some(path) = &cli.output_info {
        write_info(path, &info)?;
    }

    Ok(())
}

fn repack_subcommand(zip_cli: &ZipCli, cli: &RepackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let (signing_key, cert) = load_key(&cli.key)?;
    let (zip_reader, mut metadata, input_entries) = open_reader(&cli.input)?;
    let mut zip_writer = open_writer(&cli.output, cli.zip_mode.zip_mode)?;

    let mut payload_metadata_size = None;
    let mut metadata_entries = vec![];

    for (path, input_entry) in &input_entries {
        let (offset, mut data_writer) = start_entry(
            &mut zip_writer,
            path,
            cli.zip_mode.zip_mode,
            input_entry.is_zip64,
        )?;

        let entry = zip_reader
            .get_entry(input_entry.wayfinder)
            .with_context(|| format!("Failed to open zip entry: {path}"))?;

        if path == ota::PATH_PAYLOAD {
            let entry_reader = zip::verifying_reader(&entry, input_entry.compression_method)
                .with_context(|| format!("Failed to open zip entry: {path}"))?;

            let header = PayloadHeader::from_reader(entry_reader)
                .with_context(|| format!("Failed to read payload header: {path:?}"))?;

            payload_metadata_size = Some(header.blob_offset);
        }

        let mut entry_reader = zip::verifying_reader(&entry, input_entry.compression_method)
            .with_context(|| format!("Failed to open zip entry: {path}"))?;

        stream::copy(&mut entry_reader, &mut data_writer, cancel_signal)
            .with_context(|| format!("Failed to copy zip entry: {path}"))?;

        finalize_entry(path, offset, data_writer, &mut metadata_entries)?;
    }

    finalize_ota(
        &signing_key,
        &cert,
        zip_writer,
        cli.zip_mode.zip_mode,
        &mut metadata_entries,
        payload_metadata_size,
        &mut metadata,
        cancel_signal,
    )?;

    let info = OtaInfo {
        metadata,
        files: input_entries.into_keys().collect(),
    };

    display_info(zip_cli, &info);

    Ok(())
}

fn info_subcommand(zip_cli: &ZipCli, cli: &InfoCli) -> Result<()> {
    let (_, metadata, input_entries) = open_reader(&cli.input)?;
    let info = OtaInfo {
        metadata,
        files: input_entries.into_keys().collect(),
    };

    display_info(zip_cli, &info);

    Ok(())
}

pub fn zip_main(cli: &ZipCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        ZipCommand::Unpack(c) => unpack_subcommand(cli, c, cancel_signal),
        ZipCommand::Pack(c) => pack_subcommand(cli, c, cancel_signal),
        ZipCommand::Repack(c) => repack_subcommand(cli, c, cancel_signal),
        ZipCommand::Info(c) => info_subcommand(cli, c),
    }
}

#[derive(Debug, Args)]
struct KeyGroup {
    /// Path to signing key.
    ///
    /// This should normally be a private key. However, if --signing-helper is
    /// used, then it should be a public key instead.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,

    /// Certificate for signing key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    cert: PathBuf,

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

#[derive(Debug, Args)]
struct ZipModeGroup {
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
    )]
    zip_mode: ZipMode,
}

/// Unpack an OTA zip.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "ota.toml")]
    output_info: PathBuf,

    /// Path to output files directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "ota_files")]
    output_files: PathBuf,

    /// Do not output files.
    #[arg(long, conflicts_with = "output_files")]
    no_output_files: bool,
}

/// Pack an OTA zip.
///
/// The new OTA zip will *only* contain files listed in the info TOML file.
/// Extra files in the input files directory that aren't listed will be silently
/// ignored.
///
/// WARNING: This subcommand is for raw file manipulation and does not perform
/// any validation of the contents of the payload binary. For normal usage, use
/// `avbroot ota patch` instead.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to input info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "ota.toml")]
    input_info: PathBuf,

    /// Path to output info TOML.
    ///
    /// If specified, the OTA info containing all recomputed fields will be
    /// written to this file. This can point to the same file as --input-info.
    #[arg(long, value_name = "FILE", value_parser)]
    output_info: Option<PathBuf>,

    /// Path to input files directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "ota_files")]
    input_files: PathBuf,

    #[command(flatten)]
    key: KeyGroup,

    #[command(flatten)]
    zip_mode: ZipModeGroup,
}

/// Repack an OTA zip.
///
/// This command is equivalent to running `unpack` and `pack`, except without
/// storing the unpacked data to disk first.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    #[command(flatten)]
    key: KeyGroup,

    #[command(flatten)]
    zip_mode: ZipModeGroup,
}

/// Display OTA zip information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input OTA zip.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ZipCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
}

/// Pack, unpack, and inspect OTA zips.
#[derive(Debug, Parser)]
pub struct ZipCli {
    #[command(subcommand)]
    command: ZipCommand,

    /// Don't print OTA metadata information.
    #[arg(short, long, global = true)]
    quiet: bool,
}
