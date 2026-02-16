// SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File},
    io::{BufReader, BufWriter, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use tracing::info;

use crate::{
    cli::ota,
    crypto::{self, PassphraseSource, RsaSigningKey},
    format::payload::{PayloadHeader, PayloadWriter},
    stream::{self, FromReader},
    util,
};

fn open_reader(path: &Path, allow_delta: bool) -> Result<(BufReader<File>, PayloadHeader)> {
    let mut reader = File::open(path)
        .map(BufReader::new)
        .with_context(|| format!("Failed to open payload for reading: {path:?}"))?;
    let header = PayloadHeader::from_reader(&mut reader)
        .with_context(|| format!("Failed to read payload header: {path:?}"))?;
    if !allow_delta && !header.is_full_ota() {
        bail!("Payload is a delta OTA, not a full OTA");
    }

    Ok((reader, header))
}

fn open_writer(
    path: &Path,
    header: PayloadHeader,
    key: RsaSigningKey,
) -> Result<PayloadWriter<BufWriter<File>>> {
    let writer = File::create(path)
        .map(BufWriter::new)
        .with_context(|| format!("Failed to open payload for writing: {path:?}"))?;
    let payload_writer = PayloadWriter::new(writer, header, key)
        .with_context(|| format!("Failed to write payload header: {path:?}"))?;

    Ok(payload_writer)
}

fn read_info(path: &Path) -> Result<PayloadHeader> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read payload info TOML: {path:?}"))?;
    let info = toml::de::from_str(&data)
        .with_context(|| format!("Failed to parse payload info TOML: {path:?}"))?;

    Ok(info)
}

fn write_info(path: &Path, manifest: &PayloadHeader) -> Result<()> {
    let data = toml::ser::to_string_pretty(manifest)
        .with_context(|| format!("Failed to serialize payload info TOML: {path:?}"))?;
    fs::write(path, data)
        .with_context(|| format!("Failed to write payload info TOML: {path:?}"))?;

    Ok(())
}

fn display_header(cli: &PayloadCli, header: &PayloadHeader) {
    if !cli.quiet {
        println!("{header:#?}");
    }
}

fn load_key(group: &KeyGroup) -> Result<RsaSigningKey> {
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

    Ok(signing_key)
}

fn unpack_subcommand(
    payload_cli: &PayloadCli,
    cli: &UnpackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let (mut reader, header) = open_reader(&cli.input, false)?;
    let payload_size = reader
        .seek(SeekFrom::End(0))
        .with_context(|| format!("Failed to get file size: {:?}", cli.input))?;

    display_header(payload_cli, &header);

    write_info(&cli.output_info, &header)?;

    if !cli.no_output_images {
        fs::create_dir_all(&cli.output_images)
            .with_context(|| format!("Failed to create directory: {:?}", cli.output_images))?;

        ota::extract_payload(
            &reader.into_inner(),
            &cli.output_images,
            0,
            payload_size,
            &header,
            &header
                .manifest
                .partitions
                .iter()
                .map(|p| &p.partition_name)
                .cloned()
                .collect(),
            cancel_signal,
        )?;
    }

    Ok(())
}

fn pack_subcommand(
    payload_cli: &PayloadCli,
    cli: &PackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let signing_key = load_key(&cli.key)?;

    let mut header = read_info(&cli.input_info)?;

    // Pre-open all of the image files.
    let input_files = header
        .manifest
        .partitions
        .iter()
        .map(|p| {
            let path =
                util::path_join_single(&cli.input_images, format!("{}.img", p.partition_name))?;
            let file = File::open(&path)
                .map(Arc::new)
                .with_context(|| format!("Failed to open file: {path:?}"))?;

            Ok((p.partition_name.clone(), file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    for (name, input_file) in &input_files {
        let Some(dpm) = &header.manifest.dynamic_partition_metadata else {
            continue;
        };

        if !dpm.groups.iter().any(|g| g.partition_names.contains(name)) {
            continue;
        }

        header
            .manifest
            .partitions
            .iter_mut()
            .find(|p| p.partition_name == *name)
            .unwrap()
            .estimate_cow_size = Some(0);

        ota::recow_image(name, input_file, &mut header, cancel_signal)?;
    }

    // Compress the images and compute the list of install operations for
    // insertion into the payload header. The compressed data is stored in new
    // temp files and the original input files are dropped.
    let mut compressed_files = input_files
        .into_iter()
        .map(|(name, mut input_file)| {
            ota::compress_image(&name, &mut input_file, &mut header, None, cancel_signal)
                .with_context(|| format!("Failed to compress image: {name}"))?;

            Ok((name, input_file))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    info!("Generating new OTA payload");

    // Now we can write the actual payload. With everything precomputed, this is
    // mostly just a simple copy.
    let mut payload_writer = open_writer(&cli.output, header.clone(), signing_key)?;

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

        // The compressed chunks are laid out sequentially and data_offset is
        // set to the offset within that file.
        let Some(input_file) = compressed_files.get_mut(&name) else {
            unreachable!("Compressed data not found for image: {name}");
        };

        input_file
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek image: {name}"))?;

        stream::copy_n(input_file, &mut payload_writer, data_length, cancel_signal)
            .with_context(|| format!("Failed to copy from replacement image: {name}"))?;
    }

    let (_, header, properties, _) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    // Display the header information now that it has been finalized.
    display_header(payload_cli, &header);

    // Optionally, write payload_properties.txt.
    if let Some(path) = &cli.output_properties {
        fs::write(path, properties)
            .with_context(|| format!("Failed to write payload properties: {path:?}"))?;
    }

    Ok(())
}

fn repack_subcommand(
    payload_cli: &PayloadCli,
    cli: &RepackCli,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let signing_key = load_key(&cli.key)?;

    let (mut reader, header) = open_reader(&cli.input, true)?;

    info!("Generating new OTA payload");

    let mut payload_writer = open_writer(&cli.output, header.clone(), signing_key)?;

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

        // Directly copy blobs from the original payload.
        let data_offset = data_offset
            .checked_add(header.blob_offset)
            .ok_or_else(|| anyhow!("data_offset overflow in partition #{pi} operation #{oi}"))?;

        reader
            .seek(SeekFrom::Start(data_offset))
            .with_context(|| format!("Failed to seek original payload to {data_offset}"))?;

        stream::copy_n(&mut reader, &mut payload_writer, data_length, cancel_signal)
            .with_context(|| format!("Failed to copy from original payload: {name}"))?;
    }

    let (_, header, properties, _) = payload_writer
        .finish()
        .context("Failed to finalize payload")?;

    // Display the header information now that it has been finalized.
    display_header(payload_cli, &header);

    // Optionally, write payload_properties.txt.
    if let Some(path) = &cli.output_properties {
        fs::write(path, properties)
            .with_context(|| format!("Failed to write payload properties: {path:?}"))?;
    }

    Ok(())
}

fn info_subcommand(payload_cli: &PayloadCli, cli: &InfoCli) -> Result<()> {
    let (_, header) = open_reader(&cli.input, true)?;

    display_header(payload_cli, &header);

    Ok(())
}

pub fn payload_main(cli: &PayloadCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        PayloadCommand::Unpack(c) => unpack_subcommand(cli, c, cancel_signal),
        PayloadCommand::Pack(c) => pack_subcommand(cli, c, cancel_signal),
        PayloadCommand::Repack(c) => repack_subcommand(cli, c, cancel_signal),
        PayloadCommand::Info(c) => info_subcommand(cli, c),
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

/// Unpack a payload binary.
///
/// Each partition is extracted to `<partition name>.img` in the output images
/// directory. The payload header metadata is written to the info TOML file.
///
/// If any partition names are unsafe to use in a path, the extraction process
/// will fail and exit.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input payload binary.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output info TOML.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "payload.toml"
    )]
    output_info: PathBuf,

    /// Path to output images directory.
    #[arg(
        long,
        value_name = "DIR",
        value_parser,
        default_value = "payload_images"
    )]
    output_images: PathBuf,

    /// Do not output images.
    #[arg(long, conflicts_with = "output_images")]
    no_output_images: bool,
}

/// Pack a payload binary.
///
/// The new payload binary will *only* contain images listed in the info TOML
/// file. Extra images in the input images directory that aren't listed will be
/// silently ignored. Images are added to the payload in the order that they are
/// listed in the info TOML file.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output payload binary.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to output payload properties file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output_properties: Option<PathBuf>,

    /// Path to input info TOML.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "payload.toml"
    )]
    input_info: PathBuf,

    /// Path to input images directory.
    #[arg(
        long,
        value_name = "DIR",
        value_parser,
        default_value = "payload_images"
    )]
    input_images: PathBuf,

    #[command(flatten)]
    key: KeyGroup,
}

/// Repack a payload binary.
///
/// This command is equivalent to running `unpack` and `pack`, except without
/// storing the unpacked data to disk nor recompressing the partition images.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input payload binary.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output payload binary.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to output payload properties file.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output_properties: Option<PathBuf>,

    #[command(flatten)]
    key: KeyGroup,
}

/// Display payload information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input payload binary.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum PayloadCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
}

/// Pack, unpack, and inspect OTA payloads.
#[derive(Debug, Parser)]
pub struct PayloadCli {
    #[command(subcommand)]
    command: PayloadCommand,

    /// Don't print payload header information.
    #[arg(short, long, global = true)]
    quiet: bool,
}
