/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Cursor, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::{
    format::{avb::Header, bootimage::BootImage, compression::CompressedReader, cpio},
    stream::{FromReader, ToWriter},
};

fn read_image(path: &Path) -> Result<BootImage> {
    let file = File::open(path).with_context(|| format!("Failed to open for reading: {path:?}"))?;
    let reader = BufReader::new(file);
    let image = BootImage::from_reader(reader)
        .with_context(|| format!("Failed to read boot image: {path:?}"))?;

    Ok(image)
}

fn write_image(path: &Path, image: &BootImage) -> Result<()> {
    let file =
        File::create(path).with_context(|| format!("Failed to open for writing: {path:?}"))?;
    let mut writer = BufWriter::new(file);
    image
        .to_writer(&mut writer)
        .with_context(|| format!("Failed to write boot image: {path:?}"))?;
    writer
        .flush()
        .with_context(|| format!("Failed to flush boot image: {path:?}"))?;

    Ok(())
}

fn read_header(path: &Path) -> Result<BootImage> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read header TOML: {path:?}"))?;
    let image = toml_edit::de::from_str(&data)
        .with_context(|| format!("Failed to parse header TOML: {path:?}"))?;

    Ok(image)
}

fn write_header(path: &Path, image: &BootImage) -> Result<()> {
    let data = toml_edit::ser::to_string_pretty(image)
        .with_context(|| format!("Failed to serialize header TOML: {path:?}"))?;
    fs::write(path, data).with_context(|| format!("Failed to write header TOML: {path:?}"))?;

    Ok(())
}

fn read_data_if_exists(path: &Path) -> Result<Option<Vec<u8>>> {
    let data = match fs::read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read data: {path:?}"))?,
    };

    Ok(Some(data))
}

fn read_text_if_exists(path: &Path) -> Result<Option<String>> {
    let data = match fs::read_to_string(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read text: {path:?}"))?,
    };

    Ok(Some(data))
}

fn read_avb_header_if_exists(path: &Path) -> Result<Option<Header>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to open for reading: {path:?}"))?,
    };
    let header = Header::from_reader(BufReader::new(file))
        .with_context(|| format!("Failed to read vbmeta header: {path:?}"))?;

    Ok(Some(header))
}

fn write_data_if_not_empty(path: &Path, data: &[u8]) -> Result<()> {
    if !data.is_empty() {
        fs::write(path, data).with_context(|| format!("Failed to write data: {path:?}"))?;
    }

    Ok(())
}

fn write_text_if_not_empty(path: &Path, text: &str) -> Result<()> {
    if !text.is_empty() {
        fs::write(path, text.as_bytes())
            .with_context(|| format!("Failed to write text: {path:?}"))?;
    }

    Ok(())
}

fn write_avb_header(path: &Path, header: &Header) -> Result<()> {
    let file =
        File::create(path).with_context(|| format!("Failed to open for writing: {path:?}"))?;
    header.to_writer(BufWriter::new(file))?;

    Ok(())
}

fn display_info(cli: &BootCli, image: &BootImage) {
    if !cli.quiet {
        if cli.debug {
            println!("{image:#?}");
        } else {
            println!("{image}");
        }
    }
}

fn unpack_subcommand(boot_cli: &BootCli, cli: &UnpackCli) -> Result<()> {
    let image = read_image(&cli.input)?;
    display_info(boot_cli, &image);

    write_header(&cli.output_header, &image)?;

    let mut kernel = None;
    let mut second = None;
    let mut recovery_dtbo = None;
    let mut dtb = None;
    let mut vts_signature = None;
    let mut bootconfig = None;
    let mut ramdisks = vec![];

    match &image {
        BootImage::V0Through2(b) => {
            kernel = Some(&b.kernel);
            second = Some(&b.second);
            if let Some(v1) = &b.v1_extra {
                recovery_dtbo = Some(&v1.recovery_dtbo);
            }
            if let Some(v2) = &b.v2_extra {
                dtb = Some(&v2.dtb);
            }
            ramdisks.push(&b.ramdisk);
        }
        BootImage::V3Through4(b) => {
            kernel = Some(&b.kernel);
            if let Some(v4) = &b.v4_extra {
                vts_signature = v4.signature.as_ref();
            }
            ramdisks.push(&b.ramdisk);
        }
        BootImage::VendorV3Through4(b) => {
            dtb = Some(&b.dtb);
            if let Some(v4) = &b.v4_extra {
                bootconfig = Some(&v4.bootconfig);
            }
            ramdisks.extend(b.ramdisks.iter());
        }
    }

    if let Some(data) = kernel {
        write_data_if_not_empty(&cli.output_kernel, data)?;
    }
    if let Some(data) = second {
        write_data_if_not_empty(&cli.output_second, data)?;
    }
    if let Some(data) = recovery_dtbo {
        write_data_if_not_empty(&cli.output_recovery_dtbo, data)?;
    }
    if let Some(data) = dtb {
        write_data_if_not_empty(&cli.output_dtb, data)?;
    }
    if let Some(header) = vts_signature {
        write_avb_header(&cli.output_vts_signature, header)?;
    }
    if let Some(text) = bootconfig {
        write_text_if_not_empty(&cli.output_bootconfig, text)?;
    }

    for (i, data) in ramdisks.iter().enumerate() {
        let mut path = cli.output_ramdisk_prefix.as_os_str().to_owned();
        path.push(i.to_string());

        write_data_if_not_empty(Path::new(&path), data)?;
    }

    Ok(())
}

fn pack_subcommand(boot_cli: &BootCli, cli: &PackCli) -> Result<()> {
    let mut image = read_header(&cli.input_header)?;

    let kernel = read_data_if_exists(&cli.input_kernel)?;
    let second = read_data_if_exists(&cli.input_second)?;
    let recovery_dtbo = read_data_if_exists(&cli.input_recovery_dtbo)?;
    let dtb = read_data_if_exists(&cli.input_dtb)?;
    let vts_signature = read_avb_header_if_exists(&cli.input_vts_signature)?;
    let bootconfig = read_text_if_exists(&cli.input_bootconfig)?;
    let mut ramdisks = vec![];

    for i in 0.. {
        let mut path = cli.input_ramdisk_prefix.as_os_str().to_owned();
        path.push(i.to_string());

        let Some(ramdisk) = read_data_if_exists(Path::new(&path))? else {
            break;
        };

        ramdisks.push(ramdisk);
    }

    match &mut image {
        BootImage::V0Through2(b) => {
            b.kernel = kernel.unwrap_or_default();
            b.second = second.unwrap_or_default();
            if let Some(v1) = &mut b.v1_extra {
                v1.recovery_dtbo = recovery_dtbo.unwrap_or_default();
            }
            if let Some(v2) = &mut b.v2_extra {
                v2.dtb = dtb.unwrap_or_default();
            }
            if ramdisks.len() > 1 {
                bail!("Image type only supports a single ramdisk");
            }
            b.ramdisk = ramdisks.into_iter().next().unwrap_or_default();
        }
        BootImage::V3Through4(b) => {
            b.kernel = kernel.unwrap_or_default();
            if let Some(v4) = &mut b.v4_extra {
                v4.signature = vts_signature;
            }
            if ramdisks.len() > 1 {
                bail!("Image type only supports a single ramdisk");
            }
            b.ramdisk = ramdisks.into_iter().next().unwrap_or_default();
        }
        BootImage::VendorV3Through4(b) => {
            b.dtb = dtb.unwrap_or_default();
            if let Some(v4) = &mut b.v4_extra {
                v4.bootconfig = bootconfig.unwrap_or_default();
            }
            b.ramdisks = ramdisks;
        }
    }

    display_info(boot_cli, &image);
    write_image(&cli.output, &image)?;

    Ok(())
}

fn repack_subcommand(boot_cli: &BootCli, cli: &RepackCli) -> Result<()> {
    let image = read_image(&cli.input)?;
    display_info(boot_cli, &image);
    write_image(&cli.output, &image)?;

    Ok(())
}

fn info_subcommand(boot_cli: &BootCli, cli: &InfoCli) -> Result<()> {
    let image = read_image(&cli.input)?;
    display_info(boot_cli, &image);

    Ok(())
}

pub fn magisk_info_subcommand(cli: &MagiskInfoCli) -> Result<()> {
    let raw_reader = File::open(&cli.image)
        .with_context(|| format!("Failed to open for reading: {:?}", cli.image))?;
    let boot_image = BootImage::from_reader(BufReader::new(raw_reader))
        .with_context(|| format!("Failed to load boot image: {:?}", cli.image))?;

    let mut ramdisks = vec![];

    match &boot_image {
        BootImage::V0Through2(b) => {
            if !b.ramdisk.is_empty() {
                ramdisks.push(&b.ramdisk);
            }
        }
        BootImage::V3Through4(b) => {
            if !b.ramdisk.is_empty() {
                ramdisks.push(&b.ramdisk);
            }
        }
        BootImage::VendorV3Through4(b) => {
            ramdisks.extend(b.ramdisks.iter());
        }
    }

    for (i, ramdisk) in ramdisks.iter().enumerate() {
        let reader = Cursor::new(ramdisk);
        let reader = CompressedReader::new(reader, true)
            .with_context(|| format!("Failed to load ramdisk #{i}"))?;
        let entries = cpio::load(reader, false)
            .with_context(|| format!("Failed to load ramdisk #{i} cpio"))?;

        if let Some(e) = entries.iter().find(|e| e.name == b".backup/.magisk") {
            io::stdout().write_all(&e.content)?;
            return Ok(());
        }
    }

    bail!("Not a Magisk-patched boot image");
}

pub fn boot_main(cli: &BootCli) -> Result<()> {
    match &cli.command {
        BootCommand::Unpack(c) => unpack_subcommand(cli, c),
        BootCommand::Pack(c) => pack_subcommand(cli, c),
        BootCommand::Repack(c) => repack_subcommand(cli, c),
        BootCommand::Info(c) => info_subcommand(cli, c),
        BootCommand::MagiskInfo(c) => magisk_info_subcommand(c),
    }
}

/// Unpack a boot image.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output header TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "header.toml")]
    output_header: PathBuf,

    /// Path to output kernel image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "kernel.img")]
    output_kernel: PathBuf,

    /// Path prefix for output ramdisk images.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "ramdisk.img."
    )]
    output_ramdisk_prefix: PathBuf,

    /// Path to output second stage bootloader image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "second.img")]
    output_second: PathBuf,

    /// Path to output recovery dtbo/acpio image.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "recovery_dtbo.img"
    )]
    output_recovery_dtbo: PathBuf,

    /// Path to output device tree blob image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "dtb.img")]
    output_dtb: PathBuf,

    /// Path to output VTS signature.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "vts_signature.img"
    )]
    output_vts_signature: PathBuf,

    /// Path to output bootconfig text.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "bootconfig.txt"
    )]
    output_bootconfig: PathBuf,
}

/// Pack a boot image.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to input header TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "header.toml")]
    input_header: PathBuf,

    /// Path to input kernel image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "kernel.img")]
    input_kernel: PathBuf,

    /// Path prefix for input ramdisk images.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "ramdisk.img."
    )]
    input_ramdisk_prefix: PathBuf,

    /// Path to input second stage bootloader image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "second.img")]
    input_second: PathBuf,

    /// Path to input recovery dtbo/acpio image.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "recovery_dtbo.img"
    )]
    input_recovery_dtbo: PathBuf,

    /// Path to input device tree blob image.
    #[arg(long, value_name = "FILE", value_parser, default_value = "dtb.img")]
    input_dtb: PathBuf,

    /// Path to input VTS signature.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "vts_signature.img"
    )]
    input_vts_signature: PathBuf,

    /// Path to input bootconfig text.
    #[arg(
        long,
        value_name = "FILE",
        value_parser,
        default_value = "bootconfig.txt"
    )]
    input_bootconfig: PathBuf,
}

/// Repack a boot image.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,

    /// Path to output boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,
}

/// Display boot image header information.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

/// Print Magisk config from a patched boot image.
#[derive(Debug, Parser)]
pub struct MagiskInfoCli {
    /// Path to Magisk-patched boot image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    pub image: PathBuf,
}

#[derive(Debug, Subcommand)]
enum BootCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
    MagiskInfo(MagiskInfoCli),
}

/// Pack or unpack boot images.
#[derive(Debug, Parser)]
pub struct BootCli {
    #[command(subcommand)]
    command: BootCommand,

    /// Don't print boot image header information.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Print boot image header information in debug format.
    #[arg(short, long, global = true)]
    debug: bool,
}
