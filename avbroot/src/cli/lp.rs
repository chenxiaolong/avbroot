// SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::{self, File},
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::{
    format::lp::{Extent, ExtentType, ImageType, Metadata, SECTOR_SIZE},
    stream::{self, FromReader, ToWriter, UserPosFile},
    util,
};

fn open_lp_inputs(paths: &[impl AsRef<Path>]) -> Result<(Vec<File>, Metadata)> {
    let inputs = paths
        .iter()
        .map(|p| {
            let p = p.as_ref();

            File::open(p).with_context(|| format!("Failed to open LP image for reading: {p:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let metadata = Metadata::from_reader(&inputs[0])
        .with_context(|| format!("Failed to parse LP image metadata: {:?}", paths[0].as_ref()))?;

    Ok((inputs, metadata))
}

fn open_lp_outputs(paths: &[impl AsRef<Path>]) -> Result<Vec<File>> {
    paths
        .iter()
        .map(|p| {
            let p = p.as_ref();

            File::create(p).with_context(|| format!("Failed to open LP image for writing: {p:?}"))
        })
        .collect::<Result<Vec<_>>>()
}

fn read_info(path: &Path) -> Result<Metadata> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read metadata info TOML: {path:?}"))?;
    let info = toml::de::from_str(&data)
        .with_context(|| format!("Failed to parse metadata info TOML: {path:?}"))?;

    Ok(info)
}

fn write_info(path: &Path, metadata: &Metadata) -> Result<()> {
    let data = toml::ser::to_string_pretty(metadata)
        .with_context(|| format!("Failed to serialize metadata info TOML: {path:?}"))?;
    fs::write(path, data)
        .with_context(|| format!("Failed to write metadata info TOML: {path:?}"))?;

    Ok(())
}

fn display_metadata(cli: &LpCli, metadata: &Metadata) {
    if !cli.quiet {
        println!("{metadata:#?}");
    }
}

struct CopyExtent {
    device_index: usize,
    lp_offset: u64,
    out_offset: u64,
    size: u64,
}

/// Split extents into smaller ones for parallelization.
fn split_extents(extents: &[Extent]) -> Vec<CopyExtent> {
    // 64 MiB is the smallest size we'll parallelize by.
    const CHUNK_SIZE: u64 = 64 * 1024 * 1024;

    let mut result = vec![];
    let mut out_offset = 0;

    for extent in extents {
        let mut remain = extent.num_sectors * u64::from(SECTOR_SIZE);

        match extent.extent_type {
            ExtentType::Linear {
                start_sector,
                block_device_index,
            } => {
                let mut lp_offset = start_sector * u64::from(SECTOR_SIZE);

                // 64 MiB is the smallest size we'll parallelize by.
                let num_chunks = remain.div_ceil(64 * 1024 * 1024);

                for _ in 0..num_chunks {
                    let chunk_size = CHUNK_SIZE.min(remain);

                    result.push(CopyExtent {
                        device_index: block_device_index,
                        out_offset,
                        lp_offset,
                        size: chunk_size,
                    });

                    out_offset += chunk_size;
                    lp_offset += chunk_size;
                    remain -= chunk_size;
                }
            }
            ExtentType::Zero => out_offset += remain,
        }
    }

    result
}

/// Use the CLI-specified slot or automatically select one if all slots are
/// identical.
fn get_slot_number(metadata: &Metadata, cli_slot: Option<u32>) -> Result<usize> {
    if let Some(n) = cli_slot {
        let n = n as usize;
        if n >= metadata.slots.len() {
            bail!("Slot out of range: {n}");
        }

        Ok(n)
    } else {
        if metadata.slots.windows(2).any(|w| w[0] != w[1]) {
            bail!("A slot must be specified because they are not all identical");
        }

        Ok(0)
    }
}

/// Remove all slots aside from the specified one and return the old slot count.
fn retain_slot(metadata: &mut Metadata, slot: usize) -> usize {
    let slot_count = metadata.slots.len();
    metadata.slots.swap(0, slot);
    metadata.slots.truncate(1);
    slot_count
}

/// Duplicate the first slot until the required number of slots is reached.
fn fill_slots(metadata: &mut Metadata) {
    let required = match metadata.image_type {
        ImageType::Normal => metadata.metadata_slot_count as usize,
        ImageType::Empty => 1,
    };

    for _ in metadata.slots.len()..required {
        metadata.slots.extend_from_within(0..=0);
    }
}

fn unpack_subcommand(lp_cli: &LpCli, cli: &UnpackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let inputs = cli
        .input
        .iter()
        .map(|p| {
            File::open(p).with_context(|| format!("Failed to open LP image for reading: {p:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut metadata = Metadata::from_reader(&inputs[0])
        .with_context(|| format!("Failed to read LP image metadata: {:?}", cli.input[0]))?;

    // Display and write only the selected slot.
    let slot_number = get_slot_number(&metadata, cli.slot)?;
    retain_slot(&mut metadata, slot_number);
    display_metadata(lp_cli, &metadata);
    write_info(&cli.output_info, &metadata)?;

    // For empty images, there's no data to unpack.
    if metadata.image_type == ImageType::Empty || cli.no_output_images {
        return Ok(());
    }

    fs::create_dir_all(&cli.output_images)
        .with_context(|| format!("Failed to create directory: {:?}", cli.output_images))?;

    let slot = &metadata.slots[0];

    if slot.block_devices.len() != inputs.len() {
        bail!(
            "Need {} input images, but have {}",
            slot.block_devices.len(),
            inputs.len(),
        );
    }

    // Preopen all image output files.
    let mut paths = vec![];
    let mut files = vec![];

    for group in &slot.groups {
        let mut group_paths = vec![];
        let mut group_files = vec![];

        for partition in &group.partitions {
            // A partition name with unsafe characters fails during parsing.
            let path =
                util::path_join_single(&cli.output_images, format!("{}.img", partition.name))?;

            let file = File::create(&path)
                .with_context(|| format!("Failed to open for writing: {path:?}"))?;

            file.set_len(partition.size()?)
                .with_context(|| format!("Failed to truncate file: {path:?}"))?;

            group_paths.push(path);
            group_files.push(file);
        }

        paths.push(group_paths);
        files.push(group_files);
    }

    slot.groups
        .par_iter()
        .enumerate()
        // Flatten grouped partitions.
        .flat_map(|(g_index, g)| {
            g.partitions
                .par_iter()
                .enumerate()
                .map(move |(p_index, p)| (g_index, p_index, p))
        })
        // Flatten extents in all partitions and split them to smaller chunks
        // for better parallelism.
        .flat_map(|(g_index, p_index, p)| {
            split_extents(&p.extents)
                .into_par_iter()
                .map(move |e| (g_index, p_index, e))
        })
        .try_for_each(|(g_index, p_index, extent)| {
            let mut reader = UserPosFile::new(&inputs[extent.device_index]);
            let mut writer = UserPosFile::new(&files[g_index][p_index]);

            let r_path = &cli.input[extent.device_index];
            let w_path = &paths[g_index][p_index];

            reader
                .seek(SeekFrom::Start(extent.lp_offset))
                .with_context(|| format!("Failed to seek file: {r_path:?}"))?;
            writer
                .seek(SeekFrom::Start(extent.out_offset))
                .with_context(|| format!("Failed to seek file: {w_path:?}"))?;

            stream::copy_n(&mut reader, &mut writer, extent.size, cancel_signal)
                .with_context(|| format!("Failed to copy extent: {r_path:?} -> {w_path:?}"))?;

            Ok(())
        })
}

fn pack_subcommand(lp_cli: &LpCli, cli: &PackCli, cancel_signal: &AtomicBool) -> Result<()> {
    let mut metadata = read_info(&cli.input_info)?;

    if metadata.slots.len() != 1 {
        bail!("There must be exactly one metadata slot");
    }

    let slot = &mut metadata.slots[0];

    let mut outputs = open_lp_outputs(&cli.output)?;

    if slot.block_devices.len() != outputs.len() {
        bail!(
            "Need {} output images, but have {}",
            slot.block_devices.len(),
            outputs.len(),
        );
    }

    if metadata.image_type == ImageType::Normal {
        for (i, (block_device, output)) in slot.block_devices.iter().zip(&outputs).enumerate() {
            output
                .set_len(block_device.size)
                .with_context(|| format!("Failed to truncate file: {:?}", cli.output[i]))?;
        }
    }

    // Preopen all image input files.
    let mut paths = vec![];
    let mut files = vec![];

    if metadata.image_type == ImageType::Normal {
        for group in &mut slot.groups {
            let mut group_paths = vec![];
            let mut group_files = vec![];

            for partition in &mut group.partitions {
                let path =
                    util::path_join_single(&cli.input_images, format!("{}.img", partition.name))?;

                let mut file = File::open(&path)
                    .with_context(|| format!("Failed to open for reading: {path:?}"))?;

                let size = file
                    .seek(SeekFrom::End(0))
                    .with_context(|| format!("Failed to seek file: {path:?}"))?;

                if size % u64::from(SECTOR_SIZE) != 0 {
                    bail!("File size is not {SECTOR_SIZE}B aligned: {size}: {path:?}");
                }

                // This will be filled out properly later during reallocation.
                partition.extents.push(Extent {
                    num_sectors: size / u64::from(SECTOR_SIZE),
                    extent_type: ExtentType::Linear {
                        start_sector: 0,
                        block_device_index: 0,
                    },
                });

                group_paths.push(path);
                group_files.push(file);
            }

            paths.push(group_paths);
            files.push(group_files);
        }

        // Now that we have all the partition sizes, actually allocate extents
        // for them on the block devices.
        slot.reallocate_extents()
            .context("Failed to allocate extents")?;
    }

    // Display only the selected slot and make the rest identical.
    let _ = slot;
    display_metadata(lp_cli, &metadata);
    fill_slots(&mut metadata);
    let slot = &metadata.slots[0];

    // Write the new metadata.
    metadata
        .to_writer(&mut outputs[0])
        .with_context(|| format!("Failed to write LP image metadata: {:?}", cli.output[0]))?;

    // For empty images, there's no data to pack.
    if metadata.image_type == ImageType::Empty {
        return Ok(());
    }

    slot.groups
        .par_iter()
        .enumerate()
        // Flatten grouped partitions.
        .flat_map(|(g_index, g)| {
            g.partitions
                .par_iter()
                .enumerate()
                .map(move |(p_index, p)| (g_index, p_index, p))
        })
        // Flatten extents in all partitions and split them to smaller chunks
        // for better parallelism.
        .flat_map(|(g_index, p_index, p)| {
            split_extents(&p.extents)
                .into_par_iter()
                .map(move |e| (g_index, p_index, e))
        })
        .try_for_each(|(g_index, p_index, extent)| {
            let mut reader = UserPosFile::new(&files[g_index][p_index]);
            let mut writer = UserPosFile::new(&outputs[extent.device_index]);

            let r_path = &paths[g_index][p_index];
            let w_path = &cli.output[extent.device_index];

            reader
                .seek(SeekFrom::Start(extent.out_offset))
                .with_context(|| format!("Failed to seek file: {r_path:?}"))?;
            writer
                .seek(SeekFrom::Start(extent.lp_offset))
                .with_context(|| format!("Failed to seek file: {w_path:?}"))?;

            stream::copy_n(&mut reader, &mut writer, extent.size, cancel_signal)
                .with_context(|| format!("Failed to copy extent: {r_path:?} -> {w_path:?}"))?;

            Ok(())
        })
}

fn repack_subcommand(lp_cli: &LpCli, cli: &RepackCli, cancel_signal: &AtomicBool) -> Result<()> {
    // Show a clap-style error if the number of inputs and outputs aren't equal.
    if cli.input.len() != cli.output.len() {
        let (arg_id, actual_len, expected_len) = if cli.input.len() < cli.output.len() {
            ("input", cli.input.len(), cli.output.len())
        } else {
            ("output", cli.output.len(), cli.input.len())
        };

        let mut command = RepackCli::command();
        command.build();

        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == arg_id)
            .expect("argument not found");

        let mut error =
            clap::Error::new(clap::error::ErrorKind::WrongNumberOfValues).with_cmd(&command);
        error.insert(
            clap::error::ContextKind::InvalidArg,
            clap::error::ContextValue::String(arg.to_string()),
        );
        error.insert(
            clap::error::ContextKind::ActualNumValues,
            clap::error::ContextValue::Number(actual_len as isize),
        );
        error.insert(
            clap::error::ContextKind::ExpectedNumValues,
            clap::error::ContextValue::Number(expected_len as isize),
        );

        // We don't show the usage because only Command::_build_subcommand() can
        // create an appropriate Command instance for showing the subcommand
        // usage and there's no way to call that, directly or indirectly.

        error.exit();
    }

    let (inputs, mut metadata) = open_lp_inputs(&cli.input)?;
    let mut outputs = open_lp_outputs(&cli.output)?;

    // Display only the selected slot and make the rest identical.
    let slot_number = get_slot_number(&metadata, cli.slot)?;
    retain_slot(&mut metadata, slot_number);
    display_metadata(lp_cli, &metadata);
    fill_slots(&mut metadata);

    let slot = &metadata.slots[0];

    if slot.block_devices.len() != inputs.len() {
        bail!(
            "Need {} images, but have {}",
            slot.block_devices.len(),
            inputs.len(),
        );
    }

    // Write the new metadata.
    metadata
        .to_writer(&mut outputs[0])
        .with_context(|| format!("Failed to write LP image metadata: {:?}", cli.output[0]))?;

    // Explicitly set the file size in case there are dm-zero extents, which are
    // ignored below.
    if metadata.image_type == ImageType::Normal {
        for (i, (block_device, output)) in slot.block_devices.iter().zip(&outputs).enumerate() {
            output
                .set_len(block_device.size)
                .with_context(|| format!("Failed to truncate file: {:?}", cli.output[i]))?;
        }
    }

    slot.groups
        .par_iter()
        // Flatten grouped partitions.
        .flat_map(|group| &group.partitions)
        // Flatten extents in all partitions and split them to smaller chunks
        // for better parallelism.
        .flat_map(|partition| split_extents(&partition.extents))
        .try_for_each(|extent| {
            let mut reader = UserPosFile::new(&inputs[extent.device_index]);
            let mut writer = UserPosFile::new(&outputs[extent.device_index]);

            let r_path = &cli.input[extent.device_index];
            let w_path = &cli.output[extent.device_index];

            reader
                .seek(SeekFrom::Start(extent.lp_offset))
                .with_context(|| format!("Failed to seek file: {r_path:?}"))?;
            writer
                .seek(SeekFrom::Start(extent.lp_offset))
                .with_context(|| format!("Failed to seek file: {w_path:?}"))?;

            stream::copy_n(&mut reader, &mut writer, extent.size, cancel_signal)
                .with_context(|| format!("Failed to copy extent: {r_path:?} -> {w_path:?}"))?;

            Ok(())
        })
}

fn info_subcommand(lp_cli: &LpCli, cli: &InfoCli) -> Result<()> {
    let (_, metadata) = open_lp_inputs(&[&cli.input])?;

    // Unlike the other subcommands, we show all metadata slots here.
    display_metadata(lp_cli, &metadata);

    Ok(())
}

pub fn lp_main(cli: &LpCli, cancel_signal: &AtomicBool) -> Result<()> {
    match &cli.command {
        LpCommand::Unpack(c) => unpack_subcommand(cli, c, cancel_signal),
        LpCommand::Pack(c) => pack_subcommand(cli, c, cancel_signal),
        LpCommand::Repack(c) => repack_subcommand(cli, c, cancel_signal),
        LpCommand::Info(c) => info_subcommand(cli, c),
    }
}

/// Unpack an LP image.
///
/// The LP image metadata is written to the info TOML file. For normal images,
/// each partition is extracted to `<partition name>.img` in the output images
/// directory. For empty images, the output images directory is unused.
///
/// If any partition names are unsafe to use in a path, the extraction process
/// will fail and exit. Extracted files are never written outside of the tree
/// directory, even if an external process tries to interfere.
#[derive(Debug, Parser)]
struct UnpackCli {
    /// Path to input LP images.
    ///
    /// If there are multiple images, they must be specified in order. If the
    /// order is unknown, run `avbroot lp info` against the `super` image and
    /// look at the `block_devices` field.
    #[arg(short, long, value_name = "FILE", value_parser, required = true)]
    input: Vec<PathBuf>,

    /// Path to output info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "lp.toml")]
    output_info: PathBuf,

    /// Path to output images directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "lp_images")]
    output_images: PathBuf,

    /// Do not output images.
    #[arg(long, conflicts_with = "output_images")]
    no_output_images: bool,

    /// The LP metadata slot to use.
    ///
    /// This slot is the only slot where data extents are copied from. Any data
    /// referenced exclusively by other slots (if any) will be ignored.
    ///
    /// This option is required if not all slots are identical.
    #[arg(short, long)]
    slot: Option<u32>,
}

/// Pack an LP image.
///
/// For normal images, the number of metadata slots written is equal to the
/// `metadata_slot_count` value in the info TOML. Each slot has identical
/// metadata. It is not possible to write multiple slots with different metadata
/// using this tool. For empty images, only a single slot is written, regardless
/// of the value of `metadata_slot_count`, as required by the file format.
///
/// The new LP image will *only* contain images listed in the info TOML file and
/// they are added in the order listed. The input images directory is not used
/// when packing an empty image.
#[derive(Debug, Parser)]
struct PackCli {
    /// Path to output LP images.
    ///
    /// If there are multiple images, they must be specified in the same order
    /// as the block device entries are listed in the info TOML.
    #[arg(short, long, value_name = "FILE", value_parser, required = true)]
    output: Vec<PathBuf>,

    /// Path to input info TOML.
    #[arg(long, value_name = "FILE", value_parser, default_value = "lp.toml")]
    input_info: PathBuf,

    /// Path to input images directory.
    #[arg(long, value_name = "DIR", value_parser, default_value = "lp_images")]
    input_images: PathBuf,
}

/// Repack an LP image.
///
/// This command is equivalent to running `unpack` and `pack`, except without
/// storing the unpacked data to disk.
#[derive(Debug, Parser)]
struct RepackCli {
    /// Path to input LP images.
    ///
    /// If there are multiple images, they must be specified in order. If the
    /// order is unknown, run `avbroot lp info` against the `super` image and
    /// look at the `block_devices` field.
    #[arg(short, long, value_name = "FILE", value_parser, required = true)]
    input: Vec<PathBuf>,

    /// Path to output LP images.
    ///
    /// The number of output images must equal the number of input images.
    #[arg(short, long, value_name = "FILE", value_parser, required = true)]
    output: Vec<PathBuf>,

    /// The LP metadata slot to use.
    ///
    /// This slot is the only slot where data extents are copied to the output
    /// images. Any data referenced exclusively by other slots (if any) will be
    /// ignored.
    ///
    /// This option is required if not all slots are identical.
    #[arg(short, long)]
    slot: Option<u32>,
}

/// Display LP image metadata.
#[derive(Debug, Parser)]
struct InfoCli {
    /// Path to input LP image.
    ///
    /// If there are multiple images, this should refer to the first one, which
    /// is usually the `super` image. The other images are not needed when
    /// inspecting the metadata because the metadata is only stored in the first
    /// image.
    #[arg(short, long, value_name = "FILE", value_parser)]
    input: PathBuf,
}

#[derive(Debug, Subcommand)]
enum LpCommand {
    Unpack(UnpackCli),
    Pack(PackCli),
    Repack(RepackCli),
    Info(InfoCli),
}

/// Pack, unpack, and inspect LP images.
#[derive(Debug, Parser)]
pub struct LpCli {
    #[command(subcommand)]
    command: LpCommand,

    /// Don't print LP metadata information.
    #[arg(short, long, global = true)]
    quiet: bool,
}
