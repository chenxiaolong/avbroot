// SPDX-FileCopyrightText: 2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

use crate::WORKSPACE_DIR;

#[cfg(not(target_os = "windows"))]
const EXE_SUFFIX: &str = "";
#[cfg(target_os = "windows")]
const EXE_SUFFIX: &str = ".exe";

fn run(mut command: Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("Failed to spawn: {command:?}"))?;
    if !status.success() {
        bail!("Command failed with status: {status}: {command:?}");
    }

    Ok(())
}

fn build_avbroot() -> Result<PathBuf> {
    let mut command = Command::new(env!("CARGO"));
    command.arg("build");
    command.current_dir(WORKSPACE_DIR);

    run(command)?;

    let mut executable = Path::new(WORKSPACE_DIR).to_owned();
    if let Some(target_dir) = env::var_os("CARGO_TARGET_DIR") {
        executable.push(target_dir);
    } else {
        executable.push("target");
    }
    executable.push("debug");
    executable.push(format!("avbroot{EXE_SUFFIX}"));

    Ok(executable)
}

fn generate_avb_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let mut command = Command::new(avbroot);
    command.arg("avb");
    command.arg("pack");
    command.arg("-q");
    command.arg("-o");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

fn generate_boot_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let vts_signature_dir = input_dir.join("vts_signature");
    if vts_signature_dir.exists() {
        let mut command = Command::new(avbroot);
        command.arg("avb");
        command.arg("pack");
        command.arg("-q");
        command.arg("-o");
        command.arg("../vts_signature.img");
        command.current_dir(vts_signature_dir);

        run(command)?;
    }

    let mut command = Command::new(avbroot);
    command.arg("boot");
    command.arg("pack");
    command.arg("-q");
    command.arg("-o");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

fn generate_cpio_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let mut command = Command::new(avbroot);
    command.arg("cpio");
    command.arg("pack");
    command.arg("-q");
    command.arg("-o");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

fn generate_fec_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let mut command = Command::new(avbroot);
    command.arg("fec");
    command.arg("generate");
    command.arg("-i");
    command.arg("input.img");
    command.arg("-f");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

fn generate_lp_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let mut command = Command::new(avbroot);
    command.arg("lp");
    command.arg("pack");
    command.arg("-q");
    command.arg("-o");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

fn generate_sparse_image(avbroot: &Path, input_dir: &Path, output_file: &Path) -> Result<()> {
    let mut command = Command::new(avbroot);
    command.arg("sparse");
    command.arg("pack");
    command.arg("-q");
    command.arg("-i");
    command.arg("input.img");
    command.arg("-o");
    command.arg(output_file);
    command.current_dir(input_dir);

    run(command)
}

type Generator = fn(&Path, &Path, &Path) -> Result<()>;

fn generate_corpus(
    avbroot: &Path,
    input_dir: &Path,
    output_dir: &Path,
    generator: Generator,
    suffix: &str,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create directory: {output_dir:?}"))?;

    let parent = fs::read_dir(input_dir)
        .with_context(|| format!("Failed to open directory: {input_dir:?}"))?;

    for entry in parent {
        let entry = entry.with_context(|| format!("Failed to list directory: {input_dir:?}"))?;
        let entry_input_dir = entry.path();
        let mut entry_output_file = output_dir.join(entry.file_name());
        entry_output_file.as_mut_os_string().push(suffix);

        println!("{entry_input_dir:?} -> {entry_output_file:?}");

        generator(avbroot, &entry_input_dir, &entry_output_file)?;
    }

    Ok(())
}

pub fn fuzz_corpus_subcommand() -> Result<()> {
    let fuzz_dir = Path::new(WORKSPACE_DIR).join("fuzz");
    let corpus = fuzz_dir.join("corpus");
    let hfuzz_workspace = fuzz_dir.join("hfuzz_workspace");

    let avbroot = build_avbroot()?;

    let items: [(Generator, _, _); _] = [
        (generate_avb_image, "avb", ".img"),
        (generate_boot_image, "bootimage", ".img"),
        (generate_cpio_image, "cpio", ".cpio"),
        (generate_fec_image, "fec", ".fec"),
        (generate_lp_image, "lp", ".img"),
        (generate_sparse_image, "sparse", ".img"),
    ];

    for (generator, name, suffix) in items {
        let input_dir = corpus.join(name);
        let mut output_dir = hfuzz_workspace.join(name);
        output_dir.push("input");

        generate_corpus(&avbroot, &input_dir, &output_dir, generator, suffix)?;
    }

    Ok(())
}
