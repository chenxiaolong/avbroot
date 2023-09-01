/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, ValueEnum};
use tempfile::TempDir;
use walkdir::WalkDir;
use zip::{write::FileOptions, ZipWriter};

use crate::WORKSPACE_DIR;

#[cfg(unix)]
const D8: &str = "d8";
#[cfg(windows)]
const D8: &str = "d8.bat";

fn newest_child_by_name(directory: &Path) -> Result<PathBuf> {
    let mut children = vec![];

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry
            .path()
            .into_os_string()
            .into_string()
            .map_err(|e| anyhow!("Non-UTF-8 path: {e:?}"))?;

        children.push(path);
    }

    children.sort_by(|a, b| human_sort::compare(a, b));

    children
        .pop()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("{directory:?} has no children"))
}

fn build_empty_zip(writer: &mut dyn Write) -> Result<()> {
    let mut writer = ZipWriter::new_streaming(writer);
    writer.finish()?;
    Ok(())
}

fn build_dex(writer: &mut dyn Write, sources: &[&Path]) -> Result<()> {
    let sdk = env::var_os("ANDROID_HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("ANDROID_HOME must be set to the Android SDK path"))?;
    let build_tools = newest_child_by_name(&sdk.join("build-tools"))?;
    let platform = newest_child_by_name(&sdk.join("platforms"))?;
    let d8 = build_tools.join(D8);
    let android_jar = platform.join("android.jar");

    let temp_dir = TempDir::new()?;

    let mut process = Command::new("javac")
        .args(["-source", "1.8"])
        .args(["-target", "1.8"])
        .arg("-cp")
        .arg(android_jar)
        .arg("-d")
        .arg(temp_dir.path())
        .args(sources)
        .spawn()?;
    let status = process.wait()?;
    if !status.success() {
        bail!("javac failed with {status}");
    }

    let mut class_files = vec![];

    for entry in WalkDir::new(temp_dir.path()) {
        let entry = entry?;

        if entry.path().extension() == Some(OsStr::new("class")) {
            class_files.push(entry.into_path());
        }
    }

    let mut process = Command::new(d8)
        .arg("--output")
        .arg(temp_dir.path())
        .args(class_files)
        .spawn()?;
    let status = process.wait()?;
    if !status.success() {
        bail!("d8 failed with {status}");
    }

    let mut reader = File::open(temp_dir.path().join("classes.dex"))?;
    io::copy(&mut reader, writer)?;

    Ok(())
}

fn parse_props(data: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();

    for line in data.split('\n') {
        if line.is_empty() {
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            bail!("Malformed line: {line:?}");
        };

        result.insert(k.trim().to_owned(), v.trim().to_owned());
    }

    Ok(result)
}

fn start_module(
    dist_dir: &Path,
    common_dir: &Path,
    module_dir: &Path,
) -> Result<(PathBuf, ZipWriter<BufWriter<File>>)> {
    let module_prop_raw = fs::read_to_string(module_dir.join("module.prop"))?;
    let module_prop = parse_props(&module_prop_raw)?;

    let name = module_prop["name"].as_str();
    let version = module_prop["version"].as_str();
    let version = version.strip_prefix('v').unwrap_or(version);
    let zip_path = dist_dir.join(format!("{name}-{version}.zip"));

    let raw_writer = File::create(&zip_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(raw_writer));

    zip_writer.start_file(
        "META-INF/com/google/android/update-binary",
        FileOptions::default(),
    )?;
    io::copy(
        &mut File::open(common_dir.join("update-binary"))?,
        &mut zip_writer,
    )?;

    zip_writer.start_file(
        "META-INF/com/google/android/updater-script",
        FileOptions::default(),
    )?;
    io::copy(
        &mut File::open(common_dir.join("updater-script"))?,
        &mut zip_writer,
    )?;

    zip_writer.start_file("module.prop", FileOptions::default())?;
    zip_writer.write_all(module_prop_raw.as_bytes())?;

    Ok((zip_path, zip_writer))
}

pub fn modules_subcommand(cli: &ModulesCli) -> Result<()> {
    let modules_dir = Path::new(WORKSPACE_DIR).join("modules");
    let common_dir = modules_dir.join("common");
    let dist_dir = modules_dir.join("dist");

    fs::create_dir_all(&dist_dir)?;

    let modules = if cli.module.all {
        Module::value_variants()
    } else {
        &cli.module.module
    };

    for module in modules {
        let module_dir = modules_dir.join(module.to_string());

        let (path, mut writer) = start_module(&dist_dir, &common_dir, &module_dir)?;

        match module {
            Module::ClearOtaCerts => {
                writer.start_file("system/etc/security/otacerts.zip", FileOptions::default())?;
                build_empty_zip(&mut writer)?;
            }
            Module::OemUnlockOnBoot => {
                writer.start_file("classes.dex", FileOptions::default())?;
                build_dex(&mut writer, &[&module_dir.join("Main.java")])?;

                writer.start_file("service.sh", FileOptions::default())?;
                let mut reader = File::open(module_dir.join("service.sh"))?;
                io::copy(&mut reader, &mut writer)?;
            }
        }

        writer.finish()?;

        let path = path.canonicalize()?;
        println!("Built module: {path:?}");
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "lower")]
enum Module {
    ClearOtaCerts,
    OemUnlockOnBoot,
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ModuleGroup {
    /// Name of module.
    #[arg(short, long)]
    module: Vec<Module>,

    /// Build all modules.
    #[arg(short, long, conflicts_with = "module")]
    all: bool,
}

/// Build companion modules.
#[derive(Debug, Parser)]
pub struct ModulesCli {
    #[command(flatten)]
    module: ModuleGroup,
}
