/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{bail, Result};
use clap::Parser;
use toml_edit::{value, Document};

use crate::WORKSPACE_DIR;

fn update_cargo_version(version: &str) -> Result<()> {
    let path = Path::new(WORKSPACE_DIR).join("Cargo.toml");
    let data = fs::read_to_string(&path)?;

    let mut document: Document = data.parse()?;
    document["workspace"]["package"]["version"] = value(version);

    fs::write(path, document.to_string())?;

    Ok(())
}

fn update_module_version(path: &Path, version: &str) -> Result<()> {
    let mut version_code = 0;

    // 8 bits per version component.
    for piece in version.split('.') {
        let piece: u32 = piece.parse()?;
        version_code <<= 8;
        version_code |= piece;
    }

    let raw_reader = File::open(path)?;
    let mut reader = BufReader::new(raw_reader);
    let mut result = String::new();
    let mut line = String::new();

    loop {
        line.clear();

        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        if line.starts_with("version=") {
            result.push_str(&format!("version=v{version}\n"));
        } else if line.starts_with("versionCode=") {
            result.push_str(&format!("versionCode={version_code}\n"));
        } else {
            result.push_str(&line);
        }
    }

    fs::write(path, &result)?;

    Ok(())
}

fn update_changelog_version(version: &str) -> Result<()> {
    let path = Path::new(WORKSPACE_DIR).join("CHANGELOG.md");
    let raw_reader = File::open(&path)?;
    let mut reader = BufReader::new(raw_reader);
    let mut result = String::new();
    let mut line = String::new();

    let expected = format!("### Version {version}");
    let mut changed = false;

    loop {
        line.clear();

        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim();

        if trimmed.starts_with("### ") {
            if trimmed == expected {
                return Ok(());
            } else if trimmed == "### Unreleased" {
                result.push_str(&expected);
                result.push('\n');
                changed = true;
                continue;
            }
        }

        result.push_str(&line);
    }

    if !changed {
        bail!("CHANGELOG.md does not contain 'Unreleased' heading");
    }

    fs::write(path, result)?;

    Ok(())
}

pub fn set_version_subcommand(cli: &SetVersionCli) -> Result<()> {
    update_cargo_version(&cli.version)?;

    let modules_dir = Path::new(WORKSPACE_DIR).join("modules");

    for entry in fs::read_dir(modules_dir)? {
        let entry = entry?;

        if entry.file_type()?.is_dir() {
            let module_prop = entry.path().join("module.prop");
            if module_prop.exists() {
                update_module_version(&module_prop, &cli.version)?;
            }
        }
    }

    update_changelog_version(&cli.version)?;

    Ok(())
}

/// Set the version number in all Cargo.toml files and in the module metadata.
#[derive(Debug, Parser)]
pub struct SetVersionCli {
    /// Version number.
    #[arg(short = 'V', long, value_name = "VERSION")]
    version: String,
}
