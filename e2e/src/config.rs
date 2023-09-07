/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{collections::BTreeMap, fs, ops::Range, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use toml_edit::{
    ser::ValueSerializer,
    visit_mut::{self, VisitMut},
    Array, Document, InlineTable, Item, KeyMut, Table, Value,
};

#[derive(Serialize, Deserialize)]
pub struct Sha256Hash(
    #[serde(
        serialize_with = "hex::serialize",
        deserialize_with = "hex::deserialize"
    )]
    pub [u8; 32],
);

#[derive(Serialize, Deserialize)]
pub struct Magisk {
    pub url: String,
    pub hash: Sha256Hash,
}

#[derive(Serialize, Deserialize)]
pub struct OtaHashes {
    pub full: Sha256Hash,
    pub stripped: Sha256Hash,
}

#[derive(Serialize, Deserialize)]
pub struct ImageHashes {
    pub original: OtaHashes,
    pub patched: OtaHashes,
    pub avb_images: BTreeMap<String, Sha256Hash>,
}

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub url: String,
    pub sections: Vec<Range<u64>>,
    pub hash: ImageHashes,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub magisk: Magisk,
    pub device: BTreeMap<String, Device>,
}

struct ConfigFormatter;

impl VisitMut for ConfigFormatter {
    fn visit_table_like_kv_mut(&mut self, key: KeyMut<'_>, node: &mut Item) {
        // Convert non-array-of-tables inline tables into regular tables.
        if let Item::Value(Value::InlineTable(t)) = node {
            let inline_table = std::mem::replace(t, InlineTable::new());
            *node = Item::Table(inline_table.into_table());
        }

        // But for hashes, use dotted notation until TOML 1.1, which allows
        // newlines in inline tables, is released.
        if key == "hash" || key == "original" || key == "patched" || key == "avb_images" {
            if let Some(t) = node.as_table_like_mut() {
                t.set_dotted(true);
            }
        }

        visit_mut::visit_table_like_kv_mut(self, key, node);
    }

    fn visit_table_mut(&mut self, node: &mut Table) {
        // Make tables implicit unless they are empty, which may be meaningful.
        if !node.is_empty() {
            node.set_implicit(true);
        }

        visit_mut::visit_table_mut(self, node);
    }

    fn visit_array_mut(&mut self, node: &mut Array) {
        visit_mut::visit_array_mut(self, node);

        // Put array elements on their own indented lines.
        if node.is_empty() {
            node.set_trailing("");
            node.set_trailing_comma(false);
        } else {
            for item in node.iter_mut() {
                item.decor_mut().set_prefix("\n    ");
            }
            node.set_trailing("\n");
            node.set_trailing_comma(true);
        }
    }
}

/// Add a device to the config file. This leaves all comments intact, except for
/// those contained within the existing device section if it exists.
pub fn add_device(document: &mut Document, name: &str, device: &Device) -> Result<()> {
    let device_table = document.entry("device").or_insert_with(|| {
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        Item::Table(t)
    });
    let old_table = device_table.get(name).and_then(|i| i.as_table());

    let value = device.serialize(ValueSerializer::new())?;
    let Value::InlineTable(inline_table) = value else {
        unreachable!("Device did not serialize as an inline table");
    };
    let mut table = inline_table.into_table();

    ConfigFormatter.visit_table_mut(&mut table);

    // Keep top-level comment on the table.
    if let Some(t) = old_table {
        *table.decor_mut() = t.decor().clone();
    }

    device_table[name] = Item::Table(table);

    Ok(())
}

pub fn load_config(path: &Path) -> Result<(Config, Document)> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read config: {path:?}"))?;
    let config: Config = toml_edit::de::from_str(&contents)
        .with_context(|| format!("Failed to parse config: {path:?}"))?;
    let document: Document = contents.parse().unwrap();

    Ok((config, document))
}
