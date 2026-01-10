// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use avbroot::format::payload::{CowVersion, VabcAlgo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Sha256Hash(
    #[serde(
        serialize_with = "hex::serialize",
        deserialize_with = "hex::deserialize"
    )]
    pub [u8; 32],
);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtaInfo {
    pub device: String,
    pub fingerprint: String,
    pub build_number: String,
    pub incremental_version: String,
    pub android_version: String,
    pub sdk_version: String,
    pub security_patch_level: String,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Avb {
    pub signed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RamdiskContent {
    Init,
    Otacerts,
    FirstStage,
    DsuKeyDir,
    Dlkm,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootVersion {
    V2,
    V3,
    V4,
    VendorV3,
    VendorV4,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootData {
    pub version: BootVersion,
    #[serde(default)]
    pub kernel: bool,
    #[serde(default)]
    pub ramdisks: Vec<Vec<RamdiskContent>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmVerityContent {
    SystemOtacerts,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DmVerityData {
    pub content: DmVerityContent,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VbmetaData {
    pub deps: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Data {
    Boot(BootData),
    DmVerity(DmVerityData),
    Vbmeta(VbmetaData),
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hashes {
    pub original: Sha256Hash,
    pub patched: Sha256Hash,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    pub avb: Avb,
    pub data: Data,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VabcSettings {
    pub version: CowVersion,
    pub algo: VabcAlgo,
    pub force_compression_factor: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub vabc: Option<VabcSettings>,
    pub partitions: BTreeMap<String, Partition>,
    pub hashes_streaming: Hashes,
    pub hashes_seekable: Hashes,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub ota_info: OtaInfo,
    #[serde(default)]
    pub profile: BTreeMap<String, Profile>,
}

pub fn load_config(path: &Path) -> Result<Config> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read config: {path:?}"))?;
    toml::de::from_str(&contents).with_context(|| format!("Failed to parse config: {path:?}"))
}
