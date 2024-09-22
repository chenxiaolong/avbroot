// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{env, ffi::OsStr, fs, io, path::Path};

fn main() {
    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("protobuf");
    let in_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("protobuf");

    println!("cargo:rerun-if-changed={}", in_dir.to_str().unwrap());

    let mut protos = Vec::new();

    for entry in fs::read_dir(&in_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() == Some(OsStr::new("proto")) {
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
            protos.push(path);
        }
    }

    match fs::remove_dir_all(&out_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        r => r.unwrap(),
    }

    fs::create_dir_all(&out_dir).unwrap();

    let file_descriptors = protox::compile(&protos, [&in_dir]).unwrap();

    const CUE_AI: &str = ".chromeos_update_engine.ApexInfo";
    const CUE_DAM: &str = ".chromeos_update_engine.DeltaArchiveManifest";
    const CUE_DPG: &str = ".chromeos_update_engine.DynamicPartitionGroup";
    const CUE_DPM: &str = ".chromeos_update_engine.DynamicPartitionMetadata";
    const CUE_PU: &str = ".chromeos_update_engine.PartitionUpdate";
    const CUE_VABCFS: &str = ".chromeos_update_engine.VABCFeatureSet";

    const DERIVE_SERDE: &str = "#[derive(serde::Deserialize, serde::Serialize)]";
    const SERDE_DEFAULT: &str = "#[serde(default)]";
    const SERDE_SKIP: &str = "#[serde(skip)]";
    const SERDE_SKIP_IF_VEC_EMPTY: &str = "#[serde(skip_serializing_if = \"Vec::is_empty\")]";

    use constcat::concat as c;

    prost_build::Config::new()
        .btree_map(["."])
        // Allow deserializing and serializing the types we care about.
        .type_attribute(CUE_AI, DERIVE_SERDE)
        .type_attribute(CUE_DAM, DERIVE_SERDE)
        .type_attribute(CUE_DPG, DERIVE_SERDE)
        .type_attribute(CUE_DPM, DERIVE_SERDE)
        .type_attribute(CUE_PU, DERIVE_SERDE)
        .type_attribute(CUE_VABCFS, DERIVE_SERDE)
        // Allow default-initializing all fields.
        .type_attribute(CUE_AI, SERDE_DEFAULT)
        .type_attribute(CUE_DAM, SERDE_DEFAULT)
        .type_attribute(CUE_DPG, SERDE_DEFAULT)
        .type_attribute(CUE_DPM, SERDE_DEFAULT)
        .type_attribute(CUE_PU, SERDE_DEFAULT)
        .type_attribute(CUE_VABCFS, SERDE_DEFAULT)
        // Don't serialize fields that define the structure of the payload
        // binary and that we recompute during packing.
        .field_attribute(c!(CUE_DAM, ".signatures_offset"), SERDE_SKIP)
        .field_attribute(c!(CUE_DAM, ".signatures_size"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".operations"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".estimate_cow_size"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".old_partition_info"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".new_partition_info"), SERDE_SKIP)
        // Don't serialize AVB 1.0 fields.
        .field_attribute(c!(CUE_PU, ".hash_tree_data_extent"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".hash_tree_extent"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".hash_tree_algorithm"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".hash_tree_salt"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".fec_data_extent"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".fec_extent"), SERDE_SKIP)
        .field_attribute(c!(CUE_PU, ".fec_roots"), SERDE_SKIP)
        // Don't serialize fields for incremental OTAs.
        .field_attribute(c!(CUE_PU, ".merge_operations"), SERDE_SKIP)
        // Don't serialize fields for vendor-signed images, which update_engine
        // doesn't support anyway.
        .field_attribute(c!(CUE_PU, ".new_partition_signature"), SERDE_SKIP)
        // Don't serialize empty lists.
        .field_attribute(c!(CUE_DAM, ".apex_info"), SERDE_SKIP_IF_VEC_EMPTY)
        .field_attribute(c!(CUE_DAM, ".partitions"), SERDE_SKIP_IF_VEC_EMPTY)
        .field_attribute(c!(CUE_DPG, ".partition_names"), SERDE_SKIP_IF_VEC_EMPTY)
        .field_attribute(c!(CUE_DPM, ".groups"), SERDE_SKIP_IF_VEC_EMPTY)
        .compile_fds(file_descriptors)
        .unwrap();
}
