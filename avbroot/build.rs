/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

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

    prost_build::Config::new()
        .btree_map(["."])
        .compile_fds(file_descriptors)
        .unwrap();
}
