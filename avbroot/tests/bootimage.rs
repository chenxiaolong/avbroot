/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::Cursor;

use avbroot::{
    self,
    format::bootimage::{BootImage, BootImageExt},
    stream::{FromReader, ToWriter},
};
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

fn get_test_key() -> RsaPrivateKey {
    let data = include_str!(concat!(
        env!("CARGO_WORKSPACE_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.key",
    ));
    let passphrase = include_str!(concat!(
        env!("CARGO_WORKSPACE_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.passphrase",
    ));

    RsaPrivateKey::from_pkcs8_encrypted_pem(data, passphrase.trim_end()).unwrap()
}

fn round_trip(data: &[u8], expected_version: u32) {
    let reader = Cursor::new(data);
    let mut image = BootImage::from_reader(reader).unwrap();

    assert_eq!(image.header_version(), expected_version);

    match &mut image {
        BootImage::V3Through4(b) => {
            let should_sign = b
                .v4_extra
                .as_ref()
                .map_or(false, |v4| v4.signature.is_some());
            let key = get_test_key();
            let signed = b.sign(&key).unwrap();
            assert_eq!(signed, should_sign);
        }
        _ => {}
    }

    let mut writer = Cursor::new(Vec::new());
    image.to_writer(&mut writer).unwrap();
    let new_data = writer.into_inner();

    assert_eq!(data, new_data);
}

#[test]
fn round_trip_v0() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v0.img",
    ));
    round_trip(data, 0);
}

#[test]
fn round_trip_v1() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v1.img",
    ));
    round_trip(data, 1);
}

#[test]
fn round_trip_v2() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v2.img",
    ));
    round_trip(data, 2);
}

#[test]
fn round_trip_v3() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v3.img",
    ));
    round_trip(data, 3);
}

#[test]
fn round_trip_v4() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v4.img",
    ));
    round_trip(data, 4);
}

#[test]
fn round_trip_v4_vts() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/boot_v4_vts.img",
    ));
    round_trip(data, 4);
}

#[test]
fn round_trip_vendor_v3() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vendor_v3.img",
    ));
    round_trip(data, 3);
}

#[test]
fn round_trip_vendor_v4() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vendor_v4.img",
    ));
    round_trip(data, 4);
}
