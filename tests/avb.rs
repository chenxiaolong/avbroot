/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use assert_matches::assert_matches;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

use avbroot::{self, format::avb};

fn get_test_key() -> RsaPrivateKey {
    let data = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.key",
    ));
    let passphrase = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.passphrase",
    ));

    RsaPrivateKey::from_pkcs8_encrypted_pem(data, passphrase.trim_end()).unwrap()
}

#[test]
fn round_trip_root_image() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vbmeta_root.img",
    ));
    let reader = Cursor::new(data);

    let (mut header, footer, _) = avb::load_image(reader).unwrap();
    assert_matches!(footer, None);

    // Clear out the signature-related fields and re-sign.
    header.hash.clear();
    header.signature.clear();
    header.public_key.clear();
    let key = get_test_key();
    header.sign(&key).unwrap();

    let mut writer = Cursor::new(Vec::new());
    avb::write_root_image(&mut writer, &header, 64).unwrap();
    let new_data = writer.into_inner();

    assert_eq!(data, new_data.as_slice());
}

#[test]
fn round_trip_appended_image() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vbmeta_appended.img",
    ));
    let mut reader = Cursor::new(data);

    let (mut header, footer, _) = avb::load_image(&mut reader).unwrap();
    let footer = footer.unwrap();

    // Clear out the signature-related fields and re-sign.
    header.hash.clear();
    header.signature.clear();
    header.public_key.clear();
    let key = get_test_key();
    header.sign(&key).unwrap();

    let mut writer = Cursor::new(Vec::new());

    // Copy the partition data.
    let image_size = reader.seek(SeekFrom::End(0)).unwrap();
    reader.seek(SeekFrom::Start(0)).unwrap();
    io::copy(&mut reader.take(footer.original_image_size), &mut writer).unwrap();

    // Write new vbmeta structures.
    avb::write_appended_image(&mut writer, &header, &footer, image_size).unwrap();
    let new_data = writer.into_inner();

    assert_eq!(data, new_data.as_slice());
}
