/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
};

use assert_matches::assert_matches;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

use avbroot::{
    self,
    format::avb::{self, AppendedDescriptorMut, AppendedDescriptorRef},
    stream::{self, SharedCursor},
};

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

#[test]
fn round_trip_root_image() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vbmeta_root.img",
    ));
    let reader = Cursor::new(data);

    let (mut header, footer, _) = avb::load_image(reader).unwrap();
    assert_matches!(footer, None);

    let key = get_test_key();

    assert_eq!(header.verify().unwrap().unwrap(), key.to_public_key());

    // Clear out the signature-related fields and re-sign.
    header.hash.clear();
    header.signature.clear();
    header.public_key.clear();
    header.sign(&key).unwrap();

    let mut writer = Cursor::new(Vec::new());
    avb::write_root_image(&mut writer, &header, 64).unwrap();
    let new_data = writer.into_inner();

    assert_eq!(data, new_data.as_slice());
}

#[test]
fn round_trip_appended_hash_image() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vbmeta_appended_hash.img",
    ));
    let mut reader = Cursor::new(data);
    let cancel_signal = AtomicBool::new(false);

    let (mut header, footer, image_size) = avb::load_image(&mut reader).unwrap();
    let mut footer = footer.unwrap();

    let key = get_test_key();

    assert_eq!(header.verify().unwrap().unwrap(), key.to_public_key());

    // Verify the digest.
    match header.appended_descriptor().unwrap() {
        AppendedDescriptorRef::HashTree(_) => panic!("Expected hash descriptor"),
        AppendedDescriptorRef::Hash(d) => {
            reader.rewind().unwrap();
            d.verify(&mut reader, &cancel_signal).unwrap();
        }
    }

    let mut writer = Cursor::new(Vec::new());

    // Copy the partition data.
    reader.seek(SeekFrom::Start(0)).unwrap();
    stream::copy_n(
        &mut reader,
        &mut writer,
        footer.original_image_size,
        &cancel_signal,
    )
    .unwrap();

    // Regenerate the digest.
    match header.appended_descriptor_mut().unwrap() {
        AppendedDescriptorMut::HashTree(_) => panic!("Expected hash descriptor"),
        AppendedDescriptorMut::Hash(d) => {
            d.root_digest.clear();
            writer.rewind().unwrap();
            d.update(&mut writer, &cancel_signal).unwrap();
        }
    }

    // Clear out the signature-related fields and re-sign.
    header.hash.clear();
    header.signature.clear();
    header.public_key.clear();
    header.sign(&key).unwrap();

    // Write new vbmeta structures.
    avb::write_appended_image(&mut writer, &header, &mut footer, image_size).unwrap();
    let new_data = writer.into_inner();

    assert_eq!(data, new_data.as_slice());
}

#[test]
fn round_trip_appended_hash_tree_image() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/vbmeta_appended_hash_tree.img",
    ));
    let mut reader = SharedCursor::default();
    reader.write_all(data).unwrap();
    let cancel_signal = AtomicBool::new(false);

    let (mut header, footer, image_size) = avb::load_image(&mut reader).unwrap();
    let mut footer = footer.unwrap();

    let key = get_test_key();

    assert_eq!(header.verify().unwrap().unwrap(), key.to_public_key());

    // Verify the hash tree and FEC data.
    match header.appended_descriptor().unwrap() {
        AppendedDescriptorRef::HashTree(d) => {
            d.verify(|| Ok(Box::new(reader.reopen())), &cancel_signal)
                .unwrap();
        }
        AppendedDescriptorRef::Hash(_) => panic!("Expected hash tree descriptor"),
    }

    let mut writer = SharedCursor::default();

    // Copy the partition data, excluding the hash tree and FEC data.
    reader.seek(SeekFrom::Start(0)).unwrap();
    stream::copy_n(
        &mut reader,
        &mut writer,
        footer.original_image_size,
        &cancel_signal,
    )
    .unwrap();

    // Regenerate the hash tree and FEC data.
    match header.appended_descriptor_mut().unwrap() {
        AppendedDescriptorMut::HashTree(d) => {
            d.root_digest.clear();
            d.tree_offset = 0;
            d.tree_size = 0;
            d.fec_offset = 0;
            d.fec_size = 0;

            d.update(
                || Ok(Box::new(writer.reopen())),
                || Ok(Box::new(writer.reopen())),
                &cancel_signal,
            )
            .unwrap();
        }
        AppendedDescriptorMut::Hash(_) => panic!("Expected hash tree descriptor"),
    }

    // Clear out the signature-related fields and re-sign.
    header.hash.clear();
    header.signature.clear();
    header.public_key.clear();
    header.sign(&key).unwrap();

    // Write new vbmeta structures.
    avb::write_appended_image(&mut writer, &header, &mut footer, image_size).unwrap();
    let mut new_data = Vec::new();
    writer.rewind().unwrap();
    writer.read_to_end(&mut new_data).unwrap();

    assert_eq!(data, new_data.as_slice());
}
