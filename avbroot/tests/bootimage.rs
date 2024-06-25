/*
 * SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::Cursor;

use avbroot::{
    self,
    crypto::RsaSigningKey,
    format::{
        avb::{AlgorithmType, Descriptor, HashDescriptor, Header},
        bootimage::{
            self, BootImage, BootImageExt, BootImageV0Through2, BootImageV3Through4, RamdiskMeta,
            V1Extra, V2Extra, V4Extra, VendorBootImageV3Through4, VendorV4Extra,
        },
    },
    stream::{FromReader, ToWriter},
};
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

fn get_test_key() -> RsaSigningKey {
    let data = include_str!(concat!(
        env!("CARGO_WORKSPACE_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.key",
    ));
    let passphrase = include_str!(concat!(
        env!("CARGO_WORKSPACE_DIR"),
        "/e2e/keys/TEST_KEY_DO_NOT_USE_avb.passphrase",
    ));

    let key = RsaPrivateKey::from_pkcs8_encrypted_pem(data, passphrase.trim_end()).unwrap();
    RsaSigningKey::Internal(key)
}

fn repeat(s: &str, max_len: usize) -> String {
    assert!(!s.is_empty());

    let mut result = s.repeat(max_len / s.len());
    result.push_str(&s[..max_len % s.len()]);

    result
}

fn round_trip(image: &BootImage, sha512: &[u8; 64], expected_version: u32) {
    assert_eq!(image.header_version(), expected_version);

    let mut writer = Cursor::new(Vec::new());
    image.to_writer(&mut writer).unwrap();
    let data = writer.into_inner();

    assert_eq!(
        ring::digest::digest(&ring::digest::SHA512, &data).as_ref(),
        sha512,
    );

    let reader = Cursor::new(data);
    let new_image = BootImage::from_reader(reader).unwrap();

    assert_eq!(&new_image, image);
}

#[test]
fn round_trip_v0() {
    let image = BootImage::V0Through2(BootImageV0Through2 {
        kernel_addr: 0x01234567,
        ramdisk_addr: 0x89abcdef,
        second_addr: 0x02468ace,
        tags_addr: 0x13579bdf,
        page_size: 4096,
        os_version: 0x76543210,
        name: repeat("Name", 16),
        cmdline: repeat("Cmdline", 512),
        id: [
            0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0xffeeddcc, 0xbbaa9988, 0x77665544,
            0x33221100,
        ],
        extra_cmdline: repeat("ExtraCmdline", 1024),
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
        second: b"second data".to_vec(),
        v1_extra: None,
        v2_extra: None,
    });
    let sha512 = [
        0x23, 0x65, 0x0b, 0xfa, 0x7a, 0x09, 0x0a, 0xdf, 0xdd, 0x9a, 0x6c, 0x03, 0xfa, 0xc5, 0xe1,
        0xfa, 0x27, 0x65, 0xa0, 0x94, 0xef, 0xa2, 0x0c, 0xc5, 0x3e, 0xd9, 0x67, 0x7d, 0x88, 0x7b,
        0xb3, 0x48, 0x39, 0xab, 0x28, 0x77, 0x7b, 0x18, 0xec, 0x60, 0xe0, 0xb7, 0x0d, 0x15, 0x26,
        0xb2, 0xd4, 0x27, 0x25, 0x92, 0x5c, 0x7b, 0x0b, 0x5c, 0xf7, 0xed, 0x27, 0x6c, 0x39, 0xb5,
        0xb7, 0x44, 0xbb, 0xec,
    ];

    round_trip(&image, &sha512, 0);
}

#[test]
fn round_trip_v1() {
    let image = BootImage::V0Through2(BootImageV0Through2 {
        kernel_addr: 0x01234567,
        ramdisk_addr: 0x89abcdef,
        second_addr: 0x02468ace,
        tags_addr: 0x13579bdf,
        page_size: 4096,
        os_version: 0x76543210,
        name: repeat("Name", 16),
        cmdline: repeat("Cmdline", 512),
        id: [
            0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0xffeeddcc, 0xbbaa9988, 0x77665544,
            0x33221100,
        ],
        extra_cmdline: repeat("ExtraCmdline", 1024),
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
        second: b"second data".to_vec(),
        v1_extra: Some(V1Extra {
            recovery_dtbo_offset: 0x0123456789abcdef,
            recovery_dtbo: b"recovery_dtbo data".to_vec(),
        }),
        v2_extra: None,
    });
    let sha512 = [
        0x37, 0x8e, 0xf1, 0xf0, 0xb8, 0x44, 0x0f, 0x9e, 0x16, 0xc0, 0x15, 0x98, 0xa2, 0xb5, 0x06,
        0x63, 0x59, 0xf4, 0x91, 0xb6, 0x28, 0x03, 0xe6, 0xdc, 0xd2, 0x0d, 0xd7, 0x49, 0x33, 0x63,
        0x91, 0xd4, 0xa8, 0x24, 0xff, 0xb0, 0x5f, 0x99, 0x2a, 0x9a, 0xb3, 0x66, 0x81, 0x41, 0x69,
        0xb0, 0xbc, 0xe2, 0x5b, 0x33, 0x3f, 0x39, 0x6a, 0xa8, 0xbd, 0xe1, 0x15, 0x3e, 0x51, 0x5a,
        0x2a, 0x9d, 0x23, 0x90,
    ];

    round_trip(&image, &sha512, 1);
}

#[test]
fn round_trip_v2() {
    let image = BootImage::V0Through2(BootImageV0Through2 {
        kernel_addr: 0x01234567,
        ramdisk_addr: 0x89abcdef,
        second_addr: 0x02468ace,
        tags_addr: 0x13579bdf,
        page_size: 4096,
        os_version: 0x76543210,
        name: repeat("Name", 16),
        cmdline: repeat("Cmdline", 512),
        id: [
            0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0xffeeddcc, 0xbbaa9988, 0x77665544,
            0x33221100,
        ],
        extra_cmdline: repeat("ExtraCmdline", 1024),
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
        second: b"second data".to_vec(),
        v1_extra: Some(V1Extra {
            recovery_dtbo_offset: 0x0123456789abcdef,
            recovery_dtbo: b"recovery_dtbo data".to_vec(),
        }),
        v2_extra: Some(V2Extra {
            dtb_addr: 0xfedcba9876543210,
            dtb: b"dtb data".to_vec(),
        }),
    });
    let sha512 = [
        0x04, 0x24, 0x5b, 0xb7, 0x07, 0x82, 0xa9, 0x08, 0x68, 0xb9, 0xc9, 0x65, 0x1f, 0x53, 0xd7,
        0x6c, 0xcf, 0xf3, 0x48, 0x58, 0x9a, 0xd4, 0xb1, 0xf3, 0xd8, 0x6f, 0x95, 0x10, 0x70, 0x2f,
        0x53, 0x30, 0x60, 0x60, 0xe4, 0x68, 0xd9, 0x84, 0xe8, 0x0a, 0xf3, 0x12, 0xb3, 0xa3, 0x1b,
        0x06, 0x88, 0x2f, 0x5d, 0x34, 0x5a, 0xea, 0x8f, 0xbb, 0x54, 0x49, 0x3c, 0xc1, 0x9c, 0xc6,
        0x24, 0x80, 0x03, 0xde,
    ];

    round_trip(&image, &sha512, 2);
}

#[test]
fn round_trip_v3() {
    let image = BootImage::V3Through4(BootImageV3Through4 {
        os_version: 0x01234567,
        reserved: [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff],
        cmdline: repeat("Cmdline", 1536),
        v4_extra: None,
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
    });
    let sha512 = [
        0x30, 0xea, 0x77, 0x0a, 0xd3, 0x24, 0x6a, 0x3f, 0xf8, 0xdf, 0xe6, 0xd9, 0x5a, 0xa1, 0xd3,
        0xa4, 0x3b, 0x8a, 0x13, 0x39, 0x5e, 0x58, 0x24, 0x3e, 0x71, 0x31, 0x78, 0xa1, 0x2c, 0xad,
        0x1d, 0xca, 0x24, 0x12, 0xf5, 0xfb, 0x2c, 0x48, 0xa5, 0x3d, 0xc0, 0x38, 0x55, 0xb6, 0xfd,
        0xd3, 0x30, 0xe0, 0x69, 0x11, 0x28, 0xd7, 0x29, 0xda, 0x2e, 0x5a, 0x49, 0x5c, 0x39, 0x1d,
        0xb9, 0xdb, 0x53, 0xe1,
    ];

    round_trip(&image, &sha512, 3);
}

#[test]
fn round_trip_v4() {
    let image = BootImage::V3Through4(BootImageV3Through4 {
        os_version: 0x01234567,
        reserved: [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff],
        cmdline: repeat("Cmdline", 1536),
        v4_extra: Some(V4Extra { signature: None }),
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
    });
    let sha512 = [
        0xa8, 0x1d, 0x2b, 0x78, 0x22, 0x45, 0x0b, 0xe7, 0xc2, 0x3a, 0xd8, 0xda, 0x95, 0x49, 0x77,
        0x18, 0xd0, 0x7b, 0x9b, 0x7f, 0xc7, 0xf6, 0x48, 0xb4, 0x2d, 0x85, 0x6d, 0xe3, 0x5a, 0xa3,
        0x24, 0xb6, 0x94, 0x56, 0xb9, 0x07, 0x84, 0xdb, 0x50, 0x01, 0xca, 0x6c, 0x86, 0x26, 0x32,
        0x79, 0x0c, 0xc5, 0x70, 0xcf, 0xcc, 0x7f, 0xc3, 0x5b, 0x96, 0x56, 0x23, 0x5c, 0xd0, 0x50,
        0xb0, 0x98, 0xdb, 0x4a,
    ];

    round_trip(&image, &sha512, 4);
}

#[test]
fn round_trip_v4_vts() {
    let mut header = Header {
        required_libavb_version_major: 1,
        required_libavb_version_minor: 0,
        algorithm_type: AlgorithmType::Sha256Rsa4096,
        hash: vec![],       // autogenerated
        signature: vec![],  // autogenerated
        public_key: vec![], // autogenerated
        public_key_metadata: vec![],
        descriptors: vec![Descriptor::Hash(HashDescriptor {
            image_size: 12288,
            hash_algorithm: "sha256".to_owned(),
            partition_name: "boot".to_owned(),
            salt: vec![0x64, 0x30, 0x30, 0x64, 0x66, 0x30, 0x30, 0x64],
            root_digest: vec![
                0xab, 0xd5, 0x48, 0x3e, 0x11, 0xe7, 0x94, 0x0c, 0xb9, 0xbf, 0x38, 0x75, 0x87, 0xa4,
                0xa1, 0x65, 0x99, 0x81, 0xa1, 0xb8, 0x39, 0x62, 0xb7, 0xc1, 0xfa, 0xf1, 0xb0, 0xcd,
                0x63, 0x07, 0xd4, 0x49,
            ],
            flags: 0,
            reserved: [0; 60],
        })],
        rollback_index: 0,
        flags: 0,
        rollback_index_location: 0,
        release_string: "avbtool 1.2.0".to_owned(),
        reserved: [0; 80],
    };

    let key = get_test_key();
    header.sign(&key).unwrap();
    assert_eq!(header.verify().unwrap().unwrap(), key.to_public_key());

    let image = BootImage::V3Through4(BootImageV3Through4 {
        os_version: 0x01234567,
        reserved: [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff],
        cmdline: repeat("Cmdline", 1536),
        v4_extra: Some(V4Extra {
            signature: Some(header),
        }),
        kernel: b"kernel data".to_vec(),
        ramdisk: b"ramdisk data".to_vec(),
    });
    let sha512 = [
        0x19, 0x47, 0x15, 0x3c, 0x1f, 0x62, 0x84, 0xee, 0xbc, 0x16, 0x9e, 0x5a, 0xf2, 0x45, 0x2a,
        0xf7, 0x40, 0xc2, 0x18, 0x7f, 0x23, 0xb2, 0xa4, 0x20, 0x10, 0xdf, 0xb1, 0x5c, 0xf2, 0x7f,
        0x6f, 0x79, 0x22, 0x1d, 0x29, 0x27, 0x78, 0xea, 0xb3, 0x9e, 0x1f, 0xfe, 0xeb, 0xc8, 0x9f,
        0xe6, 0xef, 0xce, 0xa2, 0x28, 0x0b, 0x05, 0x1d, 0x52, 0xff, 0xab, 0xd4, 0x6f, 0x87, 0x11,
        0xd9, 0xb6, 0x5f, 0x2e,
    ];

    round_trip(&image, &sha512, 4);
}

#[test]
fn round_trip_vendor_v3() {
    let image = BootImage::VendorV3Through4(VendorBootImageV3Through4 {
        page_size: 4096,
        kernel_addr: 0x01234567,
        ramdisk_addr: 0x89abcdef,
        cmdline: repeat("Cmdline", 2048),
        tags_addr: 0xfedcba98,
        name: repeat("Name", 16),
        dtb: b"dtb data".to_vec(),
        dtb_addr: 0x76543210,
        ramdisks: vec![b"ramdisk data".to_vec()],
        v4_extra: None,
    });
    let sha512 = [
        0x17, 0x18, 0xb9, 0x67, 0x4c, 0x82, 0x71, 0x98, 0x6a, 0x8a, 0xb8, 0x85, 0x3c, 0x77, 0x9e,
        0x27, 0xeb, 0xce, 0x2a, 0x23, 0x04, 0x63, 0x7c, 0x94, 0xd4, 0xad, 0x1f, 0x3c, 0xee, 0x7e,
        0x41, 0x8b, 0xa8, 0xd9, 0x35, 0xec, 0xf2, 0xc1, 0x52, 0x3a, 0xd9, 0x5b, 0xbe, 0x63, 0xe8,
        0x00, 0xd2, 0x23, 0x4e, 0x37, 0x76, 0x31, 0x5a, 0xfc, 0x63, 0x43, 0x32, 0x34, 0x30, 0xf6,
        0x3e, 0x2e, 0x3e, 0x66,
    ];

    round_trip(&image, &sha512, 3);
}

#[test]
fn round_trip_vendor_v4() {
    let board_id = [
        0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0xffeeddcc, 0xbbaa9988, 0x77665544,
        0x33221100, 0x004488cc, 0x115599dd, 0x2266aaee, 0x3377bbff, 0xffbb7733, 0xeeaa6622,
        0xdd995511, 0xcc884400,
    ];
    let image = BootImage::VendorV3Through4(VendorBootImageV3Through4 {
        page_size: 2048,
        kernel_addr: 0x01234567,
        ramdisk_addr: 0x89abcdef,
        cmdline: repeat("Cmdline", 2048),
        tags_addr: 0xfedcba98,
        name: repeat("Name", 16),
        dtb: b"dtb data".to_vec(),
        dtb_addr: 0x76543210,
        ramdisks: vec![
            b"ramdisk 0 data".to_vec(),
            b"ramdisk 1 data".to_vec(),
            b"ramdisk 2 data".to_vec(),
            b"ramdisk 3 data".to_vec(),
        ],
        v4_extra: Some(VendorV4Extra {
            ramdisk_metas: vec![
                RamdiskMeta {
                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_NONE,
                    ramdisk_name: repeat("None", 32),
                    board_id,
                },
                RamdiskMeta {
                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_PLATFORM,
                    ramdisk_name: repeat("Platform", 32),
                    board_id,
                },
                RamdiskMeta {
                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_RECOVERY,
                    ramdisk_name: repeat("Recovery", 32),
                    board_id,
                },
                RamdiskMeta {
                    ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_DLKM,
                    ramdisk_name: repeat("Dlkm", 32),
                    board_id,
                },
            ],
            bootconfig: "bootconfig data".to_owned(),
        }),
    });
    let sha512 = [
        0x0e, 0x3f, 0x86, 0x9e, 0xad, 0x98, 0xbb, 0x53, 0xc7, 0xc4, 0x3f, 0xb8, 0xc6, 0x06, 0xdc,
        0xb2, 0xe5, 0x47, 0x66, 0xe3, 0xaf, 0x2c, 0xa4, 0x91, 0x8d, 0x4b, 0xc5, 0x70, 0x1e, 0x51,
        0x19, 0x23, 0x7c, 0xab, 0x40, 0x24, 0x95, 0xef, 0xc8, 0x65, 0xdb, 0x5f, 0x0a, 0x41, 0x93,
        0xff, 0x6c, 0x22, 0xb4, 0x9a, 0xe2, 0x20, 0xc1, 0x95, 0xa0, 0x3c, 0xc2, 0x13, 0xdb, 0xc8,
        0x24, 0x33, 0x77, 0x75,
    ];

    round_trip(&image, &sha512, 4);
}
