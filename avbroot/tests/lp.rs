/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{io::Cursor, num::NonZeroU64};

use avbroot::{
    format::lp::{
        BlockDevice, BlockDeviceFlags, Extent, ExtentType, HeaderFlags, ImageType, Metadata,
        MetadataSlot, Partition, PartitionAttributes, PartitionGroup, PartitionGroupFlags,
    },
    stream::{FromReader, ToWriter},
};

fn round_trip(metadata: &Metadata, sha512: &[u8; 64]) {
    let mut writer = Cursor::new(Vec::new());
    metadata.to_writer(&mut writer).unwrap();
    let data = writer.into_inner();

    assert_eq!(
        ring::digest::digest(&ring::digest::SHA512, &data).as_ref(),
        sha512,
    );

    let mut reader = Cursor::new(&data);
    let new_metadata = Metadata::from_reader(&mut reader).unwrap();

    assert_eq!(&new_metadata, metadata);
}

#[test]
fn round_trip_empty_image() {
    // Layout from Google Pixel 9 Pro XL stock factory image:
    // komodo-ad1a.240530.047-factory-bb04e484.zip -> super_empty.img
    let metadata = Metadata {
        image_type: ImageType::Empty,
        metadata_max_size: 65536,
        metadata_slot_count: 3,
        logical_block_size: 4096,
        slots: vec![MetadataSlot {
            major_version: 10,
            minor_version: 2,
            groups: vec![
                PartitionGroup {
                    name: "default".into(),
                    flags: PartitionGroupFlags::empty(),
                    maximum_size: None,
                    partitions: vec![],
                },
                PartitionGroup {
                    name: "google_dynamic_partitions_a".into(),
                    flags: PartitionGroupFlags::empty(),
                    maximum_size: NonZeroU64::new(8527020032),
                    partitions: vec![
                        Partition {
                            name: "system_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "system_dlkm_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "system_ext_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "product_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "vendor_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "vendor_dlkm_a".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                    ],
                },
                PartitionGroup {
                    name: "google_dynamic_partitions_b".into(),
                    flags: PartitionGroupFlags::empty(),
                    maximum_size: NonZeroU64::new(8527020032),
                    partitions: vec![
                        Partition {
                            name: "system_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "system_dlkm_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "system_ext_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "product_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "vendor_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                        Partition {
                            name: "vendor_dlkm_b".into(),
                            attributes: PartitionAttributes::READONLY,
                            extents: vec![],
                        },
                    ],
                },
            ],
            block_devices: vec![BlockDevice {
                first_logical_sector: 2048,
                alignment: 1048576,
                alignment_offset: 0,
                size: 8531214336,
                partition_name: "super".into(),
                flags: BlockDeviceFlags::empty(),
            }],
            flags: HeaderFlags::VIRTUAL_AB_DEVICE,
        }],
    };
    // This is semantically equivalent, but not identical. The Metadata data
    // structure only retains the order of partitions within a group, but not
    // globally. This checksum is meant to protect against unintended future
    // changes.
    let sha512 = [
        0xfa, 0xdf, 0xf2, 0xb6, 0x74, 0xec, 0x78, 0x7d, 0x0f, 0x7d, 0x17, 0x54, 0xcf, 0x1b, 0x53,
        0x13, 0x66, 0x13, 0x5e, 0x8e, 0xcc, 0x84, 0xa2, 0x63, 0xaf, 0x0d, 0x68, 0x96, 0xc6, 0x40,
        0x4e, 0x83, 0xe4, 0xe9, 0xef, 0x61, 0xdc, 0x2a, 0x25, 0x5f, 0xa2, 0x7d, 0x29, 0x0b, 0xb6,
        0x26, 0x93, 0x59, 0xc9, 0xa8, 0x56, 0x3b, 0x3d, 0x3d, 0x15, 0x6b, 0xee, 0x78, 0x56, 0x78,
        0xa1, 0x83, 0x6d, 0x70,
    ];

    round_trip(&metadata, &sha512);
}

#[test]
fn round_trip_normal_image() {
    // Layout from Google Pixel 9 Pro XL GrapheneOS factory image:
    // komodo-install-2024082500.zip -> super_1.img
    let slot = MetadataSlot {
        major_version: 10,
        minor_version: 2,
        groups: vec![
            PartitionGroup {
                name: "default".into(),
                flags: PartitionGroupFlags::empty(),
                maximum_size: None,
                partitions: vec![],
            },
            PartitionGroup {
                name: "google_dynamic_partitions_a".into(),
                flags: PartitionGroupFlags::empty(),
                maximum_size: NonZeroU64::new(8527020032),
                partitions: vec![
                    Partition {
                        name: "system_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 2465952,
                            extent_type: ExtentType::Linear {
                                start_sector: 2048,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "system_dlkm_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 23720,
                            extent_type: ExtentType::Linear {
                                start_sector: 2469888,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "system_ext_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 786144,
                            extent_type: ExtentType::Linear {
                                start_sector: 2494464,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "product_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 1396432,
                            extent_type: ExtentType::Linear {
                                start_sector: 3280896,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "vendor_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 1959024,
                            extent_type: ExtentType::Linear {
                                start_sector: 4677632,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "vendor_dlkm_a".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![Extent {
                            num_sectors: 55008,
                            extent_type: ExtentType::Linear {
                                start_sector: 6637568,
                                block_device_index: 0,
                            },
                        }],
                    },
                ],
            },
            PartitionGroup {
                name: "google_dynamic_partitions_b".into(),
                flags: PartitionGroupFlags::empty(),
                maximum_size: NonZeroU64::new(8527020032),
                partitions: vec![
                    Partition {
                        name: "system_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                    Partition {
                        name: "system_dlkm_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                    Partition {
                        name: "system_ext_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                    Partition {
                        name: "product_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                    Partition {
                        name: "vendor_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                    Partition {
                        name: "vendor_dlkm_b".into(),
                        attributes: PartitionAttributes::READONLY,
                        extents: vec![],
                    },
                ],
            },
        ],
        block_devices: vec![BlockDevice {
            first_logical_sector: 2048,
            alignment: 1048576,
            alignment_offset: 0,
            size: 8531214336,
            partition_name: "super".into(),
            flags: BlockDeviceFlags::empty(),
        }],
        flags: HeaderFlags::VIRTUAL_AB_DEVICE,
    };
    let metadata = Metadata {
        image_type: ImageType::Normal,
        metadata_max_size: 65536,
        metadata_slot_count: 3,
        logical_block_size: 4096,
        slots: vec![slot; 3],
    };
    // This is semantically equivalent, but not identical. The Metadata data
    // structure only retains the order of partitions within a group, but not
    // globally. This checksum is meant to protect against unintended future
    // changes.
    let sha512 = [
        0x3b, 0xad, 0xd4, 0x22, 0xa1, 0x5a, 0xc5, 0xdf, 0x72, 0x7d, 0x92, 0x35, 0x04, 0x8a, 0x75,
        0xd9, 0x33, 0x0d, 0xaa, 0x9e, 0x97, 0xd4, 0x13, 0x28, 0x5e, 0x0f, 0x12, 0x0c, 0xf2, 0xb3,
        0xdc, 0x35, 0x89, 0x65, 0x40, 0xb0, 0x67, 0xb1, 0x54, 0x09, 0x52, 0x3e, 0x78, 0x3d, 0x3f,
        0xa7, 0xf7, 0xa0, 0x77, 0xa8, 0xfc, 0xb7, 0x93, 0x19, 0xcd, 0x43, 0xea, 0x9a, 0x74, 0x65,
        0x54, 0x3c, 0xaa, 0x12,
    ];

    round_trip(&metadata, &sha512);
}

#[test]
fn round_trip_retrofit_image() {
    // Layout from Google Pixel 3a XL stock factory image:
    // bonito-ota-sp2a.220505.008-37a410d5.zip -> system.img
    let slot = MetadataSlot {
        major_version: 10,
        minor_version: 0,
        groups: vec![
            PartitionGroup {
                name: "default".into(),
                flags: PartitionGroupFlags::empty(),
                maximum_size: None,
                partitions: vec![],
            },
            PartitionGroup {
                name: "google_dynamic_partitions".into(),
                flags: PartitionGroupFlags::SLOT_SUFFIXED,
                maximum_size: NonZeroU64::new(4068474880),
                partitions: vec![
                    Partition {
                        name: "system".into(),
                        attributes: PartitionAttributes::READONLY
                            | PartitionAttributes::SLOT_SUFFIXED,
                        extents: vec![Extent {
                            num_sectors: 1757416,
                            extent_type: ExtentType::Linear {
                                start_sector: 2048,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "vendor".into(),
                        attributes: PartitionAttributes::READONLY
                            | PartitionAttributes::SLOT_SUFFIXED,
                        extents: vec![Extent {
                            num_sectors: 991848,
                            extent_type: ExtentType::Linear {
                                start_sector: 1761280,
                                block_device_index: 0,
                            },
                        }],
                    },
                    Partition {
                        name: "product".into(),
                        attributes: PartitionAttributes::READONLY
                            | PartitionAttributes::SLOT_SUFFIXED,
                        extents: vec![
                            Extent {
                                num_sectors: 3627008,
                                extent_type: ExtentType::Linear {
                                    start_sector: 2754560,
                                    block_device_index: 0,
                                },
                            },
                            Extent {
                                num_sectors: 538240,
                                extent_type: ExtentType::Linear {
                                    start_sector: 2048,
                                    block_device_index: 1,
                                },
                            },
                        ],
                    },
                    Partition {
                        name: "system_ext".into(),
                        attributes: PartitionAttributes::READONLY
                            | PartitionAttributes::SLOT_SUFFIXED,
                        extents: vec![Extent {
                            num_sectors: 490744,
                            extent_type: ExtentType::Linear {
                                start_sector: 540672,
                                block_device_index: 1,
                            },
                        }],
                    },
                ],
            },
        ],
        block_devices: vec![
            BlockDevice {
                first_logical_sector: 2048,
                alignment: 1048576,
                alignment_offset: 0,
                size: 3267362816,
                partition_name: "system".into(),
                flags: BlockDeviceFlags::SLOT_SUFFIXED,
            },
            BlockDevice {
                first_logical_sector: 2048,
                alignment: 1048576,
                alignment_offset: 0,
                size: 805306368,
                partition_name: "vendor".into(),
                flags: BlockDeviceFlags::SLOT_SUFFIXED,
            },
        ],
        flags: HeaderFlags::empty(),
    };
    let metadata = Metadata {
        image_type: ImageType::Normal,
        metadata_max_size: 65536,
        metadata_slot_count: 2,
        logical_block_size: 4096,
        slots: vec![slot; 2],
    };
    // First 274432 bytes of system.img. Unlike the other test cases, this is
    // identical to the original image because there is only one partition group
    // with partitions, so the group-level ordering is the same as the global
    // ordering.
    let sha512 = [
        0xb9, 0x97, 0xf5, 0x83, 0x39, 0x37, 0x90, 0x0a, 0xb6, 0x46, 0xdd, 0x27, 0x57, 0xf1, 0xf3,
        0xbd, 0x8f, 0xc4, 0x63, 0x07, 0x6f, 0xf4, 0x19, 0xc0, 0x02, 0x28, 0x48, 0x99, 0x54, 0xbb,
        0xb3, 0xbf, 0x67, 0x95, 0xc4, 0xa7, 0x99, 0xf4, 0xa9, 0xc4, 0xf4, 0x1d, 0xf7, 0x59, 0x28,
        0xeb, 0xbc, 0x85, 0x46, 0xd1, 0x7d, 0x65, 0x0f, 0xbe, 0x21, 0xf6, 0xf2, 0xa2, 0x20, 0x5b,
        0xda, 0xde, 0xfa, 0x50,
    ];

    round_trip(&metadata, &sha512);
}
