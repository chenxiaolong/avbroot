// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{self, Cursor};

use avbroot::{
    self,
    format::cpio::{CpioEntry, CpioEntryData, CpioEntryType, CpioReader, CpioWriter},
    util,
};

fn generate_archive() -> Vec<u8> {
    let writer = Cursor::new(Vec::new());
    let mut cpio_writer = CpioWriter::new(writer, false);

    for entry in [
        CpioEntry::new_symlink(b"symlink", b"target"),
        CpioEntry::new_directory(b"directory", 0o755),
        CpioEntry::new_file(b"file", 0o644, CpioEntryData::Data(b"foobar".to_vec())),
        CpioEntry {
            path: b"reserved".to_vec(),
            data: CpioEntryData::Size(0),
            inode: 12345,
            file_type: CpioEntryType::Reserved,
            file_mode: 0o4777,
            uid: 12345678,
            gid: 87654321,
            nlink: 2,
            mtime: 1700000000,
            dev_maj: 2222,
            dev_min: 3333,
            rdev_maj: 4444,
            rdev_min: 5555,
            crc32: 0xfedcba09,
        },
    ] {
        cpio_writer.start_entry(&entry).unwrap();
    }

    let writer = cpio_writer.finish().unwrap();
    let data = writer.into_inner();

    assert_eq!(
        ring::digest::digest(&ring::digest::SHA512, &data).as_ref(),
        [
            0xb0, 0x51, 0xac, 0x28, 0x6f, 0x78, 0xe2, 0xe7, 0x45, 0xa0, 0x52, 0x7c, 0xff, 0x42,
            0x30, 0x55, 0xbd, 0x64, 0x7d, 0x4e, 0xb8, 0xe6, 0x95, 0xe5, 0x9b, 0xd1, 0x13, 0xd6,
            0x43, 0x0e, 0x32, 0xb2, 0x4e, 0x62, 0xa4, 0x55, 0x64, 0x48, 0xb7, 0x32, 0x26, 0x57,
            0x75, 0x07, 0xf5, 0xa6, 0x0f, 0x18, 0xc3, 0x9e, 0x9f, 0x06, 0xdb, 0xa4, 0xf7, 0xeb,
            0x5e, 0x8f, 0xce, 0xd0, 0x2b, 0x54, 0x39, 0x57
        ],
    );

    data
}

#[test]
fn round_trip_archive() {
    let data = generate_archive();
    assert_ne!(data.len() % 512, 0);

    for pad_to_block_size in [false, true] {
        println!("Pad to block size: {pad_to_block_size}");

        let reader = Cursor::new(&data);
        let mut cpio_reader = CpioReader::new(reader, false);

        let writer = Cursor::new(Vec::new());
        let mut cpio_writer = CpioWriter::new(writer, pad_to_block_size);

        while let Some(entry) = cpio_reader.next_entry().unwrap() {
            cpio_writer.start_entry(&entry).unwrap();

            if entry.file_type == CpioEntryType::Regular {
                io::copy(&mut cpio_reader, &mut cpio_writer).unwrap();
            }
        }

        let writer = cpio_writer.finish().unwrap();
        let new_data = writer.get_ref().as_slice();

        if pad_to_block_size {
            assert!(new_data.starts_with(&data));
            assert!(util::is_zero(&new_data[data.len()..]));
            assert_eq!(new_data.len() % 512, 0);
        } else {
            assert_eq!(new_data, data);
        }
    }
}
