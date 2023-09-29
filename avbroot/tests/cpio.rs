/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::{self, Cursor};

use avbroot::{
    self,
    format::cpio::{CpioEntryType, CpioReader, CpioWriter},
    util,
};

#[test]
fn round_trip_archive() {
    let data = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/archive.cpio",
    ));
    assert_ne!(data.len() % 512, 0);

    for pad_to_block_size in [false, true] {
        println!("Pad to block size: {pad_to_block_size}");

        let reader = Cursor::new(data);
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
            assert!(new_data.starts_with(data));
            assert!(util::is_zero(&new_data[data.len()..]));
            assert_eq!(new_data.len() % 512, 0);
        } else {
            assert_eq!(new_data, data);
        }
    }
}
