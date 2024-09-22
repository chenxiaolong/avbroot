// SPDX-FileCopyrightText: 2023 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{Cursor, Read, Seek, Write};

use avbroot::{
    self,
    format::compression::{CompressedFormat, CompressedReader, CompressedWriter},
};

fn round_trip(data: &[u8], format: CompressedFormat) {
    let raw_writer = Cursor::new(Vec::new());
    let mut writer = CompressedWriter::new(raw_writer, format).unwrap();
    writer.write_all(data).unwrap();
    let mut raw_reader = writer.finish().unwrap();

    raw_reader.rewind().unwrap();
    let mut reader = CompressedReader::new(raw_reader, false).unwrap();
    assert_eq!(reader.format(), format);

    let mut new_data = vec![];
    reader.read_to_end(&mut new_data).unwrap();

    assert_eq!(data, new_data);
}

#[test]
fn round_trip_gzip() {
    round_trip(b"gzip-compressed data", CompressedFormat::Gzip);
}

#[test]
fn round_trip_lz4_legacy() {
    // Make sure we exceed the 8MiB block boundary.
    let data = b"Lz4Legacy".repeat(1024 * 1024);
    round_trip(&data, CompressedFormat::Lz4Legacy);
}
