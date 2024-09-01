/*
 * SPDX-FileCopyrightText: 2024 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::io::{Cursor, Read, Write};

use avbroot::format::sparse::{
    self, Chunk, ChunkBounds, ChunkData, CrcMode, Header, SparseReader, SparseWriter,
};

#[derive(Clone, Copy)]
struct TestChunk {
    chunk: Chunk,
    data: &'static [u8],
}

fn round_trip(block_size: u32, crc32: u32, test_chunks: &[TestChunk], sha512: &[u8; 64]) {
    let num_blocks = test_chunks.iter().map(|d| d.chunk.bounds.len()).sum();
    let header = Header {
        major_version: sparse::MAJOR_VERSION,
        minor_version: sparse::MINOR_VERSION,
        block_size,
        num_blocks,
        num_chunks: test_chunks.len() as u32,
        crc32,
    };

    let writer = Cursor::new(Vec::new());
    let mut sparse_writer = SparseWriter::new(writer, header).unwrap();

    for test_chunk in test_chunks {
        sparse_writer.start_chunk(test_chunk.chunk).unwrap();

        if !test_chunk.data.is_empty() {
            sparse_writer.write_all(test_chunk.data).unwrap();
        }
    }

    let writer = sparse_writer.finish().unwrap();
    let data = writer.into_inner();

    assert_eq!(
        ring::digest::digest(&ring::digest::SHA512, &data).as_ref(),
        sha512,
    );

    let reader = Cursor::new(&data);
    let mut sparse_reader = SparseReader::new(reader, CrcMode::Validate).unwrap();

    assert_eq!(sparse_reader.header(), header);

    let mut test_chunks_iter = test_chunks.iter();

    while let Some(chunk) = sparse_reader.next_chunk().unwrap() {
        let test_chunk = test_chunks_iter.next().unwrap();

        assert_eq!(chunk, test_chunk.chunk);

        if !test_chunk.data.is_empty() {
            let mut buf = vec![];
            sparse_reader.read_to_end(&mut buf).unwrap();

            assert_eq!(buf, test_chunk.data);
        }
    }

    assert!(test_chunks_iter.next().is_none());
}

#[test]
fn round_trip_full_image() {
    let block_size = 8;
    let file_crc32 = 0xf6e23567;
    let test_chunks = [
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 0, end: 1 },
                data: ChunkData::Data,
            },
            data: b"\x00\x01\x02\x03\x04\x05\x06\x07",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 1, end: 1 },
                data: ChunkData::Crc32(0x88aa689f),
            },
            data: b"",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 1, end: 2 },
                data: ChunkData::Fill(0x01234567),
            },
            data: b"",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 2, end: 3 },
                data: ChunkData::Data,
            },
            data: b"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 3, end: 3 },
                data: ChunkData::Crc32(0xf6e23567),
            },
            data: b"",
        },
    ];
    let sha512 = [
        0x19, 0x5f, 0xa7, 0xdb, 0x18, 0xc6, 0xb9, 0x0e, 0xce, 0x4b, 0x4f, 0x35, 0x36, 0x79, 0x46,
        0x02, 0x7a, 0x45, 0x66, 0x63, 0x0e, 0xd9, 0x76, 0x93, 0x2b, 0x88, 0xe2, 0xbc, 0x0b, 0xd9,
        0x1f, 0x21, 0x51, 0x92, 0x00, 0x2e, 0xe3, 0xa2, 0xff, 0x24, 0xea, 0xef, 0x24, 0xd5, 0x24,
        0xf0, 0x46, 0xf3, 0x10, 0x32, 0xf4, 0xa6, 0x3b, 0x9d, 0xcd, 0xc5, 0x57, 0xf4, 0xc0, 0xe8,
        0x01, 0xe8, 0x1d, 0xb3,
    ];

    round_trip(block_size, file_crc32, &test_chunks, &sha512);
}

#[test]
fn round_trip_partial_image() {
    let block_size = 8;
    let file_crc32 = 0;
    let test_chunks = [
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 0, end: 1 },
                data: ChunkData::Hole,
            },
            data: b"",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 1, end: 2 },
                data: ChunkData::Data,
            },
            data: b"\x00\x01\x02\x03\x04\x05\x06\x07",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 2, end: 3 },
                data: ChunkData::Hole,
            },
            data: b"",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 3, end: 4 },
                data: ChunkData::Data,
            },
            data: b"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        },
        TestChunk {
            chunk: Chunk {
                bounds: ChunkBounds { start: 4, end: 5 },
                data: ChunkData::Hole,
            },
            data: b"",
        },
    ];
    let sha512 = [
        0xee, 0x07, 0xc5, 0x4d, 0x85, 0xee, 0x69, 0x91, 0x61, 0x07, 0x10, 0xed, 0xec, 0x13, 0x5e,
        0xfb, 0xc3, 0x7d, 0xcf, 0x1f, 0x2a, 0x13, 0xf0, 0xb6, 0x85, 0xb4, 0xee, 0xe9, 0xd7, 0xa1,
        0x12, 0x79, 0x14, 0x16, 0x30, 0x7a, 0x81, 0xf9, 0x4f, 0x72, 0xb2, 0xdd, 0x33, 0xbe, 0x5d,
        0x55, 0x70, 0xa9, 0xe3, 0x94, 0x29, 0x40, 0x29, 0x8f, 0x35, 0x23, 0xf8, 0x78, 0x7f, 0xfe,
        0xd6, 0x4b, 0x60, 0x16,
    ];

    round_trip(block_size, file_crc32, &test_chunks, &sha512);
}
