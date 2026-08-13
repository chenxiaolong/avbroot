// SPDX-FileCopyrightText: 2024-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use prost::Message;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::{
    format::{
        avb::{self, AppendedDescriptorRef, Descriptor},
        payload::{self, PayloadHeader},
    },
    protobuf::recovery_update_verifier::{CareMap, care_map::PartitionInfo},
    stream::{ReadAt, ReadSeek, UserPosFile},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Partition not found in payload: {0}")]
    MissingPartition(String),
    #[error("No hash tree descriptor found in AVB header: {0}")]
    NoHashTreeDescriptor(String),
    #[error("No property descriptor found in AVB header: {partition}: {property}")]
    NoPropertyDescriptor { partition: String, property: String },
    #[error("Failed to extract payload operation #{1}: {0}")]
    Extract(String, usize, #[source] payload::Error),
    #[error("Failed to load AVB header from image: {0}")]
    AvbLoad(String, #[source] avb::Error),
    #[error("Failed to decode care map protobuf message")]
    Decode(#[source] prost::DecodeError),
}

type Result<T> = std::result::Result<T, Error>;

/// A sparse block-based in-memory file.
///
/// All operations are infallible outside of integer overflow.
pub struct SparseMemoryFile {
    block_size: u32,
    blocks: HashMap<u64, Vec<u8>>,
    size: u64,
    offset: u64,
}

impl SparseMemoryFile {
    pub fn new(block_size: u32) -> Self {
        assert!(block_size != 0, "Block size cannot be zero");

        Self {
            block_size,
            blocks: HashMap::new(),
            size: 0,
            offset: 0,
        }
    }
}

impl Read for SparseMemoryFile {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.offset >= self.size {
            return Ok(0);
        }

        let block_size = u64::from(self.block_size);
        let start_block = self.offset / block_size;
        let buf_remain = (self.size - self.offset).min(buf.len() as u64);
        let end_block = (self.offset + buf_remain).div_ceil(block_size);

        for block in start_block..end_block {
            let block_offset = self.offset % block_size;
            let block_remain = block_size - block_offset;
            let to_fill = buf.len().min(block_remain as usize);

            if let Some(data) = self.blocks.get(&block) {
                buf[..to_fill].copy_from_slice(&data[block_offset as usize..][..to_fill]);
            } else {
                buf[..to_fill].fill(0);
            }

            self.offset += to_fill as u64;
            buf = &mut buf[to_fill..];
        }

        Ok(buf_remain as usize)
    }
}

impl Write for SparseMemoryFile {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let block_size = u64::from(self.block_size);
        let start_block = self.offset / block_size;
        let end_offset = self.offset.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Write would put offset out-of-bounds",
            )
        })?;
        let end_block = end_offset.div_ceil(block_size);
        let buf_size = buf.len();

        for block in start_block..end_block {
            let data = self
                .blocks
                .entry(block)
                .or_insert_with(|| vec![0u8; block_size as usize]);
            let block_offset = self.offset % block_size;
            let to_copy = buf.len().min(data.len() - block_offset as usize);

            data[block_offset as usize..][..to_copy].copy_from_slice(&buf[..to_copy]);

            self.offset += to_copy as u64;
            if self.offset > self.size {
                self.size = self.offset;
            }

            buf = &buf[to_copy..];
        }

        Ok(buf_size)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SparseMemoryFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => self
                .size
                .checked_add_signed(o)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Out of bounds"))?,
            SeekFrom::Current(o) => self
                .offset
                .checked_add_signed(o)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Out of bounds"))?,
        };

        Ok(self.offset)
    }
}

/// Generate a care map [`PartitionInfo`] from the AVB metadata in the file.
pub fn generate_partition_info(
    reader: &mut dyn ReadSeek,
    block_size: u32,
    partition_name: &str,
) -> Result<PartitionInfo> {
    let (avb_header, _, _) =
        avb::load_image(reader).map_err(|e| Error::AvbLoad(partition_name.to_owned(), e))?;
    let appended = avb_header
        .appended_descriptor()
        .map_err(|e| Error::AvbLoad(partition_name.to_owned(), e))?;

    let AppendedDescriptorRef::HashTree(hash_tree) = appended else {
        return Err(Error::NoHashTreeDescriptor(partition_name.to_owned()));
    };

    let property = format!("com.android.build.{partition_name}.fingerprint");
    let fingerprint = avb_header
        .descriptors
        .iter()
        .find_map(|d| {
            if let Descriptor::Property(p) = d
                && p.key == property
            {
                p.value.to_str().map(|v| v.to_owned()).ok()
            } else {
                None
            }
        })
        .ok_or_else(|| Error::NoPropertyDescriptor {
            partition: partition_name.to_owned(),
            property,
        })?;

    let image_blocks = hash_tree.image_size / u64::from(block_size);

    Ok(PartitionInfo {
        name: partition_name.to_owned(),
        ranges: format!("2,0,{image_blocks}"),
        id: format!("ro.{partition_name}.build.fingerprint"),
        fingerprint,
    })
}

/// Generate a care_map [`PartitionInfo`] from the AVB metadata stored in the
/// specified payload partition image. This only extracts the portion of the
/// partition image containing the AVB metadata.
fn generate_partition_info_payload(
    payload: &mut dyn ReadSeek,
    header: &PayloadHeader,
    partition_name: &str,
    cancel_signal: &AtomicBool,
) -> Result<PartitionInfo> {
    let partition = header
        .manifest
        .partitions
        .iter()
        .find(|p| p.partition_name == partition_name)
        .ok_or_else(|| Error::MissingPartition(partition_name.to_owned()))?;

    let block_size = header.manifest.block_size();
    let num_operations = partition.operations.len();

    let mut partial_file = SparseMemoryFile::new(block_size);

    // Partition operations are guaranteed to be in sorted order and the footer
    // is guaranteed to be in the last operation since it is smaller than a
    // block.
    if let Some(operation) = partition.operations.last() {
        payload::apply_operation(
            payload,
            &mut partial_file,
            block_size,
            header.blob_offset,
            operation,
            cancel_signal,
        )
        .map_err(|e| Error::Extract(partition_name.to_owned(), num_operations, e))?;
    }

    let footer = avb::load_footer(&mut partial_file)
        .map_err(|e| Error::AvbLoad(partition_name.to_owned(), e))?;

    let vbmeta_end = footer
        .vbmeta_offset
        .checked_add(footer.vbmeta_size)
        .ok_or_else(|| {
            Error::AvbLoad(
                partition_name.to_owned(),
                avb::Error::IntOverflow("vbmeta_end"),
            )
        })?;

    // Find the partition operations that contain the AVB header.
    let start_op = partition.operations.binary_search_by(|op| {
        let Ok(bounds) = payload::operation_out_bounds(block_size, op) else {
            return Ordering::Greater;
        };

        if bounds.start > footer.vbmeta_offset {
            Ordering::Greater
        } else if bounds.end <= footer.vbmeta_offset {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    });
    if let Ok(start_index) = start_op {
        for index in start_index..num_operations {
            if index == num_operations {
                // Already extracted when grabbing the footer.
                continue;
            }

            let operation = &partition.operations[index];

            let bounds = payload::operation_out_bounds(block_size, operation)
                .map_err(|e| Error::Extract(partition_name.to_owned(), index, e))?;
            if bounds.start >= vbmeta_end {
                break;
            }

            payload::apply_operation(
                payload,
                &mut partial_file,
                block_size,
                header.blob_offset,
                operation,
                cancel_signal,
            )
            .map_err(|e| Error::Extract(partition_name.to_owned(), index, e))?;
        }
    }

    generate_partition_info(
        &mut partial_file,
        header.manifest.block_size(),
        partition_name,
    )
}

/// Generate a [`CareMap`] for all dynamic partitions in the payload. This is
/// done multithreaded and uses rayon's global thread pool.
pub fn generate_care_map<'name, 'file>(
    payload: &(dyn ReadAt + Sync),
    overrides: impl IntoIterator<Item = (&'name str, &'file (dyn ReadAt + Sync))>,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<CareMap> {
    let overrides = overrides.into_iter().collect::<HashMap<_, _>>();

    let partitions = if let Some(dpm) = &header.manifest.dynamic_partition_metadata {
        dpm.groups
            .par_iter()
            .flat_map(|g| &g.partition_names)
            .map(|name| -> Result<PartitionInfo> {
                if let Some(&file) = overrides.get(name.as_str()) {
                    let mut reader = UserPosFile::new(file);
                    generate_partition_info(&mut reader, header.manifest.block_size(), name)
                } else {
                    let mut reader = UserPosFile::new(payload);
                    generate_partition_info_payload(&mut reader, header, name, cancel_signal)
                }
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![]
    };

    let mut care_map = CareMap { partitions };
    normalize(&mut care_map);
    Ok(care_map)
}

/// Ensure that the care map is in normalized form so that the output is
/// reproducible regardless of the original sort order.
pub fn normalize(care_map: &mut CareMap) {
    care_map.partitions.sort_by(|a, b| a.name.cmp(&b.name));
}

/// Deserialize the care map from protobuf.
pub fn parse(data: &[u8]) -> Result<CareMap> {
    CareMap::decode(data).map_err(Error::Decode)
}

/// Serialize the care map to protobuf.
pub fn serialize(care_map: &CareMap) -> Vec<u8> {
    care_map.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_memory_file() {
        let mut file = SparseMemoryFile::new(8);
        assert_eq!(file.seek(SeekFrom::Current(0)).unwrap(), 0);

        assert_eq!(file.seek(SeekFrom::Start(4)).unwrap(), 4);
        assert_eq!(file.read(&mut vec![0; 4]).unwrap(), 0);
        assert_eq!(file.blocks.len(), 0);
        assert_eq!(file.size, 0);
        assert_eq!(file.offset, 4);

        // Initial write.
        assert_eq!(file.write(b"abcd").unwrap(), 4);
        assert_eq!(file.seek(SeekFrom::Current(0)).unwrap(), 8);
        assert_eq!(file.blocks.len(), 1);
        assert_eq!(file.blocks[&0], b"\0\0\0\0abcd");
        assert_eq!(file.size, 8);
        assert_eq!(file.offset, 8);

        let mut buf = vec![1; 16];
        file.rewind().unwrap();
        assert_eq!(file.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf[..8], b"\0\0\0\0abcd");
        assert_eq!(file.seek(SeekFrom::Current(0)).unwrap(), 8);

        // Write spanning multiple blocks.
        assert_eq!(file.seek(SeekFrom::Start(3)).unwrap(), 3);
        assert_eq!(file.write(b"efghijklmnop").unwrap(), 12);
        assert_eq!(file.blocks.len(), 2);
        assert_eq!(file.blocks[&0], b"\0\0\0efghi");
        assert_eq!(file.blocks[&1], b"jklmnop\0");
        assert_eq!(file.size, 15);
        assert_eq!(file.offset, 15);

        // Write until block boundary.
        assert_eq!(file.write(b"q").unwrap(), 1);
        assert_eq!(file.blocks.len(), 2);
        assert_eq!(file.blocks[&0], b"\0\0\0efghi");
        assert_eq!(file.blocks[&1], b"jklmnopq");
        assert_eq!(file.size, 16);
        assert_eq!(file.offset, 16);

        // Read spanning multiple blocks.
        assert_eq!(file.seek(SeekFrom::End(-13)).unwrap(), 3);
        buf.fill(1);
        assert_eq!(file.read(&mut buf).unwrap(), 13);
        assert_eq!(&buf[..13], b"efghijklmnopq");
    }
}
