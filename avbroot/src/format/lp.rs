// SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    io::{self, Read, Seek, Write},
    mem,
    num::NonZeroU64,
    str::{self, FromStr},
};

use bitflags::bitflags;
use bstr::ByteSlice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zerocopy::{byteorder::little_endian, FromBytes, FromZeros, Immutable, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    format::padding,
    stream::{
        CountingReader, FromReader, ReadDiscardExt, ReadFixedSizeExt, ToWriter, WriteZerosExt,
    },
    util::{self, is_zero, DebugString},
};

/// Magic value for [`RawGeometry::magic`].
const GEOMETRY_MAGIC: u32 = 0x616c4467;

/// Padded size for storing a [`RawGeometry`].
const GEOMETRY_SIZE: u32 = 4096;

/// Magic value for [`RawHeader::magic`].
const HEADER_MAGIC: u32 = 0x414C5030;

/// Supported major version.
pub const MAJOR_VERSION: u16 = 10;
/// Minimum supported minor version (inclusive).
pub const MINOR_VERSION_MIN: u16 = 0;
/// Maximum supported minor version (inclusive).
pub const MINOR_VERSION_MAX: u16 = 2;

/// Minor version required for using [`PartitionAttribute::UPDATED`].
const VERSION_FOR_UPDATED_ATTR: u16 = 1;
/// Metadata minor version needed for the 256-byte [`RawHeader`] instead of the
/// 128-byte header without [`RawHeader::flags`] and [`RawHeader::reserved`].
const VERSION_FOR_EXPANDED_HEADER: u16 = 2;

/// Size of a sector.
pub const SECTOR_SIZE: u32 = 512;

/// Padding at the beginning of a super image to avoid creating a boot sector.
const PARTITION_RESERVED_BYTES: u32 = 4096;

/// Maximum allowed size of [`RawGeometry::metadata_max_size`] to prevent the
/// memory usage from blowing up.
const METADATA_MAX_SIZE: u32 = 128 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    // Naming errors.
    #[error("Invalid partition name: {0:?}")]
    PartitionNameInvalid(DebugString),
    // Geometry errors.
    #[error("Invalid geometry magic: {0:#010x}")]
    GeometryInvalidMagic(u32),
    #[error("Invalid geometry size: {0} != {size}", size = mem::size_of::<RawGeometry>())]
    GeometryInvalidSize(u32),
    #[error("Expected geometry digest {expected}, but have {actual}")]
    GeometryInvalidDigest { expected: String, actual: String },
    #[error("Maximum metadata size is not sector-aligned: {0}")]
    MaxMetadataSizeUnaligned(u32),
    #[error("Maximum metadata size exceeds limit: {0} > {METADATA_MAX_SIZE}")]
    MaxMetadataSizeTooLarge(u32),
    #[error("No metadata slots defined")]
    NoMetadataSlots,
    #[error("Logical block size is not sector-aligned: {0}")]
    LogicalBlockSizeUnaligned(u32),
    // Descriptor errors.
    #[error("Descriptor offset #{0}: Entry count too large")]
    DescriptorEntryCountTooLarge(u32),
    #[error("Descriptor offset #{0}: Next entry offset too large")]
    DescriptorNextOffsetTooLarge(u32),
    // Header errors.
    #[error("Invalid header magic: {0:#010x}")]
    HeaderInvalidMagic(u32),
    #[error("Unsupported header version: {major}.{minor}")]
    HeaderUnsupportedVersion { major: u16, minor: u16 },
    #[error("Invalid header size: {0} != {size}", size = mem::size_of::<RawHeader>())]
    HeaderInvalidSize(u32),
    #[error("Expected header digest {expected}, but have {actual}")]
    HeaderInvalidDigest { expected: String, actual: String },
    #[error("Metadata slot exceeds maximum size: {metadata_size} > {max_size} - {header_size}")]
    MetadataTooLarge {
        metadata_size: u32,
        max_size: u32,
        header_size: u32,
    },
    #[error("Descriptors too large or have gaps")]
    DescriptorsTooLargeOrHaveGaps,
    #[error("Gap after last descriptor")]
    DescriptorsFinalGap,
    #[error("Invalid descriptor entry sizes")]
    DescriptorsInvalidEntrySizes,
    #[error("Descriptor entry count {entry_count} does not match {name} table length {table_len}")]
    DescriptorMismatchedEntryCount {
        name: &'static str,
        entry_count: u32,
        table_len: usize,
    },
    #[error("Expected tables digest {expected}, but have {actual}")]
    HeaderInvalidTablesDigest { expected: String, actual: String },
    // Partition errors.
    #[error("Partition {name:?}: Invalid attributes: {}", .attributes.0)]
    PartitionInvalidAttributes {
        name: DebugString,
        attributes: PartitionAttributes,
    },
    #[error("Partition {name:?}: Extent indices too large")]
    PartitionExtentIndicesTooLarge { name: DebugString },
    #[error("Partition {name:?}: Extent indices set on empty image")]
    PartitionExtentIndicesEmptyImage { name: DebugString },
    #[error("Partition {name:?}: Extent index too large")]
    PartitionExtentIndexTooLarge { name: DebugString },
    #[error("Partition {name:?}: Extent count too large")]
    PartitionExtentCountTooLarge { name: DebugString },
    #[error("Partition {name:?}: Invalid partition group index: {index}")]
    PartitionInvalidGroupIndex { name: DebugString, index: u32 },
    #[error("Partition {name:?}: Sector count too large")]
    PartitionSectorCountTooLarge { name: DebugString },
    #[error("Partition {name:?}: Byte count too large")]
    PartitionByteCountTooLarge { name: DebugString },
    // Extent errors.
    #[error("Extent #{index}: Invalid block device index: {device_index}")]
    ExtentInvalidDeviceIndex { index: usize, device_index: u32 },
    #[error("Extent #{index}: End sector too large: {start} + {count}")]
    ExtentEndSectorTooLarge {
        index: usize,
        start: u64,
        count: u64,
    },
    #[error("Extent #{index}: {start} starts before block device's first sector {sector}")]
    ExtentStartBeforeDeviceStart {
        index: usize,
        start: u64,
        sector: u64,
    },
    #[error("Extent #{index}: {end} ends after block device's last sector {sector}")]
    ExtentEndsAfterDeviceEnd { index: usize, end: u64, sector: u64 },
    #[error("Extent #{index}: Type zero extents cannot have non-zero sector or device")]
    ExtentTypeZeroNotEmpty { index: usize },
    #[error("Extent #{index}: Invalid type: {extent_type}")]
    ExtentInvalidType { index: usize, extent_type: u32 },
    #[error("Extent #{index}: Overlaps another extent: #{other}")]
    ExtentOverlapsAnother { index: usize, other: usize },
    #[error("Extent #{index}: Block device index too large")]
    ExtentDeviceIndexTooLarge { index: usize },
    // Partition group errors.
    #[error("Group {name:?}: Total size of partitions too large")]
    GroupTotalSizeTooLarge { name: DebugString },
    #[error("Group {name:?}: Total partition size {size} exceeds limit {limit}")]
    GroupTotalSizeExceedsLimit {
        name: DebugString,
        size: u64,
        limit: u64,
    },
    #[error("Group {name:?}: Index too large")]
    GroupIndexTooLarge { name: DebugString },
    // Block device errors.
    #[error("Device {name:?}: Alignment is 0")]
    DeviceAlignmentIsZero { name: DebugString },
    #[error("Device {name:?}: Partition alignment is not sector-aligned")]
    DeviceAlignmentNotSectorAligned { name: DebugString },
    #[error("Device {name:?}: First logical sector is not partition-aligned")]
    DeviceFirstSectorNotAligned { name: DebugString },
    #[error("Device {name:?}: Alignment offset is not sector-aligned")]
    DeviceOffsetNotSectorAligned { name: DebugString },
    #[error("Device {name:?}: Size is not sector-aligned")]
    DeviceSizeNotSectorAligned { name: DebugString },
    // Metadata errors.
    #[error("Expected slot count {expected}, but have {actual}")]
    MismatchedSlotCount { expected: usize, actual: usize },
    // Allocator errors.
    #[error("Insufficient space on block devices to allocate sectors")]
    AllocatorDeviceFull,
    // Wrapped errors.
    #[error("Failed to read LP data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write LP data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct HeaderFlags: u32 {
        /// The device uses virtual A/B.
        const VIRTUAL_AB_DEVICE = 1 << 0;
        /// The device has overlay mounts due to `adb remount`.
        const OVERLAYS_ACTIVE = 1 << 1;

        const _ = !0;
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct PartitionAttributes: u32 {
        /// The device-mapper block device should be created as read-only.
        const READONLY = 1 << 0;
        /// The super partition itself needs a slot suffix appended.
        const SLOT_SUFFIXED = 1 << 1;
        /// The partition was created or modified for an OTA update using
        /// snapuserd.
        const UPDATED = 1 << 2;
        /// The partition should be mapped in device-mapper.
        const DISABLED = 1 << 3;

        const _ = !0;
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct PartitionGroupFlags: u32 {
        /// Whether the group name needs a slot suffix to be appended.
        const SLOT_SUFFIXED = 1 << 0;

        const _ = !0;
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct BlockDeviceFlags: u32 {
        /// Whether the partition name needs a slot suffix to be appended.
        const SLOT_SUFFIXED = 1 << 0;

        const _ = !0;
    }
}

impl PartitionAttributes {
    /// Attributes introduced in metadata minor version 0.
    pub const MASK_V0: Self = Self::READONLY.union(Self::SLOT_SUFFIXED);
    /// Attributes introduced in metadata minor version 1.
    pub const MASK_V1: Self = Self::UPDATED.union(Self::DISABLED);
    /// All supported attributes.
    pub const MASK: Self = Self::MASK_V0.union(Self::MASK_V1);
}

/// Raw on-disk layout for the metadata geometry.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawGeometry {
    /// Magic value. This should be equal to [`GEOMETRY_MAGIC`].
    magic: little_endian::U32,
    /// Size of this [`RawGeometry`].
    struct_size: little_endian::U32,
    /// SHA-256 checksum of this [`RawGeometry`] when this field is set to all
    /// zeros.
    checksum: [u8; 32],
    /// Maximum size of a single copy of the metadata (header + tables). This
    /// must be a multiple of [`SECTOR_SIZE`].
    metadata_max_size: little_endian::U32,
    /// Number of metadata slots, excluding the backup copies.
    metadata_slot_count: little_endian::U32,
    /// Block device block size for the logical partitions. This must be a
    /// multiple of [`SECTOR_SIZE`].
    logical_block_size: little_endian::U32,
}

const _: () = assert!(mem::size_of::<RawGeometry>() < GEOMETRY_SIZE as usize);

impl fmt::Debug for RawGeometry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawGeometry")
            .field("magic", &format_args!("{:#010x}", self.magic.get()))
            .field("struct_size", &self.struct_size.get())
            .field("checksum", &hex::encode(self.checksum))
            .field("metadata_max_size", &self.metadata_max_size.get())
            .field("metadata_slot_count", &self.metadata_slot_count.get())
            .field("logical_block_size", &self.logical_block_size.get())
            .finish()
    }
}

impl RawGeometry {
    /// Ensure that all fields are semantically valid and can be used without
    /// further checks.
    fn validate(&self) -> Result<()> {
        if self.magic.get() != GEOMETRY_MAGIC {
            return Err(Error::GeometryInvalidMagic(self.magic.get()));
        }

        if self.struct_size.get() != mem::size_of::<Self>() as u32 {
            return Err(Error::GeometryInvalidSize(self.struct_size.get()));
        }

        #[cfg(not(fuzzing))]
        {
            let mut copy = *self;
            copy.checksum.fill(0);

            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, copy.as_bytes());
            if digest.as_ref() != self.checksum {
                return Err(Error::GeometryInvalidDigest {
                    expected: hex::encode(self.checksum),
                    actual: hex::encode(digest),
                });
            }
        }

        if self.metadata_max_size.get() == 0 || self.metadata_max_size.get() % SECTOR_SIZE != 0 {
            return Err(Error::MaxMetadataSizeUnaligned(
                self.metadata_max_size.get(),
            ));
        } else if self.metadata_max_size.get() > METADATA_MAX_SIZE {
            return Err(Error::MaxMetadataSizeTooLarge(self.metadata_max_size.get()));
        } else if self.metadata_slot_count.get() == 0 {
            return Err(Error::NoMetadataSlots);
        }

        if self.logical_block_size.get() % SECTOR_SIZE != 0 {
            return Err(Error::LogicalBlockSizeUnaligned(
                self.logical_block_size.get(),
            ));
        }

        Ok(())
    }
}

/// Raw on-disk layout for a table descriptor within a [`RawHeader`].
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawTableDescriptor {
    /// Offset relative to the end of the [`RawHeader`].
    offset: little_endian::U32,
    /// Number of entries in the table.
    num_entries: little_endian::U32,
    /// Size of each entry.
    entry_size: little_endian::U32,
}

impl fmt::Debug for RawTableDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawTableDescriptor")
            .field("offset", &self.offset.get())
            .field("num_entries", &self.num_entries.get())
            .field("entry_size", &self.entry_size.get())
            .finish()
    }
}

impl RawTableDescriptor {
    /// Return a slice of the specified table item type `T` from the tables
    /// buffer. `buf` must have size [`RawHeader::tables_size`] and the header
    /// containing this descriptor must have already passed
    /// [`RawHeader::validate`]. Otherwise, this function may panic.
    fn slice_from_buf<'a, T: FromBytes + Immutable + 'a>(&self, buf: &'a [u8]) -> &'a [T] {
        let offset = self.offset.get() as usize;
        let entry_size = self.entry_size.get() as usize;
        let size = self.num_entries.get() as usize * entry_size;
        let buf = &buf[offset..][..size];

        assert_eq!(mem::size_of::<T>(), entry_size);

        <[T]>::ref_from_bytes(buf).unwrap()
    }

    /// Update all fields to match the slice of items beginning at the specified
    /// table offset. Returns the starting offset for the next table.
    fn update<T: IntoBytes>(&mut self, items: &[T], offset: u32) -> Result<u32> {
        let entry_size = mem::size_of::<T>() as u32;
        let num_entries: u32 = items
            .len()
            .try_into()
            .map_err(|_| Error::DescriptorEntryCountTooLarge(offset))?;
        let next_offset = entry_size
            .checked_mul(num_entries)
            .and_then(|o| o.checked_add(offset))
            .ok_or(Error::DescriptorNextOffsetTooLarge(offset))?;

        self.offset = offset.into();
        self.entry_size = entry_size.into();
        self.num_entries = num_entries.into();

        Ok(next_offset)
    }
}

/// Raw on-disk layout for the metadata header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHeader {
    /// Magic value. This should be equal to [`HEADER_MAGIC`].
    magic: little_endian::U32,
    /// Major version. [`MAJOR_VERSION`] is the only version supported. All
    /// other versions cannot be parsed.
    major_version: little_endian::U16,
    /// Minor version. Versions between [`MINOR_VERSION_MIN`] and
    /// [`MINOR_VERSION_MAX`] are supported.
    minor_version: little_endian::U16,
    /// Size of this [`RawHeader`].
    header_size: little_endian::U32,
    /// SHA-256 checksum of this [`RawHeader`] when this field is set to all
    /// zeros.
    header_checksum: [u8; 32],
    /// Size of all tables.
    tables_size: little_endian::U32,
    /// SHA-256 checksum of all tables.
    tables_checksum: [u8; 32],
    /// Partition table descriptor.
    partitions: RawTableDescriptor,
    /// Extent table descriptor.
    extents: RawTableDescriptor,
    /// Updatable group descriptor.
    groups: RawTableDescriptor,
    /// Block device table descriptor.
    block_devices: RawTableDescriptor,
    /// [Minor version >=2 only] Header flags. These are informational and do
    /// not affect parsing.
    flags: little_endian::U32,
    /// [Minor version >=2 only] Reserved bytes for future header versions.
    reserved: [u8; 124],
}

impl fmt::Debug for RawHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawHeader")
            .field("magic", &format_args!("{:#010x}", self.magic.get()))
            .field("major_version", &self.major_version.get())
            .field("minor_version", &self.minor_version.get())
            .field("header_size", &self.header_size.get())
            .field("header_checksum", &hex::encode(self.header_checksum))
            .field("tables_size", &self.tables_size.get())
            .field("tables_checksum", &hex::encode(self.tables_checksum))
            .field("partitions", &self.partitions)
            .field("extents", &self.extents)
            .field("groups", &self.groups)
            .field("block_devices", &self.block_devices)
            .field("flags", &HeaderFlags::from_bits_retain(self.flags.get()).0)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl RawHeader {
    const SIZE_V1_0: usize = mem::offset_of!(Self, flags);

    fn size_for_version(major_version: u16, minor_version: u16) -> usize {
        if major_version == MAJOR_VERSION && minor_version >= VERSION_FOR_EXPANDED_HEADER {
            mem::size_of::<Self>()
        } else {
            Self::SIZE_V1_0
        }
    }

    fn size(&self) -> usize {
        Self::size_for_version(self.major_version.get(), self.minor_version.get())
    }

    fn validate_descriptor(
        &self,
        descriptor: &RawTableDescriptor,
        start_offset: u32,
    ) -> Option<u32> {
        if descriptor.offset.get() != start_offset {
            return None;
        }

        let size = descriptor
            .num_entries
            .get()
            .checked_mul(descriptor.entry_size.get())?;
        let next_offset = start_offset.checked_add(size)?;

        if next_offset > self.tables_size.get() {
            return None;
        }

        Some(next_offset)
    }

    /// Ensure that all fields are semantically valid and can be used without
    /// further checks. [`RawGeometry::validate`] must have passed before this
    /// function is called.
    fn validate(&self, geometry: &RawGeometry) -> Result<()> {
        if self.magic.get() != HEADER_MAGIC {
            return Err(Error::HeaderInvalidMagic(self.magic.get()));
        }

        if self.major_version.get() != MAJOR_VERSION || self.minor_version.get() > MINOR_VERSION_MAX
        {
            return Err(Error::HeaderUnsupportedVersion {
                major: self.major_version.get(),
                minor: self.minor_version.get(),
            });
        }

        let expected_size = self.size();

        if self.header_size.get() != expected_size as u32 {
            return Err(Error::HeaderInvalidSize(self.header_size.get()));
        }

        if self.minor_version.get() < VERSION_FOR_EXPANDED_HEADER {
            // This would be an implementation error.
            assert!(self.flags.get() == 0);
            assert!(util::is_zero(&self.reserved));
        }

        #[cfg(not(fuzzing))]
        {
            let mut copy = *self;
            copy.header_checksum.fill(0);

            let portion = &copy.as_bytes()[..expected_size];

            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, portion);
            if digest.as_ref() != self.header_checksum {
                return Err(Error::HeaderInvalidDigest {
                    expected: hex::encode(self.header_checksum),
                    actual: hex::encode(digest),
                });
            }
        }

        // metadata_max_size is guaranteed to be at least one sector, so the
        // subtraction cannot overflow.
        if self.tables_size.get() > geometry.metadata_max_size.get() - self.header_size.get() {
            return Err(Error::MetadataTooLarge {
                metadata_size: self.tables_size.get(),
                max_size: geometry.metadata_max_size.get(),
                header_size: self.header_size.get(),
            });
        }

        let mut offset = 0;

        // The tables must be contiguous.
        for descriptor in [
            &self.partitions,
            &self.extents,
            &self.groups,
            &self.block_devices,
        ] {
            offset = self
                .validate_descriptor(descriptor, offset)
                .ok_or(Error::DescriptorsTooLargeOrHaveGaps)?;
        }

        // There cannot be a gap at the end either.
        if offset != self.tables_size.get() {
            return Err(Error::DescriptorsFinalGap);
        }

        if self.partitions.entry_size.get() != mem::size_of::<RawPartition>() as u32
            || self.extents.entry_size.get() != mem::size_of::<RawExtent>() as u32
            || self.groups.entry_size.get() != mem::size_of::<RawPartitionGroup>() as u32
            || self.block_devices.entry_size.get() != mem::size_of::<RawBlockDevice>() as u32
        {
            return Err(Error::DescriptorsInvalidEntrySizes);
        }

        Ok(())
    }
}

/// A potentially invalid raw partition name string.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct PartitionName([u8; 36]);

impl fmt::Debug for PartitionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, suffix) = self.split();
        let display = if util::is_zero(suffix) {
            prefix
        } else {
            &self.0
        };

        fmt::Debug::fmt(&display.as_bstr(), f)
    }
}

impl PartitionName {
    fn split(&self) -> (&[u8], &[u8]) {
        self.0
            .iter()
            .position(|b| *b == 0)
            .map_or((&self.0, &[]), |i| self.0.split_at(i))
    }

    fn validate(&self) -> Result<()> {
        let (prefix, suffix) = self.split();

        // AOSP liblp's metadata_format.h says "Characters may only be
        // alphanumeric or _", but AOSP creates partitions named like
        // "system_b-cow".
        let prefix_valid = prefix
            .iter()
            .all(|b| matches!(*b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'));

        if prefix_valid && is_zero(suffix) {
            Ok(())
        } else {
            Err(Error::PartitionNameInvalid(DebugString::new(self)))
        }
    }

    fn as_str(&self) -> Result<&str> {
        self.validate()?;

        // ASCII is always UTF-8.
        Ok(str::from_utf8(self.split().0).unwrap())
    }
}

impl FromStr for PartitionName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut name = Self([0u8; 36]);

        if s.len() > name.0.len() {
            return Err(Error::PartitionNameInvalid(DebugString::new(s)));
        }

        let to_copy = s.len().min(name.0.len());
        name.0[..to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);

        name.validate()?;

        Ok(name)
    }
}

/// Raw on-disk layout for an entry in the logical partitions table.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawPartition {
    /// Partition name in ASCII. This must be unique across all partitions.
    name: PartitionName,
    /// Partition attributes.
    attributes: little_endian::U32,
    /// Index of the first extent owned by this partition.
    first_extent_index: little_endian::U32,
    /// Number of extents covered by this partition.
    num_extents: little_endian::U32,
    /// Index of the group containing this partition.
    group_index: little_endian::U32,
}

impl fmt::Debug for RawPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attributes = PartitionAttributes::from_bits_retain(self.attributes.get());

        f.debug_struct("RawPartition")
            .field("name", &self.name)
            .field("attributes", &attributes.0)
            .field("first_extent_index", &self.first_extent_index.get())
            .field("num_extents", &self.num_extents.get())
            .field("group_index", &self.group_index.get())
            .finish()
    }
}

impl RawPartition {
    /// Ensure that all fields are semantically valid and can be used without
    /// further checks. [`RawHeader::validate`] must have passed before this
    /// function is called, but [`RawExtent::validate`] and
    /// [`RawPartitionGroup::validate`] do not.
    fn validate(
        &self,
        image_type: ImageType,
        header: &RawHeader,
        extents: &[RawExtent],
        groups: &[RawPartitionGroup],
    ) -> Result<()> {
        self.name.validate()?;

        let mut valid_attributes = PartitionAttributes::MASK_V0;
        if header.minor_version.get() >= VERSION_FOR_UPDATED_ATTR {
            valid_attributes |= PartitionAttributes::MASK_V1;
        }

        let attributes = PartitionAttributes::from_bits_retain(self.attributes.get());

        if !(attributes - valid_attributes).is_empty() {
            return Err(Error::PartitionInvalidAttributes {
                name: DebugString::new(self.name),
                attributes,
            });
        }

        match image_type {
            ImageType::Normal => {
                if self
                    .first_extent_index
                    .get()
                    .checked_add(self.num_extents.get())
                    .is_none_or(|n| n as usize > extents.len())
                {
                    return Err(Error::PartitionExtentIndicesTooLarge {
                        name: DebugString::new(self.name),
                    });
                }
            }
            ImageType::Empty => {
                if self.first_extent_index.get() != 0 || self.num_extents.get() != 0 {
                    return Err(Error::PartitionExtentIndicesEmptyImage {
                        name: DebugString::new(self.name),
                    });
                }
            }
        }

        if self.group_index.get() as usize >= groups.len() {
            return Err(Error::PartitionInvalidGroupIndex {
                name: DebugString::new(self.name),
                index: self.group_index.get(),
            });
        }

        Ok(())
    }
}

/// Raw on-disk layout for an entry in the extent table.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawExtent {
    /// Number of [`SECTOR_SIZE`]-byte sectors in this extent.
    num_sectors: little_endian::U64,
    /// device-mapper target type.
    target_type: little_endian::U32,
    /// For [`TargetType::Linear`], this is the physical partition sector that
    /// this extent maps to. For [`TargetType::Zero`], this is always 0.
    target_data: little_endian::U64,
    /// For [`TargetType::Linear`], this is the index into the block devices
    /// table specifying the physical source of this extent. For
    /// [`TargetType::Zero`], this is always 0.
    target_source: little_endian::U32,
}

impl fmt::Debug for RawExtent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawExtent")
            .field("num_sectors", &self.num_sectors.get())
            .field("target_type", &self.target_type.get())
            .field("target_data", &self.target_data.get())
            .field("target_source", &self.target_source.get())
            .finish()
    }
}

impl RawExtent {
    /// dm-linear target.
    const TARGET_TYPE_LINEAR: u32 = 0;
    /// dm-zero target.
    const TARGET_TYPE_ZERO: u32 = 1;

    /// Ensure that all fields are semantically valid and can be used without
    /// further checks. [`RawBlockDevice::validate`] does not need to have
    /// passed before this function is called.
    fn validate(&self, index: usize, block_devices: &[RawBlockDevice]) -> Result<()> {
        match self.target_type.get() {
            Self::TARGET_TYPE_LINEAR => {
                let Some(device) = block_devices.get(self.target_source.get() as usize) else {
                    return Err(Error::ExtentInvalidDeviceIndex {
                        index,
                        device_index: self.target_source.get(),
                    });
                };

                let count = self.num_sectors.get();
                let start = self.target_data.get();
                let end = start.checked_add(count).ok_or({
                    Error::ExtentEndSectorTooLarge {
                        index,
                        start,
                        count,
                    }
                })?;

                if start < device.first_logical_sector.get() {
                    return Err(Error::ExtentStartBeforeDeviceStart {
                        index,
                        start,
                        sector: device.first_logical_sector.get(),
                    });
                }

                let device_sectors = device.size.get() / u64::from(SECTOR_SIZE);

                if end > device_sectors {
                    return Err(Error::ExtentEndsAfterDeviceEnd {
                        index,
                        end,
                        sector: device_sectors,
                    });
                }
            }
            Self::TARGET_TYPE_ZERO => {
                if self.target_data.get() != 0 || self.target_source.get() != 0 {
                    return Err(Error::ExtentTypeZeroNotEmpty { index });
                }
            }
            n => {
                return Err(Error::ExtentInvalidType {
                    index,
                    extent_type: n,
                })
            }
        }

        Ok(())
    }
}

/// Raw on-disk layout for an entry in the partition groups table.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawPartitionGroup {
    /// Partition group name in ASCII. This must be unique across all groups.
    name: PartitionName,
    /// Partition group flags.
    flags: little_endian::U32,
    /// Maximum size of all partitions in this group. If this is set to 0, then
    /// there is no size limit.
    maximum_size: little_endian::U64,
}

impl fmt::Debug for RawPartitionGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = PartitionGroupFlags::from_bits_retain(self.flags.get());

        f.debug_struct("RawPartitionGroup")
            .field("name", &self.name)
            .field("flags", &flags.0)
            .field("maximum_size", &self.maximum_size.get())
            .finish()
    }
}

impl RawPartitionGroup {
    /// Ensure that all fields are semantically valid and can be used without
    /// further checks. [`RawPartition::validate`] and [`RawExtent::validate`]
    /// must have passed for all specified partitions and extents before this
    /// function is called.
    fn validate(
        &self,
        index: usize,
        partitions: &[RawPartition],
        extents: &[RawExtent],
    ) -> Result<()> {
        if self.maximum_size.get() != 0 {
            let mut total_size = 0u64;

            for partition in partitions {
                if partition.group_index.get() as usize == index {
                    let first = partition.first_extent_index.get() as usize;
                    let count = partition.num_extents.get() as usize;

                    for extent in &extents[first..][..count] {
                        total_size = total_size
                            .checked_add(extent.num_sectors.get())
                            .ok_or_else(|| Error::GroupTotalSizeTooLarge {
                                name: DebugString::new(self.name),
                            })?;
                    }
                }
            }

            if total_size > self.maximum_size.get() {
                return Err(Error::GroupTotalSizeExceedsLimit {
                    name: DebugString::new(self.name),
                    size: total_size,
                    limit: self.maximum_size.get(),
                });
            }
        }

        self.name.validate()
    }
}

/// Raw on-disk layout for an entry in the block devices table.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawBlockDevice {
    /// The first [`SECTOR_SIZE`]-byte sector where actual data for the logical
    /// partitions can be allocated.
    first_logical_sector: little_endian::U64,
    /// Alignment for the partition start offset.
    alignment: little_endian::U32,
    /// Adjustment for when the super partition itself is not aligned.
    alignment_offset: little_endian::U32,
    /// Block device size.
    size: little_endian::U64,
    /// Partition name in ASCII. This must be unique across all block devices.
    partition_name: PartitionName,
    /// Block device flags.
    flags: little_endian::U32,
}

impl fmt::Debug for RawBlockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = BlockDeviceFlags::from_bits_retain(self.flags.get());

        f.debug_struct("RawBlockDevice")
            .field("first_logical_sector", &self.first_logical_sector.get())
            .field("alignment", &self.alignment.get())
            .field("alignment_offset", &self.alignment_offset.get())
            .field("size", &self.size.get())
            .field("partition_name", &self.partition_name)
            .field("flags", &flags.0)
            .finish()
    }
}

impl RawBlockDevice {
    /// Ensure that all fields are semantically valid and can be used without
    /// further checks.
    fn validate(&self) -> Result<()> {
        if self.alignment.get() == 0 {
            return Err(Error::DeviceAlignmentIsZero {
                name: DebugString::new(self.partition_name),
            });
        } else if self.alignment.get() % SECTOR_SIZE != 0 {
            return Err(Error::DeviceAlignmentNotSectorAligned {
                name: DebugString::new(self.partition_name),
            });
        }

        let alignment_sectors = u64::from(self.alignment.get() / SECTOR_SIZE);
        if self.first_logical_sector.get() % alignment_sectors != 0 {
            return Err(Error::DeviceFirstSectorNotAligned {
                name: DebugString::new(self.partition_name),
            });
        }

        if self.alignment_offset.get() % SECTOR_SIZE != 0 {
            return Err(Error::DeviceOffsetNotSectorAligned {
                name: DebugString::new(self.partition_name),
            });
        }

        if self.size.get() % u64::from(SECTOR_SIZE) != 0 {
            return Err(Error::DeviceSizeNotSectorAligned {
                name: DebugString::new(self.partition_name),
            });
        }

        self.partition_name.validate()
    }
}

/// A wrapper around the on-disk layouts for a single metadata slot.
#[derive(Clone, Debug)]
struct RawMetadataSlot {
    header: RawHeader,
    partitions: Vec<RawPartition>,
    extents: Vec<RawExtent>,
    groups: Vec<RawPartitionGroup>,
    block_devices: Vec<RawBlockDevice>,
}

impl RawMetadataSlot {
    /// Ensure that all fields are semantically valid and can be used without
    /// further checks.
    fn validate(&self, image_type: ImageType, geometry: &RawGeometry) -> Result<()> {
        self.header.validate(geometry)?;

        for (len, descriptor, name) in [
            (self.partitions.len(), &self.header.partitions, "partition"),
            (self.extents.len(), &self.header.extents, "extent"),
            (self.groups.len(), &self.header.groups, "partition group"),
            (
                self.block_devices.len(),
                &self.header.block_devices,
                "block device",
            ),
        ] {
            if len != descriptor.num_entries.get() as usize {
                return Err(Error::DescriptorMismatchedEntryCount {
                    name,
                    entry_count: descriptor.num_entries.get(),
                    table_len: len,
                });
            }
        }

        // Although not all of the table validation functions require their
        // dependencies to be validated first, we'll validate these tables in
        // topological order just to be safe.

        for block_device in &self.block_devices {
            block_device.validate()?;
        }

        for (i, extent) in self.extents.iter().enumerate() {
            extent.validate(i, &self.block_devices)?;
        }

        // Ensure that all extents are not overlapping. We have to sort here
        // because the extents may not be in order when loading the super
        // partition on an actual device. Also, AOSP liblp's `metadata_format.h`
        // says "Gaps between extents are not allowed", but AOSP frequently
        // creates this situation after a virtual A/B CoW merge.
        let mut sorted_extents = self
            .extents
            .iter()
            .enumerate()
            .filter(|(_, e)| e.target_type.get() == RawExtent::TARGET_TYPE_LINEAR)
            .collect::<Vec<_>>();
        sorted_extents.sort_by_key(|(_, e)| (e.target_source, e.target_data));

        for window in sorted_extents.windows(2) {
            let ((a_i, a), (b_i, b)) = (window[0], window[1]);

            if a.target_source == b.target_source
                && a.target_data.get() + a.num_sectors.get() > b.target_data.get()
            {
                return Err(Error::ExtentOverlapsAnother {
                    index: b_i,
                    other: a_i,
                });
            }
        }

        for partition in &self.partitions {
            partition.validate(image_type, &self.header, &self.extents, &self.groups)?;
        }

        for (i, group) in self.groups.iter().enumerate() {
            group.validate(i, &self.partitions, &self.extents)?;
        }

        Ok(())
    }
}

/// A type for storing the raw metadata of an LP image. This only validates
/// fields when reading and writing the image. No fields are recomputed during
/// writes to guarantee lossless round tripping.
#[derive(Clone, Debug)]
struct RawMetadata {
    image_type: ImageType,
    geometry: RawGeometry,
    slots: Vec<RawMetadataSlot>,
}

impl RawMetadata {
    /// Read the [`RawGeometry`] at the current offset.
    fn read_geometry(mut reader: impl Read) -> Result<(ImageType, RawGeometry)> {
        let mut buf = [0u8; GEOMETRY_SIZE as usize];
        reader
            .read_exact(&mut buf)
            .map_err(|e| Error::DataRead("geometry", e))?;

        // For non-empty images, AOSP says the first block is supposed to be
        // filled with zeros, but Samsung puts their own SignerVer02 structure
        // in there, so we can't rely on that.
        let mut geometry = RawGeometry::ref_from_prefix(&buf).unwrap().0;

        let image_type = match geometry.validate() {
            Ok(()) => {
                // This is an empty image for use with fastboot. These have no
                // extra padding at the beginning of the file nor backup copies
                // of the geometry and metadata structs.
                ImageType::Empty
            }
            Err(Error::GeometryInvalidMagic(_)) => {
                // This is an normal non-empty image, which has extra padding at
                // the beginning to avoid having the geometry struct interpreted
                // as a boot sector.

                // Read the primary copy of the geometry.
                reader
                    .read_exact(&mut buf)
                    .map_err(|e| Error::DataRead("geometry_primary", e))?;

                geometry = RawGeometry::ref_from_prefix(&buf).unwrap().0;

                if geometry.validate().is_ok() {
                    // Skip the backup copy.
                    reader
                        .read_discard_exact(GEOMETRY_SIZE.into())
                        .map_err(|e| Error::DataRead("geometry_secondary", e))?;
                } else {
                    // Try to parse the backup copy.
                    reader
                        .read_exact(&mut buf)
                        .map_err(|e| Error::DataRead("geometry_secondary", e))?;

                    geometry = RawGeometry::ref_from_prefix(&buf).unwrap().0;
                    geometry.validate()?;
                }

                ImageType::Normal
            }
            Err(e) => return Err(e),
        };

        Ok((image_type, geometry.to_owned()))
    }

    /// Read a single [`RawMetadataSlot`], including the header and all tables.
    /// This does not read the extra padding between the end of the last table
    /// and [`RawGeometry::metadata_max_size`].
    fn read_metadata(
        mut reader: impl Read,
        image_type: ImageType,
        geometry: &RawGeometry,
    ) -> Result<RawMetadataSlot> {
        let mut header = RawHeader::new_zeroed();

        reader
            .read_exact(&mut header.as_mut_bytes()[..RawHeader::SIZE_V1_0])
            .map_err(|e| Error::DataRead("header_v1.0", e))?;
        if header.size() > RawHeader::SIZE_V1_0 {
            reader
                .read_exact(&mut header.as_mut_bytes()[RawHeader::SIZE_V1_0..])
                .map_err(|e| Error::DataRead("header_v1.2", e))?;
        }

        // We'll end up validating this again at the end, but this initial
        // validation is necessary so ensure everything is in bounds when
        // parsing the tables.
        header.validate(geometry)?;

        let tables_buf = reader
            .read_vec_exact(header.tables_size.get() as usize)
            .map_err(|e| Error::DataRead("tables", e))?;

        let partitions = header
            .partitions
            .slice_from_buf::<RawPartition>(&tables_buf);
        let extents = header.extents.slice_from_buf::<RawExtent>(&tables_buf);
        let groups = header
            .groups
            .slice_from_buf::<RawPartitionGroup>(&tables_buf);
        let block_devices = header
            .block_devices
            .slice_from_buf::<RawBlockDevice>(&tables_buf);

        let slot = RawMetadataSlot {
            header,
            partitions: partitions.to_vec(),
            extents: extents.to_vec(),
            groups: groups.to_vec(),
            block_devices: block_devices.to_vec(),
        };

        slot.validate(image_type, geometry)?;

        Ok(slot)
    }

    /// Ensure that all fields are semantically valid and can be used without
    /// further checks.
    fn validate(&self) -> Result<()> {
        self.geometry.validate()?;

        let expected_slots = match self.image_type {
            ImageType::Normal => self.geometry.metadata_slot_count.get() as usize,
            ImageType::Empty => 1,
        };
        if self.slots.len() != expected_slots {
            return Err(Error::MismatchedSlotCount {
                expected: expected_slots,
                actual: self.slots.len(),
            });
        }

        for slot in &self.slots {
            #[cfg(not(fuzzing))]
            {
                let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
                context.update(slot.partitions.as_bytes());
                context.update(slot.extents.as_bytes());
                context.update(slot.groups.as_bytes());
                context.update(slot.block_devices.as_bytes());
                let digest = context.finish();

                if digest.as_ref() != slot.header.tables_checksum {
                    return Err(Error::HeaderInvalidTablesDigest {
                        expected: hex::encode(slot.header.tables_checksum),
                        actual: hex::encode(digest),
                    });
                }
            }

            slot.validate(self.image_type, &self.geometry)?;
        }

        Ok(())
    }
}

impl<R: Read> FromReader<R> for RawMetadata {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let (image_type, geometry) = Self::read_geometry(&mut reader)?;

        let (num_copies, num_slots) = match image_type {
            // Normal images have a backup copy of everything and contains all
            // slots.
            ImageType::Normal => (2, geometry.metadata_slot_count.get() as usize),
            // Empty images only contain one slot, no matter what the geometry
            // says.
            ImageType::Empty => (1, 1),
        };
        let mut slots = vec![None; num_slots];
        let mut last_err = None;

        for _ in 0..num_copies {
            for slot in &mut slots {
                let mut to_skip = u64::from(geometry.metadata_max_size.get());

                if slot.is_none() {
                    let orig_offset = reader
                        .stream_position()
                        .map_err(|e| Error::DataRead("orig_offset", e))?;

                    match Self::read_metadata(&mut reader, image_type, &geometry) {
                        Ok(m) => *slot = Some(m),
                        Err(e @ Error::DataRead(_, _)) => return Err(e),
                        Err(e) => last_err = Some(e),
                    }

                    // Skip the remaining padding.
                    let cur_offset = reader
                        .stream_position()
                        .map_err(|e| Error::DataRead("cur_offset", e))?;
                    to_skip -= cur_offset - orig_offset;
                }

                reader
                    .read_discard(to_skip)
                    .map_err(|e| Error::DataRead("slot_padding", e))?;
            }
        }

        let slots = slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| last_err.unwrap())?;

        Ok(Self {
            image_type,
            geometry,
            slots,
        })
    }
}

impl<W: Write> ToWriter<W> for RawMetadata {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        self.validate()?;

        let geometry = self.geometry.as_bytes();
        let geometry_padding = GEOMETRY_SIZE as usize - geometry.len();

        match self.image_type {
            ImageType::Normal => {
                writer
                    .write_zeros_exact(PARTITION_RESERVED_BYTES.into())
                    .map_err(|e| Error::DataWrite("reserved", e))?;

                for _ in 0..2 {
                    writer
                        .write_all(geometry)
                        .map_err(|e| Error::DataWrite("geometry", e))?;
                    writer
                        .write_zeros_exact(geometry_padding as u64)
                        .map_err(|e| Error::DataWrite("geometry_padding", e))?;
                }

                let metadata_max_size = self.geometry.metadata_max_size.get() as usize;

                for _ in 0..2 {
                    for slot in &self.slots {
                        let header_size = RawHeader::size_for_version(
                            slot.header.major_version.get(),
                            slot.header.minor_version.get(),
                        );
                        let header = &slot.header.as_bytes()[..header_size];
                        let tables_size = slot.header.tables_size.get() as usize;
                        let metadata_padding = metadata_max_size - header.len() - tables_size;

                        writer
                            .write_all(header)
                            .map_err(|e| Error::DataWrite("header", e))?;
                        writer
                            .write_all(slot.partitions.as_bytes())
                            .map_err(|e| Error::DataWrite("partition_tables", e))?;
                        writer
                            .write_all(slot.extents.as_bytes())
                            .map_err(|e| Error::DataWrite("extent_tables", e))?;
                        writer
                            .write_all(slot.groups.as_bytes())
                            .map_err(|e| Error::DataWrite("group_tables", e))?;
                        writer
                            .write_all(slot.block_devices.as_bytes())
                            .map_err(|e| Error::DataWrite("block_device_tables", e))?;
                        writer
                            .write_zeros_exact(metadata_padding as u64)
                            .map_err(|e| Error::DataWrite("metadata_padding", e))?;
                    }
                }
            }
            ImageType::Empty => {
                writer
                    .write_all(geometry)
                    .map_err(|e| Error::DataWrite("geometry", e))?;
                writer
                    .write_zeros_exact(geometry_padding as u64)
                    .map_err(|e| Error::DataWrite("geometry_padding", e))?;

                writer
                    .write_all(self.slots[0].header.as_bytes())
                    .map_err(|e| Error::DataWrite("header", e))?;
                writer
                    .write_all(self.slots[0].partitions.as_bytes())
                    .map_err(|e| Error::DataWrite("partition_tables", e))?;
                writer
                    .write_all(self.slots[0].extents.as_bytes())
                    .map_err(|e| Error::DataWrite("extent_tables", e))?;
                writer
                    .write_all(self.slots[0].groups.as_bytes())
                    .map_err(|e| Error::DataWrite("group_tables", e))?;
                writer
                    .write_all(self.slots[0].block_devices.as_bytes())
                    .map_err(|e| Error::DataWrite("block_device_tables", e))?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum ImageType {
    /// An normal LP image containing actual partition data. This has the final
    /// layout for how the image would be stored on disk on a device. There is
    /// a [`PARTITION_RESERVED_BYTES`]-byte gap at the beginning of the image,
    /// followed by two copies of the geometry structure and two copies of the
    /// metadata.
    Normal,
    /// An empty LP image containing no partition data. This is meant for use
    /// with fastboot only (`super_empty.img`). There are no reserved bytes at
    /// the beginning of the image and there is only a single copy of the
    /// geometry and the metadata. The metadata is not padded to the maximum
    /// size specified in the geometry.
    Empty,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Partition {
    /// Partition name in ASCII.
    pub name: String,
    /// Partition attributes.
    pub attributes: PartitionAttributes,
    /// Extents covered by this partition.
    #[serde(skip)]
    pub extents: Vec<Extent>,
}

impl fmt::Debug for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Partition")
            .field("name", &self.name)
            .field("attributes", &self.attributes.0)
            .field("extents", &self.extents)
            .finish()
    }
}

impl Partition {
    /// Compute the number of sectors covered by the extents.
    pub fn num_sectors(&self) -> Result<u64> {
        self.extents
            .iter()
            .try_fold(0u64, |total, e| total.checked_add(e.num_sectors))
            .ok_or_else(|| Error::PartitionSectorCountTooLarge {
                name: DebugString::new(&self.name),
            })
    }

    /// Compute the number of bytes covered by the extents.
    pub fn size(&self) -> Result<u64> {
        self.num_sectors()
            .ok()
            .and_then(|n| n.checked_mul(SECTOR_SIZE.into()))
            .ok_or_else(|| Error::PartitionByteCountTooLarge {
                name: DebugString::new(&self.name),
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentType {
    Linear {
        /// The physical sector that this extent starts at on the block device.
        start_sector: u64,
        /// The index of the block device that backs this extent.
        block_device_index: usize,
    },
    Zero,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Extent {
    /// Number of [`SECTOR_SIZE`]-byte sectors in this extent.
    pub num_sectors: u64,
    /// device-mapper target type.
    pub extent_type: ExtentType,
}

impl fmt::Debug for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extent")
            .field("num_sectors", &self.num_sectors)
            .field("extent_type", &self.extent_type)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PartitionGroup {
    /// Partition group name in ASCII.
    pub name: String,
    /// Partition group flags.
    pub flags: PartitionGroupFlags,
    /// Maximum size of all partitions in this group.
    pub maximum_size: Option<NonZeroU64>,
    /// The partitions in this group.
    pub partitions: Vec<Partition>,
}

impl fmt::Debug for PartitionGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartitionGroup")
            .field("name", &self.name)
            .field("flags", &self.flags.0)
            .field("maximum_size", &format_args!("{:?}", self.maximum_size))
            .field("partitions", &self.partitions)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BlockDevice {
    /// The first [`SECTOR_SIZE`]-byte sector where actual data for the logical
    /// partitions can be allocated.
    pub first_logical_sector: u64,
    /// Alignment for both partition and extent sizes
    pub alignment: u32,
    /// Alignment offset for when the super partition itself is not aligned.
    pub alignment_offset: u32,
    /// Block device size.
    pub size: u64,
    /// Partition name in ASCII.
    pub partition_name: String,
    /// Block device flags.
    pub flags: BlockDeviceFlags,
}

impl fmt::Debug for BlockDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockDevice")
            .field("first_logical_sector", &self.first_logical_sector)
            .field("alignment", &self.alignment)
            .field("alignment_offset", &self.alignment_offset)
            .field("size", &self.size)
            .field("partition_name", &self.partition_name)
            .field("flags", &self.flags.0)
            .finish()
    }
}

/// Basic allocator that allocates sectors from a list of block devices linearly
/// and respects alignment if requested.
#[derive(Clone, Copy, Debug)]
struct LinearAllocator<'a> {
    devices: &'a [BlockDevice],
    /// Current device to allocate from.
    index: usize,
    /// Current device's alignment in sectors.
    align: u64,
    /// Starting sector for next (potentially unaligned) allocation.
    sector: u64,
    /// Remaining free sectors.
    remain: u64,
}

impl<'a> LinearAllocator<'a> {
    pub fn new(devices: &'a [BlockDevice]) -> Self {
        let device = &devices[0];
        let align = u64::from(device.alignment / SECTOR_SIZE);
        let sector = device.first_logical_sector;
        let remain = device.size / u64::from(SECTOR_SIZE) - sector;

        Self {
            devices,
            index: 0,
            align,
            sector,
            remain,
        }
    }

    /// Move to the next [`BlockDevice`]. [`Self::sector`] is guaranteed to be
    /// aligned.
    fn move_to_next_device(&mut self) -> Result<()> {
        if self.index + 1 == self.devices.len() {
            return Err(Error::AllocatorDeviceFull);
        }

        self.index += 1;

        let device = &self.devices[self.index];
        self.align = u64::from(device.alignment / SECTOR_SIZE);
        self.sector = device.first_logical_sector;
        self.remain = device.size / u64::from(SECTOR_SIZE) - self.sector;

        Ok(())
    }

    /// Try to allocate some sectors. If this allocation would need to cross a
    /// block device boundary, then this will only return the first extent on
    /// the current device. Call this function again with the remaining sectors
    /// to get the next extent.
    pub fn try_allocate(&mut self, req_sectors: u64) -> Result<Extent> {
        if self.remain == 0 {
            // We do this here instead of at the end of the function so that
            // allocation does not fail if we fill up every device exactly.
            self.move_to_next_device()?;
        } else {
            let padding = padding::calc(self.sector, self.align);
            if padding >= self.remain {
                // The rest of this device is unusable due to alignment. The
                // starting sector of the next device will be aligned and there
                // will be at least one free sector available.
                self.move_to_next_device()?;
            } else {
                self.sector += padding;
                self.remain -= padding;
            }
        }

        let extent = Extent {
            num_sectors: req_sectors.min(self.remain),
            extent_type: ExtentType::Linear {
                start_sector: self.sector,
                block_device_index: self.index,
            },
        };

        self.sector += extent.num_sectors;
        self.remain -= extent.num_sectors;

        Ok(extent)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetadataSlot {
    /// Major version. [`MAJOR_VERSION`] is the only version supported. All
    /// other versions cannot be parsed.
    pub major_version: u16,
    /// Minor version. Versions between [`MINOR_VERSION_MIN`] and
    /// [`MINOR_VERSION_MAX`] are supported.
    pub minor_version: u16,
    /// List of partition groups.
    pub groups: Vec<PartitionGroup>,
    /// List of block devices containing data extents.
    pub block_devices: Vec<BlockDevice>,
    /// Header flags. These are informational and do not affect parsing.
    pub flags: HeaderFlags,
}

impl fmt::Debug for MetadataSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataSlot")
            .field("major_version", &self.major_version)
            .field("minor_version", &self.minor_version)
            .field("groups", &self.groups)
            .field("block_devices", &self.block_devices)
            .field("flags", &self.flags.0)
            .finish()
    }
}

impl MetadataSlot {
    /// Recompute the extents for every partition, allocating from each sector
    /// device in order as they fill up. Each partition will have a starting
    /// sector that is aligned to [`BlockDevice::alignment`]. As long as the
    /// partition fits on a single device, it will only have a single extent.
    pub fn reallocate_extents(&mut self) -> Result<()> {
        {
            let raw_slot: RawMetadataSlot = (&*self).try_into()?;

            for raw_block_device in &raw_slot.block_devices {
                raw_block_device.validate()?;
            }
        }

        let mut allocator = LinearAllocator::new(&self.block_devices);

        for group in &mut self.groups {
            for partition in &mut group.partitions {
                let mut sectors = partition.num_sectors()?;
                let mut extents = vec![];

                while sectors > 0 {
                    let extent = allocator.try_allocate(sectors)?;
                    sectors -= extent.num_sectors;
                    extents.push(extent);
                }

                partition.extents = extents;
            }
        }

        Ok(())
    }
}

impl TryFrom<&RawMetadataSlot> for MetadataSlot {
    type Error = Error;

    fn try_from(raw_slot: &RawMetadataSlot) -> Result<Self> {
        let mut slot = MetadataSlot {
            major_version: raw_slot.header.major_version.get(),
            minor_version: raw_slot.header.minor_version.get(),
            groups: Vec::with_capacity(raw_slot.groups.len()),
            block_devices: Vec::with_capacity(raw_slot.block_devices.len()),
            flags: HeaderFlags::from_bits_retain(raw_slot.header.flags.get()),
        };

        for raw_group in &raw_slot.groups {
            let group = PartitionGroup {
                name: raw_group.name.as_str()?.to_owned(),
                flags: PartitionGroupFlags::from_bits_retain(raw_group.flags.get()),
                maximum_size: NonZeroU64::new(raw_group.maximum_size.get()),
                partitions: Vec::new(),
            };

            slot.groups.push(group);
        }

        for raw_partition in &raw_slot.partitions {
            let group_index = raw_partition.group_index.get() as usize;
            let first_extent = raw_partition.first_extent_index.get() as usize;
            let num_extents = raw_partition.num_extents.get() as usize;

            let mut partition = Partition {
                name: raw_partition.name.as_str()?.to_owned(),
                attributes: PartitionAttributes::from_bits_retain(raw_partition.attributes.get()),
                extents: Vec::with_capacity(num_extents),
            };

            for raw_extent in &raw_slot.extents[first_extent..][..num_extents] {
                let extent = Extent {
                    num_sectors: raw_extent.num_sectors.get(),
                    extent_type: match raw_extent.target_type.get() {
                        RawExtent::TARGET_TYPE_LINEAR => ExtentType::Linear {
                            start_sector: raw_extent.target_data.get(),
                            block_device_index: raw_extent.target_source.get() as usize,
                        },
                        RawExtent::TARGET_TYPE_ZERO => ExtentType::Zero,
                        _ => unreachable!(),
                    },
                };

                partition.extents.push(extent);
            }

            slot.groups[group_index].partitions.push(partition);
        }

        for raw_block_device in &raw_slot.block_devices {
            let block_device = BlockDevice {
                first_logical_sector: raw_block_device.first_logical_sector.get(),
                alignment: raw_block_device.alignment.get(),
                alignment_offset: raw_block_device.alignment_offset.get(),
                size: raw_block_device.size.get(),
                partition_name: raw_block_device.partition_name.as_str()?.to_owned(),
                flags: BlockDeviceFlags::from_bits_retain(raw_block_device.flags.get()),
            };

            slot.block_devices.push(block_device);
        }

        Ok(slot)
    }
}

impl TryFrom<RawMetadataSlot> for MetadataSlot {
    type Error = Error;

    fn try_from(raw_slot: RawMetadataSlot) -> Result<Self> {
        (&raw_slot).try_into()
    }
}

impl TryFrom<&MetadataSlot> for RawMetadataSlot {
    type Error = Error;

    fn try_from(slot: &MetadataSlot) -> Result<Self> {
        let header_size = RawHeader::size_for_version(slot.major_version, slot.minor_version);

        let mut raw_slot = RawMetadataSlot {
            header: RawHeader {
                magic: HEADER_MAGIC.into(),
                major_version: slot.major_version.into(),
                minor_version: slot.minor_version.into(),
                header_size: (header_size as u32).into(),
                header_checksum: Default::default(),
                tables_size: 0.into(),
                tables_checksum: Default::default(),
                partitions: RawTableDescriptor::new_zeroed(),
                extents: RawTableDescriptor::new_zeroed(),
                groups: RawTableDescriptor::new_zeroed(),
                block_devices: RawTableDescriptor::new_zeroed(),
                flags: slot.flags.bits().into(),
                reserved: [0u8; 124],
            },
            partitions: Vec::new(),
            extents: Vec::new(),
            groups: Vec::with_capacity(slot.groups.len()),
            block_devices: Vec::with_capacity(slot.block_devices.len()),
        };

        for group in &slot.groups {
            let raw_group = RawPartitionGroup {
                name: group.name.parse()?,
                flags: group.flags.bits().into(),
                maximum_size: group
                    .maximum_size
                    .map(|s| s.get())
                    .unwrap_or_default()
                    .into(),
            };

            let group_index: u32 =
                raw_slot
                    .groups
                    .len()
                    .try_into()
                    .map_err(|_| Error::GroupIndexTooLarge {
                        name: DebugString::new(&group.name),
                    })?;

            for partition in &group.partitions {
                let extent_index: u32 = raw_slot.extents.len().try_into().map_err(|_| {
                    Error::PartitionExtentIndexTooLarge {
                        name: DebugString::new(&partition.name),
                    }
                })?;
                let num_extents: u32 = partition.extents.len().try_into().map_err(|_| {
                    Error::PartitionExtentCountTooLarge {
                        name: DebugString::new(&partition.name),
                    }
                })?;

                let raw_partition = RawPartition {
                    name: partition.name.parse()?,
                    attributes: partition.attributes.bits().into(),
                    first_extent_index: extent_index.into(),
                    num_extents: num_extents.into(),
                    group_index: group_index.into(),
                };

                for extent in &partition.extents {
                    let (target_type, target_data, target_source) = match extent.extent_type {
                        ExtentType::Linear {
                            start_sector,
                            block_device_index,
                        } => {
                            let block_device_index: u32 =
                                block_device_index.try_into().map_err(|_| {
                                    Error::ExtentDeviceIndexTooLarge {
                                        index: raw_slot.extents.len(),
                                    }
                                })?;

                            (
                                RawExtent::TARGET_TYPE_LINEAR,
                                start_sector,
                                block_device_index,
                            )
                        }
                        ExtentType::Zero => (RawExtent::TARGET_TYPE_ZERO, 0, 0),
                    };

                    let raw_extent = RawExtent {
                        num_sectors: extent.num_sectors.into(),
                        target_type: target_type.into(),
                        target_data: target_data.into(),
                        target_source: target_source.into(),
                    };

                    raw_slot.extents.push(raw_extent);
                }

                raw_slot.partitions.push(raw_partition);
            }

            raw_slot.groups.push(raw_group);
        }

        for block_device in &slot.block_devices {
            let raw_block_device = RawBlockDevice {
                first_logical_sector: block_device.first_logical_sector.into(),
                alignment: block_device.alignment.into(),
                alignment_offset: block_device.alignment_offset.into(),
                size: block_device.size.into(),
                partition_name: block_device.partition_name.parse()?,
                flags: block_device.flags.bits().into(),
            };

            raw_slot.block_devices.push(raw_block_device);
        }

        let mut offset = 0u32;

        offset = raw_slot
            .header
            .partitions
            .update(&raw_slot.partitions, offset)?;
        offset = raw_slot.header.extents.update(&raw_slot.extents, offset)?;
        offset = raw_slot.header.groups.update(&raw_slot.groups, offset)?;
        offset = raw_slot
            .header
            .block_devices
            .update(&raw_slot.block_devices, offset)?;

        raw_slot.header.tables_size = offset.into();

        let tables_digest = {
            let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
            context.update(raw_slot.partitions.as_bytes());
            context.update(raw_slot.extents.as_bytes());
            context.update(raw_slot.groups.as_bytes());
            context.update(raw_slot.block_devices.as_bytes());
            context.finish()
        };
        raw_slot
            .header
            .tables_checksum
            .copy_from_slice(tables_digest.as_ref());

        let header_digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            &raw_slot.header.as_bytes()[..header_size],
        );
        raw_slot
            .header
            .header_checksum
            .copy_from_slice(header_digest.as_ref());

        Ok(raw_slot)
    }
}

impl TryFrom<MetadataSlot> for RawMetadataSlot {
    type Error = Error;

    fn try_from(slot: MetadataSlot) -> Result<Self> {
        (&slot).try_into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Metadata {
    /// Image type.
    pub image_type: ImageType,
    /// Maximum size of a single copy of the metadata (header + tables). This
    /// must be a multiple of [`SECTOR_SIZE`].
    pub metadata_max_size: u32,
    /// Number of metadata slots.
    pub metadata_slot_count: u32,
    /// Block device block size for the logical partitions. This must be a
    /// multiple of [`SECTOR_SIZE`].
    pub logical_block_size: u32,
    /// List of metadata slots. There must only be 1 actual slot when
    /// [`Self::image_type`] is [`ImageType::Empty`], regardless of the value of
    /// [`Self::metadata_slot_count`].
    pub slots: Vec<MetadataSlot>,
}

impl TryFrom<&RawMetadata> for Metadata {
    type Error = Error;

    fn try_from(raw_metadata: &RawMetadata) -> Result<Self> {
        let mut metadata = Self {
            image_type: raw_metadata.image_type,
            metadata_max_size: raw_metadata.geometry.metadata_max_size.get(),
            metadata_slot_count: raw_metadata.geometry.metadata_slot_count.get(),
            logical_block_size: raw_metadata.geometry.logical_block_size.get(),
            slots: Vec::with_capacity(raw_metadata.slots.len()),
        };

        for raw_slot in &raw_metadata.slots {
            let slot: MetadataSlot = raw_slot.try_into()?;

            metadata.slots.push(slot);
        }

        Ok(metadata)
    }
}

impl TryFrom<RawMetadata> for Metadata {
    type Error = Error;

    fn try_from(raw_metadata: RawMetadata) -> Result<Self> {
        (&raw_metadata).try_into()
    }
}

impl TryFrom<&Metadata> for RawMetadata {
    type Error = Error;

    fn try_from(metadata: &Metadata) -> Result<Self> {
        // We only do the bare minimum calculations needed here to fill out the
        // raw fields. There is no semantic validation.

        let mut raw_metadata = RawMetadata {
            image_type: metadata.image_type,
            geometry: RawGeometry {
                magic: GEOMETRY_MAGIC.into(),
                struct_size: (mem::size_of::<RawGeometry>() as u32).into(),
                checksum: Default::default(),
                metadata_max_size: metadata.metadata_max_size.into(),
                metadata_slot_count: metadata.metadata_slot_count.into(),
                logical_block_size: metadata.logical_block_size.into(),
            },
            slots: Vec::with_capacity(metadata.slots.len()),
        };

        let geometry_digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, raw_metadata.geometry.as_bytes());
        raw_metadata
            .geometry
            .checksum
            .copy_from_slice(geometry_digest.as_ref());

        for slot in &metadata.slots {
            let raw_slot: RawMetadataSlot = slot.try_into()?;

            raw_metadata.slots.push(raw_slot);
        }

        Ok(raw_metadata)
    }
}

impl TryFrom<Metadata> for RawMetadata {
    type Error = Error;

    fn try_from(metadata: Metadata) -> Result<Self> {
        (&metadata).try_into()
    }
}

impl<R: Read> FromReader<R> for Metadata {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        RawMetadata::from_reader(reader)?.try_into()
    }
}

impl<W: Write> ToWriter<W> for Metadata {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        let raw_metadata: RawMetadata = self.try_into()?;
        raw_metadata.validate()?;
        raw_metadata.to_writer(writer)
    }
}
