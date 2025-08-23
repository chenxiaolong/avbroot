// SPDX-FileCopyrightText: 2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use bstr::ByteSlice;
use rawzip::{
    CompressionMethod, RECOMMENDED_BUFFER_SIZE, ReaderAt, ZipArchive, ZipEntries, ZipEntry,
    ZipFileHeaderRecord, ZipLocator, ZipReader, ZipSliceArchive, ZipSliceEntries, ZipSliceEntry,
    ZipSliceVerifier, ZipVerifier,
    extra_fields::{ExtraFieldId, ExtraFields},
};
use zerocopy::{FromZeros, IntoBytes, little_endian};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    format::compression::{self, CompressedFormat, CompressedReader, CompressedWriter},
    stream::ReadAt,
};

pub trait ZipFileHeaderRecordExt<'a> {
    fn file_path_utf8(&self) -> Result<&'a str, rawzip::Error>;
}

impl<'a> ZipFileHeaderRecordExt<'a> for ZipFileHeaderRecord<'a> {
    fn file_path_utf8(&self) -> Result<&'a str, rawzip::Error> {
        str::from_utf8(self.file_path().as_bytes())
            .map_err(|e| rawzip::ErrorKind::InvalidUtf8(e).into())
    }
}

/// Validate that the current entry's compressed data range does not overlap
/// previously visited entries' ranges. This approach is identical to what
/// rawzip recommends in their examples.
fn validate_and_add_range(
    compressed_ranges: &mut Vec<(u64, u64)>,
    current_range: (u64, u64),
    path: &[u8],
) -> Result<(), rawzip::Error> {
    let (current_start, current_end) = current_range;

    let insert_pos = compressed_ranges
        .binary_search_by_key(&current_start, |&(start, _)| start)
        .unwrap_or_else(|pos| pos);

    if insert_pos > 0 {
        let (prev_start, prev_end) = compressed_ranges[insert_pos - 1];
        if prev_end > current_start {
            return Err(rawzip::ErrorKind::InvalidInput {
                msg: format!("{:?} ({current_start}..{current_end}) overlaps previous range ({prev_start}..{prev_end})", path.as_bstr()),
            }.into());
        }
    }

    if insert_pos < compressed_ranges.len() {
        let (next_start, next_end) = compressed_ranges[insert_pos];
        if current_end > next_start {
            return Err(rawzip::ErrorKind::InvalidInput {
                msg: format!("{:?} ({current_start}..{current_end}) overlaps next range ({next_start}..{next_end})", path.as_bstr()),
            }.into());
        }
    }

    compressed_ranges.insert(insert_pos, current_range);

    Ok(())
}

/// Validate that the entry's compression ratio is not excessively large, based
/// on a constant factor for [`CompressionMethod::Deflate`]. This approach is
/// identical to what rawzip recommends in their examples.
fn validate_compression_ratio(
    compressed_size: u64,
    uncompressed_size: u64,
    path: &[u8],
) -> Result<(), rawzip::Error> {
    if compressed_size > 0 && uncompressed_size / compressed_size > 1032 {
        #[allow(clippy::cast_precision_loss)]
        return Err(rawzip::ErrorKind::InvalidInput {
            msg: format!(
                "{:?} has excessively large compression ratio: {})",
                path.as_bstr(),
                uncompressed_size as f64 / compressed_size as f64,
            ),
        }
        .into());
    }

    Ok(())
}

#[derive(Debug)]
pub struct ZipEntriesSafe<'archive, 'buf, R> {
    archive: &'archive ZipArchive<R>,
    entries: ZipEntries<'archive, 'buf, R>,
    compressed_ranges: Vec<(u64, u64)>,
}

impl<R: ReaderAt> ZipEntriesSafe<'_, '_, R> {
    #[inline]
    pub fn next_entry(
        &mut self,
    ) -> Result<Option<(ZipFileHeaderRecord<'_>, ZipEntry<'_, R>)>, rawzip::Error> {
        let cd_entry = self.entries.next_entry()?;
        let Some(cd_entry) = cd_entry else {
            return Ok(None);
        };

        validate_compression_ratio(
            cd_entry.compressed_size_hint(),
            cd_entry.uncompressed_size_hint(),
            cd_entry.file_path().as_ref(),
        )?;

        let entry = self.archive.get_entry(cd_entry.wayfinder())?;

        validate_and_add_range(
            &mut self.compressed_ranges,
            entry.compressed_data_range(),
            cd_entry.file_path().as_ref(),
        )?;

        Ok(Some((cd_entry, entry)))
    }
}

pub trait ZipEntriesSafeExt<R> {
    fn entries_safe<'archive, 'buf>(
        &'archive self,
        buffer: &'buf mut [u8],
    ) -> ZipEntriesSafe<'archive, 'buf, R>;
}

impl<R> ZipEntriesSafeExt<R> for ZipArchive<R> {
    fn entries_safe<'archive, 'buf>(
        &'archive self,
        buffer: &'buf mut [u8],
    ) -> ZipEntriesSafe<'archive, 'buf, R> {
        let entries = self.entries(buffer);

        ZipEntriesSafe {
            archive: self,
            entries,
            compressed_ranges: Vec::new(),
        }
    }
}

impl<R, T: ZipEntriesSafeExt<R>> ZipEntriesSafeExt<R> for &T {
    fn entries_safe<'archive, 'buf>(
        &'archive self,
        buffer: &'buf mut [u8],
    ) -> ZipEntriesSafe<'archive, 'buf, R> {
        (**self).entries_safe(buffer)
    }
}

impl<R, T: ZipEntriesSafeExt<R>> ZipEntriesSafeExt<R> for &mut T {
    fn entries_safe<'archive, 'buf>(
        &'archive self,
        buffer: &'buf mut [u8],
    ) -> ZipEntriesSafe<'archive, 'buf, R> {
        (**self).entries_safe(buffer)
    }
}

#[derive(Debug)]
pub struct ZipSliceEntriesSafe<'data, T: AsRef<[u8]>> {
    archive: &'data ZipSliceArchive<T>,
    entries: ZipSliceEntries<'data>,
    compressed_ranges: Vec<(u64, u64)>,
}

impl<'data, T: AsRef<[u8]>> ZipSliceEntriesSafe<'data, T> {
    #[inline]
    pub fn next_entry(
        &mut self,
    ) -> Result<Option<(ZipFileHeaderRecord<'data>, ZipSliceEntry<'data>)>, rawzip::Error> {
        let cd_entry = self.entries.next_entry()?;
        let Some(cd_entry) = cd_entry else {
            return Ok(None);
        };

        validate_compression_ratio(
            cd_entry.compressed_size_hint(),
            cd_entry.uncompressed_size_hint(),
            cd_entry.file_path().as_ref(),
        )?;

        let entry = self.archive.get_entry(cd_entry.wayfinder())?;

        validate_and_add_range(
            &mut self.compressed_ranges,
            entry.compressed_data_range(),
            cd_entry.file_path().as_ref(),
        )?;

        Ok(Some((cd_entry, entry)))
    }
}

pub trait ZipSliceEntriesSafeExt<T: AsRef<[u8]>> {
    fn entries_safe(&self) -> ZipSliceEntriesSafe<'_, T>;
}

impl<T: AsRef<[u8]>> ZipSliceEntriesSafeExt<T> for ZipSliceArchive<T> {
    fn entries_safe(&self) -> ZipSliceEntriesSafe<'_, T> {
        let entries = self.entries();

        ZipSliceEntriesSafe {
            archive: self,
            entries,
            compressed_ranges: Vec::new(),
        }
    }
}

impl<T: AsRef<[u8]>, U: ZipSliceEntriesSafeExt<T>> ZipSliceEntriesSafeExt<T> for &U {
    fn entries_safe(&self) -> ZipSliceEntriesSafe<'_, T> {
        (**self).entries_safe()
    }
}

impl<T: AsRef<[u8]>, U: ZipSliceEntriesSafeExt<T>> ZipSliceEntriesSafeExt<T> for &mut U {
    fn entries_safe(&self) -> ZipSliceEntriesSafe<'_, T> {
        (**self).entries_safe()
    }
}

fn compression_method_to_format(
    compression_method: CompressionMethod,
) -> Result<CompressedFormat, rawzip::Error> {
    match compression_method {
        CompressionMethod::Store => Ok(CompressedFormat::None),
        CompressionMethod::Deflate => Ok(CompressedFormat::Deflate),
        c => Err(rawzip::ErrorKind::InvalidInput {
            msg: format!("Unsupported compression method: {c:?}"),
        }
        .into()),
    }
}

pub fn compressed_reader<'archive, R: ReaderAt>(
    entry: &ZipEntry<'archive, R>,
    compression_method: CompressionMethod,
) -> Result<CompressedReader<'archive, ZipReader<&'archive R>>, rawzip::Error> {
    let format = compression_method_to_format(compression_method)?;

    Ok(CompressedReader::with_format(entry.reader(), format))
}

pub fn compressed_slice_reader<'archive>(
    entry: &ZipSliceEntry<'archive>,
    compression_method: CompressionMethod,
) -> Result<CompressedReader<'archive, Cursor<&'archive [u8]>>, rawzip::Error> {
    let format = compression_method_to_format(compression_method)?;
    let raw_reader = Cursor::new(entry.data());

    Ok(CompressedReader::with_format(raw_reader, format))
}

pub fn verifying_reader<'archive, R: ReaderAt>(
    entry: &ZipEntry<'archive, R>,
    compression_method: CompressionMethod,
) -> Result<
    ZipVerifier<'archive, CompressedReader<'archive, ZipReader<&'archive R>>, R>,
    rawzip::Error,
> {
    compressed_reader(entry, compression_method).map(|r| entry.verifying_reader(r))
}

pub fn verifying_slice_reader<'archive>(
    entry: &ZipSliceEntry<'archive>,
    compression_method: CompressionMethod,
) -> Result<ZipSliceVerifier<CompressedReader<'archive, Cursor<&'archive [u8]>>>, rawzip::Error> {
    compressed_slice_reader(entry, compression_method).map(|r| entry.verifying_reader(r))
}

pub fn compressed_writer<'writer, W: Write + 'writer>(
    writer: W,
    compression_method: CompressionMethod,
) -> Result<CompressedWriter<'writer, W>, rawzip::Error> {
    use compression::Error;

    let format = compression_method_to_format(compression_method)?;

    match CompressedWriter::new(writer, format) {
        Ok(w) => Ok(w),
        Err(Error::Lz4Init(e) | Error::XzInit(e)) => Err(e.into()),
        Err(Error::UnknownFormat | Error::AutoDetect(_)) => unreachable!(),
    }
}

pub trait ZipArchiveReadAtExt {
    fn from_read_at<R: ReadAt>(
        file: R,
        buffer: &mut [u8],
    ) -> Result<ZipArchive<ReaderAtWrapper<R>>, rawzip::Error> {
        let end_offset = file.file_len()?;

        ZipLocator::new()
            .locate_in_reader(ReaderAtWrapper(file), buffer, end_offset)
            .map_err(|(_, e)| e)
    }
}

impl ZipArchiveReadAtExt for ZipArchive<()> {}

pub struct ReaderAtWrapper<R: ReadAt>(R);

impl<R: ReadAt> ReaderAt for ReaderAtWrapper<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        ReadAt::read_at(&self.0, buf, offset)
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct ZipLocalHeader {
    signature: little_endian::U32,
    version_needed: little_endian::U16,
    flags: little_endian::U16,
    compression_method: little_endian::U16,
    last_mod_time: little_endian::U16,
    last_mod_date: little_endian::U16,
    crc32: little_endian::U32,
    compressed_size: little_endian::U32,
    uncompressed_size: little_endian::U32,
    file_name_len: little_endian::U16,
    extra_field_len: little_endian::U16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct ZipCentralHeader {
    pub signature: little_endian::U32,
    pub version_made_by: little_endian::U16,
    pub version_needed: little_endian::U16,
    pub flags: little_endian::U16,
    pub compression_method: little_endian::U16,
    pub last_mod_time: little_endian::U16,
    pub last_mod_date: little_endian::U16,
    pub crc32: little_endian::U32,
    pub compressed_size: little_endian::U32,
    pub uncompressed_size: little_endian::U32,
    pub file_name_len: little_endian::U16,
    pub extra_field_len: little_endian::U16,
    pub file_comment_len: little_endian::U16,
    pub disk_number_start: little_endian::U16,
    pub internal_file_attrs: little_endian::U16,
    pub external_file_attrs: little_endian::U32,
    pub local_header_offset: little_endian::U32,
}

/// Convert a streaming zip into a non-streaming one. If any entry uses ZIP64,
/// the local header must contain an [`ExtraFieldId::ANDROID_ZIP_ALIGNMENT`]
/// extra field with sufficient size (16 bytes to be safe). This is used as
/// reserved space for creating a new [`ExtraFieldId::ZIP64`] extra field. Any
/// leftover space must be at least 4 bytes so that a new extra field can
/// consume the space. The existing data descriptor will remain in the gap
/// between entries and data will not be shifted.
pub fn make_non_streaming(file: impl Read + Write + Seek) -> Result<(), rawzip::Error> {
    // rawzip currently does not expose the CRC32 value, so we'll have to read
    // it ourselves.
    struct EntryInfo {
        local_header_offset: u64,
        central_header_offset: u64,
        crc32: u32,
        compressed_size: u64,
        uncompressed_size: u64,
        local_extra_fields: Vec<u8>,
    }

    let mut to_update = vec![];

    let mut central_buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let mut local_buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let archive = ZipArchive::from_seekable(file, &mut central_buffer)?;
    let mut entries = archive.entries_safe(&mut central_buffer);

    while let Some((cd_entry, entry)) = entries.next_entry()? {
        let wf = cd_entry.wayfinder();

        let local_header = entry.local_header(&mut local_buffer)?;

        to_update.push(EntryInfo {
            local_header_offset: cd_entry.local_header_offset(),
            central_header_offset: cd_entry.central_directory_offset(),
            crc32: cd_entry.crc32(),
            compressed_size: wf.compressed_size_hint(),
            uncompressed_size: wf.uncompressed_size_hint(),
            local_extra_fields: local_header.extra_fields().remaining_bytes().to_vec(),
        });
    }

    let mut file = archive.into_inner().into_inner();

    for entry in to_update {
        // Clear the central header's streaming flag.
        let mut central_flags = little_endian::U16::new(0);
        file.seek(SeekFrom::Start(entry.central_header_offset + 8))?;
        file.read_exact(central_flags.as_mut_bytes())?;
        central_flags &= !0x8;
        file.seek_relative(-(central_flags.as_bytes().len() as i64))?;
        file.write_all(central_flags.as_bytes())?;

        file.seek(SeekFrom::Start(entry.local_header_offset))?;

        let mut local_header = ZipLocalHeader::new_zeroed();
        file.read_exact(local_header.as_mut_bytes())?;

        // Clear the local header's streaming flag.
        local_header.flags &= !0x8;

        // Remove dependency on the data descriptor.
        local_header.crc32.set(entry.crc32);

        let compressed_is_zip64 = entry.compressed_size >= 0xffffffff;
        let uncompressed_is_zip64 = entry.uncompressed_size >= 0xffffffff;

        if compressed_is_zip64 {
            local_header.compressed_size.set(0xffffffff);
        } else {
            local_header
                .compressed_size
                .set(entry.compressed_size as u32);
        }

        if uncompressed_is_zip64 {
            local_header.uncompressed_size.set(0xffffffff);
        } else {
            local_header
                .uncompressed_size
                .set(entry.uncompressed_size as u32);
        }

        file.seek_relative(-(local_header.as_bytes().len() as i64))?;
        file.write_all(local_header.as_bytes())?;

        file.seek_relative(i64::from(local_header.file_name_len.get()))?;

        if !compressed_is_zip64 && !uncompressed_is_zip64 {
            continue;
        }

        let mut extra_fields = Vec::with_capacity(entry.local_extra_fields.len());
        let mut patched_placeholder = false;

        for (id, data) in ExtraFields::new(&entry.local_extra_fields) {
            if id == ExtraFieldId::ANDROID_ZIP_ALIGNMENT {
                let zip64_len =
                    8 * (usize::from(compressed_is_zip64) + usize::from(uncompressed_is_zip64));

                // Any unused space needs to be at least 4 bytes, so we can
                // properly write a new extra field for padding.
                let have_needed_space = match data.len().cmp(&zip64_len) {
                    Ordering::Less => false,
                    Ordering::Equal => true,
                    Ordering::Greater => data.len() - zip64_len >= 4,
                };
                if !have_needed_space {
                    return Err(rawzip::ErrorKind::InvalidInput {
                        msg: format!(
                            "Invalid reserved ZIP64 local extra field size: {}",
                            data.len()
                        ),
                    }
                    .into());
                }

                // The order is indeed backwards compared to the header
                // fields (APPNOTE 4.5.3).
                extra_fields.extend_from_slice(&ExtraFieldId::ZIP64.as_u16().to_le_bytes());
                extra_fields.extend_from_slice(&(zip64_len as u16).to_le_bytes());
                if uncompressed_is_zip64 {
                    extra_fields.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
                }
                if compressed_is_zip64 {
                    extra_fields.extend_from_slice(&entry.compressed_size.to_le_bytes());
                }

                // Keep using ANDROID_ZIP_ALIGNMENT for padding.
                if data.len() > zip64_len {
                    let padding_len = data.len() - zip64_len - 4;
                    extra_fields.extend_from_slice(&id.as_u16().to_le_bytes());
                    extra_fields.extend_from_slice(&(padding_len as u16).to_le_bytes());
                    extra_fields.resize(extra_fields.len() + padding_len, 0);
                }

                patched_placeholder = true;
            } else if id == ExtraFieldId::ZIP64 {
                return Err(rawzip::ErrorKind::InvalidInput {
                    msg: "Unexpected ZIP64 extra field present".to_owned(),
                }
                .into());
            } else {
                extra_fields.extend_from_slice(&id.as_u16().to_le_bytes());
                extra_fields.extend_from_slice(&(data.len() as u16).to_le_bytes());
                extra_fields.extend_from_slice(data);
            }
        }

        assert_eq!(extra_fields.len(), entry.local_extra_fields.len());

        if !patched_placeholder {
            return Err(rawzip::ErrorKind::InvalidInput {
                msg: "ZIP64 required, but no placeholder extra field found".to_owned(),
            }
            .into());
        }

        file.write_all(&extra_fields)?;
    }

    Ok(())
}
