// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    io::{self, Cursor, SeekFrom},
    ops::Range,
    sync::atomic::AtomicBool,
};

use memchr::memmem;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use thiserror::Error;
use tracing::{debug, debug_span, trace, Span};
use x509_cert::Certificate;
use zip::ZipArchive;

use crate::{
    crypto::RsaSigningKey,
    format::{
        avb::{self, AppendedDescriptorMut, Footer},
        ota,
    },
    patch::otacert,
    stream::{self, ReadSeekReopen, SectionReader, WriteSeekReopen},
    util,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Old otacerts.zip not found in image")]
    OldZipNotFound,
    #[error("Image has no vbmeta footer")]
    NoFooter,
    #[error("No hash tree descriptor found in vbmeta header")]
    NoHashTreeDescriptor,
    #[error("{0:?} overflowed integer bounds during calculations")]
    IntOverflow(&'static str),
    #[error("AVB error")]
    Avb(#[from] avb::Error),
    #[error("OTA certificate error")]
    OtaCert(#[from] otacert::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Find the bounds of a non-zip64 zip starting from the EOCD magic offset.
fn find_zip_bounds(data: &[u8], eocd_offset: usize) -> Option<Range<usize>> {
    let eocd = &data[eocd_offset..];
    if eocd.len() < 22 {
        trace!("Buffer is too small to contain EOCD");
        return None;
    }

    let cd_size = u32::from_le_bytes(eocd[12..16].try_into().unwrap()) as usize;
    let cd_offset = u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as usize;
    let comment_size = usize::from(u16::from_le_bytes(eocd[20..22].try_into().unwrap()));

    let start = eocd_offset.checked_sub(cd_size)?.checked_sub(cd_offset)?;
    let end = eocd_offset.checked_add(22)?.checked_add(comment_size)?;
    if end > data.len() {
        trace!("End of zip is out of bounds");
        return None;
    }

    trace!("Found zip bounds: {:?}", start..end);

    let reader = SectionReader::new(Cursor::new(data), start as u64, (end - start) as u64).ok()?;
    let mut zip_reader = ZipArchive::new(reader).ok()?;

    if zip_reader.is_empty() {
        // otacerts.zip files contain at least one cert.
        trace!("Zip is empty");
        return None;
    }

    for index in 0..zip_reader.len() {
        let entry = zip_reader.by_index_raw(index).ok()?;

        if !entry.name().ends_with(".x509.pem") {
            // otacerts.zip files only contain files named this way.
            trace!("Excluded due to invalid name: {:?}", entry.name());
            return None;
        }
    }

    debug!("Found otacerts.zip candidate");

    // There's one or more entries and every one is named *.x509.pem.
    Some(start..end)
}

/// Replace `otacerts.zip` with a new one containing the new certificate, but
/// padded to the same size. If the new zip is too large, the certificate will
/// be modified to remove unnecessary components until it fits. All operations
/// run in parallel where possible. The input and output must refer to the same
/// file and will be reopened from multiple threads.
///
/// Returns two sorted and non-overlapping lists of byte ranges that were
/// modified. The first list are the byte regions within the filesystem data
/// that contained otacerts.zip. The second list is the list of byte regions
/// outside of the filesyste, like the hash tree, FEC data, and AVB metadata.
///
/// If [`Error::OldZipNotFound`] is returned, the output will not have been
/// modified.
#[allow(clippy::type_complexity)]
pub fn patch_system_image(
    input: &(dyn ReadSeekReopen + Sync),
    output: &(dyn WriteSeekReopen + Sync),
    certificate: &Certificate,
    key: &RsaSigningKey,
    cancel_signal: &AtomicBool,
) -> Result<(Vec<Range<u64>>, Vec<Range<u64>>)> {
    // This must be a multiple of normal filesystem block sizes (eg. 4 KiB).
    // This ensures that the block containing otacerts.zip's data won't cross
    // chunk boundaries.
    const CHUNK_SIZE: u64 = 2 * 1024 * 1024;

    let parent_span = Span::current();

    let (mut header, footer, image_size) = avb::load_image(input.reopen_boxed()?)?;
    let Some(mut footer) = footer else {
        return Err(Error::NoFooter);
    };
    let AppendedDescriptorMut::HashTree(descriptor) = header.appended_descriptor_mut()? else {
        return Err(Error::NoHashTreeDescriptor);
    };

    let num_chunks = footer.original_image_size.div_ceil(CHUNK_SIZE);
    trace!("Parallel heuristics search for otacerts.zip with {num_chunks} chunks");

    let modified_ranges = (0..num_chunks)
        .into_par_iter()
        .map(|chunk| -> Result<Vec<Range<u64>>> {
            stream::check_cancel(cancel_signal)?;

            let offset = chunk * CHUNK_SIZE;
            let size = CHUNK_SIZE.min(footer.original_image_size - offset);
            let mut buf = vec![0u8; size as usize];

            let mut reader = input.reopen_boxed()?;
            reader.seek(SeekFrom::Start(offset))?;
            reader.read_exact(&mut buf)?;

            let mut writer = output.reopen_boxed()?;
            let mut ranges = Vec::<Range<u64>>::new();

            for eocd_offset_rel in memmem::find_iter(&buf, ota::ZIP_EOCD_MAGIC) {
                let _span = debug_span!(parent: &parent_span, "otacerts", offset, eocd_offset_rel)
                    .entered();

                let Some(bounds_rel) = find_zip_bounds(&buf, eocd_offset_rel) else {
                    continue;
                };

                let zip_size = bounds_rel.end - bounds_rel.start;
                let new_zip = otacert::create_zip_with_size(certificate, zip_size)?;

                let bounds = offset + bounds_rel.start as u64..offset + bounds_rel.end as u64;

                stream::check_cancel(cancel_signal)?;

                writer.seek(SeekFrom::Start(bounds.start))?;
                writer.write_all(&new_zip)?;

                ranges.push(bounds);
            }

            Ok(ranges)
        })
        .try_reduce(Vec::new, |mut result, item| {
            result.extend(item);
            Ok(result)
        })?;

    if modified_ranges.is_empty() {
        return Err(Error::OldZipNotFound);
    }

    let update_ranges = if descriptor.hash_algorithm == "sha1" {
        // Promote to a secure algorithm. SHA1 is allowed for verification only.
        // The entire hash tree and FEC data will need to be recomputed.
        let new_algorithm = "sha256".to_owned();

        debug!(
            "Changing insecure hash algorithm {} to {new_algorithm}",
            descriptor.hash_algorithm,
        );

        descriptor.hash_algorithm = new_algorithm;
        None
    } else {
        // Only need to update the hash tree and FEC data corresponding to the
        // modified regions.
        Some(modified_ranges.as_slice())
    };

    descriptor.update(input, output, update_ranges, cancel_signal)?;

    if !header.public_key.is_empty() {
        debug!("Signing system image");
        header.set_algo_for_key(key)?;
        header.sign(key)?;
    }

    let writer = output.reopen_boxed()?;
    avb::write_appended_image(writer, &header, &mut footer, Some(image_size))?;

    let AppendedDescriptorMut::HashTree(descriptor) = header.appended_descriptor_mut()? else {
        return Err(Error::NoHashTreeDescriptor);
    };

    // The hash tree, FEC data, and AVB regions will have been modified.
    let hash_tree_end = descriptor
        .tree_offset
        .checked_add(descriptor.tree_size)
        .ok_or_else(|| Error::IntOverflow("hash_tree_end"))?;
    let fec_data_end = descriptor
        .fec_offset
        .checked_add(descriptor.fec_size)
        .ok_or_else(|| Error::IntOverflow("fec_data_end"))?;
    let header_end = footer
        .vbmeta_offset
        .checked_add(footer.vbmeta_size)
        .ok_or_else(|| Error::IntOverflow("avb_end"))?;
    let footer_start = image_size - Footer::SIZE as u64;

    let other_ranges = util::merge_overlapping(&[
        descriptor.tree_offset..hash_tree_end,
        descriptor.fec_offset..fec_data_end,
        footer.vbmeta_offset..header_end,
        footer_start..image_size,
    ]);

    Ok((modified_ranges, other_ranges))
}
