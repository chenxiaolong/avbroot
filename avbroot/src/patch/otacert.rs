// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{borrow::Cow, cmp::Ordering, io::Cursor, path::Path};

use bitflags::bitflags;
use thiserror::Error;
use tracing::trace;
use x509_cert::{Certificate, der::asn1::BitString};
use zip::{CompressionMethod, DateTime, ZipWriter, result::ZipError, write::SimpleFileOptions};

use crate::{crypto, format::ota};

#[derive(Debug, Error)]
pub enum Error {
    #[error("New otacerts.zip is too small to pad to {0} bytes")]
    ZipTooSmall(usize),
    #[error("New otacerts.zip is too large to fit in {0} bytes")]
    ZipTooLarge(usize),
    #[error("Failed to write otacerts zip")]
    ZipWrite(#[source] ZipError),
    #[error("Failed to write certificate to otacerts zip")]
    CertWrite(#[source] crypto::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Pad a non-zip64 zip file to the specified size by adding null bytes to the
/// archive comment field.
pub fn pad_zip(data: &mut Vec<u8>, size: usize) -> Result<()> {
    match size.cmp(&data.len()) {
        Ordering::Equal => Ok(()),
        Ordering::Less => Err(Error::ZipTooLarge(size)),
        Ordering::Greater => {
            let padding = size - data.len();

            if data.len() < 22
                || &data[data.len() - 22..][..4] != ota::ZIP_EOCD_MAGIC
                || padding > usize::from(u16::MAX)
            {
                return Err(Error::ZipTooSmall(size));
            }

            // Rewrite the comment size and pad with null bytes.
            data.pop();
            data.pop();
            data.extend((padding as u16).to_le_bytes());
            data.resize(size, 0);

            Ok(())
        }
    }
}

bitflags! {
    /// Android uses X.509 as nothing more than a file format to transport RSA
    /// public keys. This is true for both the framework's RecoverySystem and
    /// recovery's otautil/verifier.cpp. The only fields that must exist are
    /// the public key and the signature algorithm. The rest can be removed with
    /// no side effects whatsoever.
    #[derive(Debug, Clone, Copy)]
    pub struct OtaCertBuildFlags: u8 {
        const COMPRESS_DEFLATE = 1 << 0;
        const REMOVE_SIGNATURE = 1 << 1;
        const REMOVE_EXTENSIONS = 1 << 2;
        const REMOVE_ISSUER = 1 << 3;
        const REMOVE_SUBJECT = 1 << 4;
    }
}

/// Create an `otacerts.zip` file containing the specified certificate.
pub fn create_zip(cert: &Certificate, flags: OtaCertBuildFlags) -> Result<Vec<u8>> {
    let raw_writer = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(raw_writer);

    let compression_method = if flags.contains(OtaCertBuildFlags::COMPRESS_DEFLATE) {
        CompressionMethod::Deflated
    } else {
        CompressionMethod::Stored
    };

    let options = SimpleFileOptions::default()
        .last_modified_time(DateTime::default())
        .compression_method(compression_method);
    let name = "ota.x509.pem";
    writer.start_file(name, options).map_err(Error::ZipWrite)?;

    let cert = if flags.is_empty() {
        Cow::Borrowed(cert)
    } else {
        let mut modified = cert.clone();

        if flags.contains(OtaCertBuildFlags::REMOVE_SIGNATURE) {
            // An empty ASN.1 bit string is always valid.
            modified.signature =
                BitString::from_bytes(&[]).expect("Empty ASN.1 bit string was invalid");
        }
        if flags.contains(OtaCertBuildFlags::REMOVE_EXTENSIONS)
            && let Some(extensions) = &mut modified.tbs_certificate.extensions
        {
            extensions.clear();
        }
        if flags.contains(OtaCertBuildFlags::REMOVE_ISSUER) {
            modified.tbs_certificate.issuer.0.clear();
            modified.tbs_certificate.issuer_unique_id = None;
        }
        if flags.contains(OtaCertBuildFlags::REMOVE_SUBJECT) {
            modified.tbs_certificate.subject.0.clear();
            modified.tbs_certificate.subject_unique_id = None;
        }

        Cow::Owned(modified)
    };

    crypto::write_pem_cert(Path::new(name), &mut writer, &cert).map_err(Error::CertWrite)?;

    let raw_writer = writer.finish().map_err(Error::ZipWrite)?;

    Ok(raw_writer.into_inner())
}

/// Create an `otacerts.zip` file padded to the specified size.
///
/// This will incrementally remove unneeded components from the certificate to
/// meet the size limit if needed.
pub fn create_zip_with_size(cert: &Certificate, size: usize) -> Result<Vec<u8>> {
    let mut flags = OtaCertBuildFlags::empty();

    for additional_flag in [
        OtaCertBuildFlags::empty(),
        OtaCertBuildFlags::COMPRESS_DEFLATE,
        OtaCertBuildFlags::REMOVE_SIGNATURE,
        OtaCertBuildFlags::REMOVE_EXTENSIONS,
        OtaCertBuildFlags::REMOVE_ISSUER,
        OtaCertBuildFlags::REMOVE_SUBJECT,
    ] {
        flags |= additional_flag;

        trace!("Attempting to create {size} byte otacerts.zip: {flags:?}");

        let mut data = create_zip(cert, flags)?;
        if data.len() <= size {
            trace!("Padding {} byte otacerts.zip to {size}", data.len());

            pad_zip(&mut data, size)?;
            return Ok(data);
        }
    }

    Err(Error::ZipTooLarge(size))
}
