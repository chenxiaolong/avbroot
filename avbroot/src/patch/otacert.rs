// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{borrow::Cow, cmp::Ordering, io::Cursor, path::Path};

use bitflags::bitflags;
use der::{Decode, Encode, Sequence, ValueOrd, asn1::BitString};
use rawzip::{CompressionMethod, ZipArchiveWriter};
use thiserror::Error;
use tracing::trace;
use x509_cert::{
    AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo, Version,
    certificate::Rfc5280,
    ext::Extensions,
    name::{Name, RdnSequence},
    serial_number::SerialNumber,
    time::Validity,
};

use crate::{
    crypto,
    format::{ota, zip},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("New otacerts.zip is too small to pad to {0} bytes")]
    ZipTooSmall(usize),
    #[error("New otacerts.zip is too large to fit in {0} bytes")]
    ZipTooLarge(usize),
    #[error("Failed to write otacerts zip")]
    ZipWrite(#[source] rawzip::Error),
    #[error("Failed to deserialize cert from DER")]
    DerRead(#[source] der::Error),
    #[error("Failed to serialize cert to DER")]
    DerWrite(#[source] der::Error),
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

/// [`x509_cert::certificate::TbsCertificateInner`] with public fields.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
struct NonCompliantTbsCertificate {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,

    serial_number: SerialNumber<Rfc5280>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity<Rfc5280>,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitString>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitString>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Extensions>,
}

/// [`x509_cert::certificate::CertificateInner`] with public fields.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
struct NonCompliantCertificate {
    tbs_certificate: NonCompliantTbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature: BitString,
}

/// Create an `otacerts.zip` file containing the specified certificate.
pub fn create_zip(cert: &Certificate, flags: OtaCertBuildFlags) -> Result<Vec<u8>> {
    let raw_writer = Cursor::new(Vec::new());
    let mut writer = ZipArchiveWriter::new(raw_writer);

    let compression_method = if flags.contains(OtaCertBuildFlags::COMPRESS_DEFLATE) {
        CompressionMethod::DEFLATE
    } else {
        CompressionMethod::STORE
    };

    let name = "ota.x509.pem";
    let (entry_writer, data_config) = writer
        .new_file(name)
        .compression_method(compression_method)
        .start()
        .map_err(Error::ZipWrite)?;
    let compressed_writer =
        zip::compressed_writer(entry_writer, compression_method).map_err(Error::ZipWrite)?;
    let mut data_writer = data_config.wrap(compressed_writer);

    let cert = if flags.is_empty() {
        Cow::Borrowed(cert)
    } else {
        // x509-cert 0.3.0 no longer allows access to all these fields, so we
        // have to convert to our own type for modification.
        let cert_tbs = cert.tbs_certificate();
        let mut modified = NonCompliantCertificate {
            tbs_certificate: NonCompliantTbsCertificate {
                version: cert_tbs.version(),
                serial_number: cert_tbs.serial_number().clone(),
                signature: cert_tbs.signature().clone(),
                issuer: cert_tbs.issuer().clone(),
                validity: *cert_tbs.validity(),
                subject: cert_tbs.subject().clone(),
                subject_public_key_info: cert_tbs.subject_public_key_info().clone(),
                issuer_unique_id: cert_tbs.issuer_unique_id().clone(),
                subject_unique_id: cert_tbs.subject_unique_id().clone(),
                extensions: cert_tbs.extensions().cloned(),
            },
            signature_algorithm: cert.signature_algorithm().clone(),
            signature: cert.signature().clone(),
        };

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
            modified.tbs_certificate.issuer =
                Name::hazmat_from_rdn_sequence(RdnSequence::default());
            modified.tbs_certificate.issuer_unique_id = None;
        }
        if flags.contains(OtaCertBuildFlags::REMOVE_SUBJECT) {
            modified.tbs_certificate.subject =
                Name::hazmat_from_rdn_sequence(RdnSequence::default());
            modified.tbs_certificate.subject_unique_id = None;
        }

        let modified_der = modified.to_der().map_err(Error::DerWrite)?;
        let modified_cert = Certificate::from_der(&modified_der).unwrap();

        Cow::Owned(modified_cert)
    };

    crypto::write_pem_cert(Path::new(name), &mut data_writer, &cert).map_err(Error::CertWrite)?;

    data_writer
        .finish()
        .and_then(|(w, d)| w.finish()?.finish(d))
        .map_err(Error::ZipWrite)?;

    let mut raw_writer = writer.finish().map_err(Error::ZipWrite)?;

    zip::make_non_streaming(&mut raw_writer).map_err(Error::ZipWrite)?;

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
