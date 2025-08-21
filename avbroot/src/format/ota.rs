// SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::BTreeMap,
    fmt::{self, Write as _},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    iter,
    path::Path,
    str::FromStr,
    sync::atomic::AtomicBool,
};

use clap::ValueEnum;
use cms::signed_data::SignedData;
use const_oid::{ObjectIdentifier, db::rfc5912};
use memchr::memmem;
use prost::Message;
use rawzip::{
    CompressionMethod, RECOMMENDED_BUFFER_SIZE, ZipArchive, ZipArchiveWriter, ZipDataWriter,
};
use ring::digest::{Algorithm, Context};
use thiserror::Error;
use x509_cert::{Certificate, der::Encode};

use crate::{
    crypto::{self, RsaPublicKeyExt, RsaSigningKey, SignatureAlgorithm},
    format::{
        payload::{self, PayloadHeader},
        zip::{self, ZipEntriesSafeExt, ZipFileHeaderRecordExt},
    },
    protobuf::build::tools::releasetools::{OtaMetadata, ota_metadata::OtaType},
    stream::{self, FromReader, HashingReader, HashingWriter, ReadFixedSizeExt},
    util,
};

pub const PATH_METADATA: &str = "META-INF/com/android/metadata";
pub const PATH_METADATA_PB: &str = "META-INF/com/android/metadata.pb";
pub const PATH_OTACERT: &str = "META-INF/com/android/otacert";
pub const PATH_PAYLOAD: &str = "payload.bin";
pub const PATH_PROPERTIES: &str = "payload_properties.txt";

const NAME_PAYLOAD_METADATA: &str = "payload_metadata.bin";

pub const PF_NAME: &str = "ota-property-files";
pub const PF_STREAMING_NAME: &str = "ota-streaming-property-files";

pub const ZIP_EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";

const COMMENT_MESSAGE: &[u8] = b"signed by avbroot\0";

const LEGACY_SEP: &str = "|";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cannot find OTA signature footer magic")]
    OtaMagicNotFound,
    #[error("Cannot find EOCD magic")]
    EocdMagicNotFound,
    #[error("EOCD magic found in archive comment at offset {0}")]
    EocdMagicInComment(usize),
    #[error("Zip is too small to contain EOCD")]
    ZipTooSmall,
    #[error("Zip archive comment is not empty: {0}")]
    ZipNonEmptyComment(u16),
    #[error("Signature offset exceeds archive comment size")]
    SignatureOffsetTooLarge,
    #[error("Expected exactly one CMS embedded certificate, but found {0}")]
    NotOneCmsCertificate(usize),
    #[error("Expected exactly one CMS SignerInfo, but found {0}")]
    NotOneCmsSignerInfo(usize),
    #[error("Unsupported digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(ObjectIdentifier),
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(ObjectIdentifier),
    #[error("Invalid legacy metadata line: {0:?}")]
    InvalidLegacyMetadataLine(String),
    #[error("Unsupported legacy metadata field: {key:?} = {value:?}")]
    UnsupportedLegacyMetadataField { key: String, value: String },
    #[error("Mismatched {key:?} entry offsets: zip only: {zip_only:?}, prop only: {prop_only:?}")]
    MismatchedPropertyFiles {
        key: String,
        zip_only: String,
        prop_only: String,
    },
    #[error("Property files {value:?} exceed {reserved} byte reserved space")]
    InsufficientReservedSpace { value: String, reserved: usize },
    #[error("Invalid property file entry: {0:?}")]
    InvalidPropertyFileEntry(String),
    #[error("Missing entry in OTA zip: {0:?}")]
    MissingZipEntry(&'static str),
    #[error("Failed to decode OTA metadata protobuf message")]
    MetadataDecode(#[source] prost::DecodeError),
    #[error("Failed to open zip file")]
    ZipOpen(#[source] rawzip::Error),
    #[error("Failed to list zip entries")]
    ZipEntryList(#[source] rawzip::Error),
    #[error("Missing zip entry: {0:?}")]
    ZipEntryMissing(Cow<'static, str>),
    #[error("Failed to open zip entry: {0:?}")]
    ZipEntryOpen(Cow<'static, str>, #[source] rawzip::Error),
    #[error("Failed to start new zip entry: {0:?}")]
    ZipEntryStart(Cow<'static, str>, #[source] rawzip::Error),
    #[error("Failed to read zip entry: {0:?}")]
    ZipEntryRead(Cow<'static, str>, #[source] io::Error),
    #[error("Failed to write zip entry: {0:?}")]
    ZipEntryWrite(Cow<'static, str>, #[source] io::Error),
    #[error("Failed to finalize zip entry: {0:?}")]
    ZipEntryFinish(Cow<'static, str>, #[source] rawzip::Error),
    #[error("Failed to load OTA certificate")]
    OtaCertLoad(#[source] crypto::Error),
    #[error("Failed to extract public key from OTA certificate")]
    OtaCertExtractPubKey(#[source] crypto::Error),
    #[error("Failed to load payload binary")]
    PayloadLoad(#[source] payload::Error),
    #[error("Failed to load CMS signature")]
    CmsLoad(#[source] crypto::Error),
    #[error("Failed to save CMS signature")]
    CmsSave(#[source] x509_cert::der::Error),
    #[error("Failed to generate CMS signature")]
    CmsSign(#[source] crypto::Error),
    #[error("Failed to verify CMS signature")]
    CmsVerify(#[source] crypto::Error),
    #[error("Failed to read OTA data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write OTA data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
    #[error("Failed to convert to non-streaming zip")]
    MakeNonStreaming(#[source] rawzip::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn parse_protobuf_metadata(data: &[u8]) -> Result<OtaMetadata> {
    OtaMetadata::decode(data).map_err(Error::MetadataDecode)
}

/// Synthesize protobuf structure from legacy plain-text metadata.
pub fn parse_legacy_metadata(data: &str) -> Result<OtaMetadata> {
    let mut metadata = OtaMetadata::default();

    for line in data.split('\n') {
        if line.is_empty() {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::InvalidLegacyMetadataLine(line.to_owned()))?;
        let unsupported = || Error::UnsupportedLegacyMetadataField {
            key: key.to_owned(),
            value: value.to_owned(),
        };
        // Booleans are represented by the presence or absence of `<key>=yes`.
        let parse_yes = || match value {
            "yes" => Ok(true),
            _ => Err(unsupported()),
        };
        let parse_list = || {
            value
                .split(LEGACY_SEP)
                .map(|s| s.to_owned())
                .collect::<Vec<_>>()
        };

        match key {
            "ota-type" => {
                match OtaType::from_str_name(value).ok_or_else(unsupported)? {
                    t @ (OtaType::Ab | OtaType::Block) => metadata.set_type(t),
                    // Not allowed by AOSP in the legacy format.
                    _ => return Err(unsupported()),
                }
            }
            "ota-wipe" => metadata.wipe = parse_yes()?,
            "ota-retrofit-dynamic-partitions" => {
                metadata.retrofit_dynamic_partitions = parse_yes()?;
            }
            "ota-downgrade" => metadata.downgrade = parse_yes()?,
            "ota-required-cache" => {
                metadata.required_cache = value.parse().map_err(|_| unsupported())?;
            }
            "post-build" => {
                let p = metadata.postcondition.get_or_insert_with(Default::default);
                p.build = parse_list();
            }
            "post-build-incremental" => {
                let p = metadata.postcondition.get_or_insert_with(Default::default);
                value.clone_into(&mut p.build_incremental);
            }
            "post-sdk-level" => {
                let p = metadata.postcondition.get_or_insert_with(Default::default);
                value.clone_into(&mut p.sdk_level);
            }
            "post-security-patch-level" => {
                let p = metadata.postcondition.get_or_insert_with(Default::default);
                value.clone_into(&mut p.security_patch_level);
            }
            "post-timestamp" => {
                let p = metadata.postcondition.get_or_insert_with(Default::default);
                p.timestamp = value.parse().map_err(|_| unsupported())?;
            }
            "pre-device" => {
                let p = metadata.precondition.get_or_insert_with(Default::default);
                p.device = parse_list();
            }
            "pre-build" => {
                let p = metadata.precondition.get_or_insert_with(Default::default);
                p.build = parse_list();
            }
            "pre-build-incremental" => {
                let p = metadata.precondition.get_or_insert_with(Default::default);
                value.clone_into(&mut p.build_incremental);
            }
            "spl-downgrade" => metadata.spl_downgrade = parse_yes()?,
            k if k.ends_with("-property-files") => {
                metadata
                    .property_files
                    .insert(key.to_owned(), value.to_owned());
            }
            _ => {
                // Ignore. Some OEMs insert values that aren't defined in AOSP.
            }
        }
    }

    Ok(metadata)
}

/// Generate the legacy plain-text and modern protobuf serializations of the
/// given metadata instance.
fn serialize_metadata(metadata: &OtaMetadata) -> (String, Vec<u8>) {
    use std::fmt::Write;

    let mut pairs = BTreeMap::<String, String>::new();

    // Other types are not allowed by AOSP in the legacy format.
    if let t @ (OtaType::Ab | OtaType::Block) = metadata.r#type() {
        pairs.insert("ota-type".to_owned(), t.as_str_name().to_owned());
    }
    if metadata.wipe {
        pairs.insert("ota-wipe".to_owned(), "yes".to_owned());
    }
    if metadata.retrofit_dynamic_partitions {
        pairs.insert(
            "ota-retrofit-dynamic-partitions".to_owned(),
            "yes".to_owned(),
        );
    }
    if metadata.downgrade {
        pairs.insert("ota-downgrade".to_owned(), "yes".to_owned());
    }

    pairs.insert(
        "ota-required-cache".to_owned(),
        metadata.required_cache.to_string(),
    );

    if let Some(p) = &metadata.postcondition {
        pairs.insert("post-build".to_owned(), p.build.join(LEGACY_SEP));
        pairs.insert(
            "post-build-incremental".to_owned(),
            p.build_incremental.clone(),
        );
        pairs.insert("post-sdk-level".to_owned(), p.sdk_level.clone());
        pairs.insert(
            "post-security-patch-level".to_owned(),
            p.security_patch_level.clone(),
        );
        pairs.insert("post-timestamp".to_owned(), p.timestamp.to_string());
    }

    if let Some(p) = &metadata.precondition {
        pairs.insert("pre-device".to_owned(), p.device.join(LEGACY_SEP));
        if !p.build.is_empty() {
            pairs.insert("pre-build".to_owned(), p.build.join(LEGACY_SEP));
            pairs.insert(
                "pre-build-incremental".to_owned(),
                p.build_incremental.clone(),
            );
        }
    }

    if metadata.spl_downgrade {
        pairs.insert("spl-downgrade".to_owned(), "yes".to_owned());
    }

    pairs.extend(metadata.property_files.clone());

    let legacy_metadata = pairs.into_iter().fold(String::new(), |mut output, (k, v)| {
        let _ = writeln!(output, "{k}={v}");
        output
    });
    let modern_metadata = metadata.encode_to_vec();

    (legacy_metadata, modern_metadata)
}

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropEntry {
    name: String,
    pub offset: u64,
    pub size: u64,
}

impl PropEntry {
    pub fn new(path: &str, offset: u64, size: u64) -> Self {
        Self {
            name: property_file_name(path).to_owned(),
            offset,
            size,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<&ZipEntry> for PropEntry {
    fn from(entry: &ZipEntry) -> Self {
        Self::new(&entry.path, entry.offset, entry.size)
    }
}

impl fmt::Display for PropEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.name, self.offset, self.size)
    }
}

impl FromStr for PropEntry {
    type Err = Error;

    fn from_str(entry: &str) -> Result<Self> {
        let mut pieces = entry.split(':');

        let name = pieces
            .next()
            .map(|p| p.to_owned())
            .ok_or_else(|| Error::InvalidPropertyFileEntry(entry.to_owned()))?;
        let offset = pieces
            .next()
            .and_then(|p| p.parse::<u64>().ok())
            .ok_or_else(|| Error::InvalidPropertyFileEntry(entry.to_owned()))?;
        let size = pieces
            .next()
            .and_then(|p| p.parse::<u64>().ok())
            .ok_or_else(|| Error::InvalidPropertyFileEntry(entry.to_owned()))?;

        if pieces.next().is_some() {
            return Err(Error::InvalidPropertyFileEntry(entry.to_owned()));
        }

        Ok(Self { name, offset, size })
    }
}

/// Parse OTA property files string.
pub fn parse_property_files(data: &str) -> Result<Vec<PropEntry>> {
    let mut result = vec![];

    for entry in data.trim_end().split(',') {
        result.push(entry.parse()?);
    }

    Ok(result)
}

/// Get the filename for use in property files entries.
fn property_file_name(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |p| p.1)
}

/// Compute the property files entries listing the offsets and sizes to every
/// zip entry.
fn compute_property_files(
    pf_name: &str,
    entries: &[PropEntry],
    max_length: Option<usize>,
    want_pb: bool,
) -> Result<String> {
    // AOSP's ota_utils.py reserves 15 bytes for the `<offset>:<size>`
    // placeholder. Since the size of `metadata.pb` is almost always 4 digits,
    // this prevents the offset from exceeding 10 digits. In the wild, there are
    // OTA files larger than 10 GB. With ota_utils.py, this limit is never
    // reached because it puts the OTA metadata files at the beginning of the
    // zip. However, avbroot needs to put them at the end due to streaming
    // writes, so we reserve an additional byte to allow offsets <100 GB.
    const RESERVATION_SIZE: usize = 16;

    let mut buf = String::new();

    let mut append = |path: &'static str| -> Result<()> {
        let name = property_file_name(path);
        let entry = entries
            .iter()
            .find(|e| e.name == name)
            .ok_or(Error::MissingZipEntry(path))?;

        let _ = write!(&mut buf, "{entry},");

        Ok(())
    };

    if pf_name == PF_NAME {
        append(NAME_PAYLOAD_METADATA)?;
    }

    for path in [PATH_PAYLOAD, PATH_PROPERTIES] {
        append(path)?;
    }

    for path in [
        "apex_info.pb",
        "care_map.pb",
        "care_map.txt",
        "compatibility.zip",
    ] {
        // These are optional.
        let _ = append(path);
    }

    if max_length.is_none() {
        buf.push_str(property_file_name(PATH_METADATA));
        buf.push(':');
        buf.extend(iter::repeat_n(' ', RESERVATION_SIZE));
        buf.push(',');

        if want_pb {
            buf.push_str(property_file_name(PATH_METADATA_PB));
            buf.push(':');
            buf.extend(iter::repeat_n(' ', RESERVATION_SIZE));
            buf.push(',');
        }
    } else {
        append(PATH_METADATA)?;
        if want_pb {
            append(PATH_METADATA_PB)?;
        }
    }

    // Strip final trailing comma.
    buf.pop();

    if let Some(l) = max_length {
        if buf.len() > l {
            return Err(Error::InsufficientReservedSpace {
                value: buf,
                reserved: l,
            });
        }

        let remain = l - buf.len();
        buf.extend(iter::repeat_n(' ', remain));
    }

    Ok(buf)
}

// Add fake payload_metadata.bin entry, covering the header + header signature
// regions of the payload.
fn add_payload_metadata_entry(
    entries: &mut Vec<PropEntry>,
    payload_metadata_size: u64,
) -> Result<()> {
    let payload_offset = entries
        .iter()
        .find(|e| e.name == PATH_PAYLOAD)
        .ok_or(Error::MissingZipEntry(PATH_PAYLOAD))?
        .offset;
    entries.push(PropEntry::new(
        NAME_PAYLOAD_METADATA,
        payload_offset,
        payload_metadata_size,
    ));

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ZipMode {
    Streaming,
    Seekable,
}

impl fmt::Display for ZipMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_possible_value().ok_or(fmt::Error)?.get_name())
    }
}

/// Add metadata files to the output OTA zip. `zip_entries` is the list of
/// [`ZipEntry`] already written to `zip_writer`. `next_offset` is the current
/// file offset (where the next zip entry's local header begins).
/// `metadata` is the OTA metadata protobuf message from the original OTA.
/// `payload_metadata_size` is the size of the new payload's metadata and
/// metadata signature regions.
///
/// The zip file's backing file position MUST BE set to where the central
/// directory would start.
pub fn add_metadata(
    zip_entries: &[ZipEntry],
    zip_writer: &mut ZipArchiveWriter<impl Write>,
    next_offset: u64,
    metadata: &OtaMetadata,
    payload_metadata_size: u64,
) -> Result<OtaMetadata> {
    fn write_entry(
        archive: &mut ZipArchiveWriter<impl Write>,
        path: &'static str,
        data: &[u8],
    ) -> Result<(u64, u64)> {
        let entry_writer = archive
            .new_file(path)
            .create()
            .map_err(|e| Error::ZipEntryStart(path.into(), e))?;
        let data_offset = entry_writer.stream_offset();
        let mut data_writer = ZipDataWriter::new(entry_writer);

        data_writer
            .write_all(data)
            .map_err(|e| Error::ZipEntryWrite(path.into(), e))?;

        let data_size = data_writer
            .finish()
            .and_then(|(w, d)| w.finish(d))
            .map_err(|e| Error::ZipEntryFinish(path.into(), e))?;

        Ok((data_offset, data_size))
    }

    let mut metadata = metadata.clone();

    let mut prop_entries = zip_entries.iter().map(PropEntry::from).collect();
    add_payload_metadata_entry(&mut prop_entries, payload_metadata_size)?;

    // Compute initial property files with reserved space as placeholders to
    // store the self-referential metadata entries later.
    metadata.property_files.clear();
    for pf in [PF_NAME, PF_STREAMING_NAME] {
        metadata.property_files.insert(
            pf.to_owned(),
            compute_property_files(pf, &prop_entries, None, true)?,
        );
    }

    // Add the placeholders to a temporary zip to compute final property files.
    let (temp_legacy_offset, temp_modern_offset) = {
        let (legacy_raw, modern_raw) = serialize_metadata(&metadata);
        let raw_writer = Cursor::new(Vec::new());
        // Note that we don't need to worry about the offsets changing based on
        // the zip writing mode (streaming vs. seekable). Currently, we always
        // include data descriptors and do post-processing to copy the fields
        // into the local header without shifting the data.
        let mut writer = ZipArchiveWriter::new(raw_writer);

        let (legacy_offset, legacy_size) =
            write_entry(&mut writer, PATH_METADATA, legacy_raw.as_bytes())?;
        let (modern_offset, modern_size) = write_entry(&mut writer, PATH_METADATA_PB, &modern_raw)?;

        prop_entries.push(PropEntry::new(
            PATH_METADATA,
            next_offset + legacy_offset,
            legacy_size,
        ));
        prop_entries.push(PropEntry::new(
            PATH_METADATA_PB,
            next_offset + modern_offset,
            modern_size,
        ));

        (next_offset + legacy_offset, next_offset + modern_offset)
    };

    // Compute the final property files using the offsets of the fake entries.
    for (key, value) in &mut metadata.property_files {
        *value = compute_property_files(key, &prop_entries, Some(value.len()), true)?;
    }

    // Add the final metadata files to the real zip.
    {
        let (legacy_raw, modern_raw) = serialize_metadata(&metadata);

        let (legacy_offset, _) = write_entry(zip_writer, PATH_METADATA, legacy_raw.as_bytes())?;
        let (modern_offset, _) = write_entry(zip_writer, PATH_METADATA_PB, &modern_raw)?;

        assert_eq!(legacy_offset, temp_legacy_offset);
        assert_eq!(modern_offset, temp_modern_offset);
    }

    Ok(metadata)
}

/// Verify that the zip entry offsets and sizes match the OTA metadata.
pub fn verify_metadata(
    reader: impl Read + Seek,
    metadata: &OtaMetadata,
    payload_metadata_size: u64,
) -> Result<()> {
    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let archive = ZipArchive::from_seekable(reader, &mut buffer).map_err(Error::ZipOpen)?;
    let mut zip_entries = vec![];

    let mut entries = archive.entries_safe(&mut buffer);

    while let Some((cd_entry, entry)) = entries.next_entry().map_err(Error::ZipEntryList)? {
        if cd_entry.compression_method() != CompressionMethod::Store {
            continue;
        }

        let Ok(path) = cd_entry.file_path_utf8() else {
            continue;
        };

        let range = entry.compressed_data_range();

        zip_entries.push(PropEntry::new(path, range.0, range.1 - range.0));
    }

    add_payload_metadata_entry(&mut zip_entries, payload_metadata_size)?;

    zip_entries.sort_by(|a, b| a.name.cmp(&b.name));

    for (key, value) in &metadata.property_files {
        let mut prop_entries = parse_property_files(value)?;
        prop_entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Check that this is a subset of the actual entries.
        let mut zip_iter = zip_entries.iter().peekable();
        let mut prop_iter = prop_entries.iter().peekable();
        let mut zip_only = vec![];
        let mut prop_only = vec![];

        loop {
            match (zip_iter.peek(), prop_iter.peek()) {
                (Some(&zip), Some(&prop)) => match zip.name.cmp(&prop.name) {
                    Ordering::Less => {
                        // Exists in zip, but not in property files.
                        zip_iter.next();
                    }
                    Ordering::Equal => {
                        // If the zip had multiple files with the same filename,
                        // but in different directories, this will fail.
                        if zip != prop {
                            zip_only.push(zip);
                            prop_only.push(prop);
                        }
                        zip_iter.next();
                        prop_iter.next();
                    }
                    Ordering::Greater => {
                        // Exists in property files, but not in zip.
                        prop_only.push(prop);
                        prop_iter.next();
                    }
                },
                (Some(_), None) => {
                    // Exists in zip, but not in property files.
                    zip_iter.next();
                }
                (None, Some(prop)) => {
                    // Exists in property files, but not in zip.
                    prop_only.push(prop);
                    prop_iter.next();
                }
                (None, None) => break,
            }
        }

        if !zip_only.is_empty() || !prop_only.is_empty() {
            return Err(Error::MismatchedPropertyFiles {
                key: key.clone(),
                zip_only: util::join(zip_only.into_iter().map(|e| e.to_string()), ","),
                prop_only: util::join(prop_only.into_iter().map(|e| e.to_string()), ","),
            });
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct RawOtaSignature {
    /// Decoded CMS structure.
    signed_data: SignedData,
    /// Length of the file (from the beginning) that's covered by the signature.
    hashed_size: u64,
}

impl RawOtaSignature {
    pub fn embedded_cert(&self) -> Result<&Certificate> {
        let mut iter = crypto::iter_cms_certs(&self.signed_data);

        let Some(cert) = iter.next() else {
            return Err(Error::NotOneCmsCertificate(0));
        };

        let None = iter.next() else {
            return Err(Error::NotOneCmsCertificate(2 + iter.count()));
        };

        Ok(cert)
    }
}

#[derive(Clone, Debug)]
pub struct OtaSignature {
    pub cert: Certificate,
    pub digest_algo: &'static Algorithm,
    pub sig_algo: SignatureAlgorithm,
    pub sig: Vec<u8>,
    pub data_size: u64,
}

impl TryFrom<RawOtaSignature> for OtaSignature {
    type Error = Error;

    fn try_from(raw_ota_sig: RawOtaSignature) -> Result<Self> {
        let cert = raw_ota_sig.embedded_cert()?;

        // Make sure this is a signature scheme we can handle. There's currently
        // no Rust library to verify arbitrary CMS signatures for large files
        // without fully reading them into memory.
        let signers_len = raw_ota_sig.signed_data.signer_infos.0.len();
        if signers_len != 1 {
            return Err(Error::NotOneCmsSignerInfo(signers_len));
        }

        let signer = raw_ota_sig.signed_data.signer_infos.0.get(0).unwrap();
        if signer.digest_alg.oid != rfc5912::ID_SHA_256
            && signer.digest_alg.oid != rfc5912::ID_SHA_1
        {
            return Err(Error::UnsupportedDigestAlgorithm(signer.digest_alg.oid));
        } else if signer.signature_algorithm.oid != rfc5912::RSA_ENCRYPTION
            && signer.signature_algorithm.oid != rfc5912::SHA_256_WITH_RSA_ENCRYPTION
        {
            return Err(Error::UnsupportedSignatureAlgorithm(
                signer.signature_algorithm.oid,
            ));
        }

        // We support SHA1 for verification only.
        let (digest_algo, sig_algo) = if signer.digest_alg.oid == rfc5912::ID_SHA_256 {
            (&ring::digest::SHA256, SignatureAlgorithm::Sha256WithRsa)
        } else {
            (
                &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                SignatureAlgorithm::Sha1WithRsa,
            )
        };

        Ok(Self {
            cert: cert.clone(),
            digest_algo,
            sig_algo,
            sig: signer.signature.as_bytes().to_vec(),
            data_size: raw_ota_sig.hashed_size,
        })
    }
}

impl OtaSignature {
    /// Verify an OTA zip against its embedded certificate. This function makes
    /// no assertion about whether the certificate is actually trusted.
    ///
    /// CMS signed attributes are intentionally not supported because AOSP
    /// recovery does not support them either. It expects the CMS [`SignedData`]
    /// structure to be used for nothing more than a raw signature transport
    /// mechanism.
    pub fn verify_ota(
        &self,
        mut reader: impl Read + Seek,
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let public_key = crypto::get_public_key(&self.cert).map_err(Error::OtaCertExtractPubKey)?;

        // Manually hash the parts of the file covered by the signature.
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| Error::DataRead("raw_data", e))?;

        let mut hashing_reader = HashingReader::new(reader, Context::new(self.digest_algo));

        stream::copy_n(
            &mut hashing_reader,
            io::sink(),
            self.data_size,
            cancel_signal,
        )
        .map_err(|e| Error::DataRead("raw_data", e))?;

        let (_, context) = hashing_reader.finish();
        let digest = context.finish();

        // Verify the signature against the public key.
        public_key
            .verify_sig(self.sig_algo, digest.as_ref(), &self.sig)
            .map_err(Error::CmsVerify)?;

        Ok(())
    }
}

/// Parse the CMS signature from the OTA zip comment. This does not perform any
/// parsing of zip data structures.
fn parse_raw_ota_sig(mut reader: impl Read + Seek) -> Result<RawOtaSignature> {
    let file_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| Error::DataRead("file_size", e))?;

    reader
        .seek_relative(-6)
        .map_err(|e| Error::DataRead("footer", e))?;
    let footer = reader
        .read_array_exact::<6>()
        .map_err(|e| Error::DataRead("footer", e))?;

    let abs_eoc_offset = u16::from_le_bytes(footer[0..2].try_into().unwrap());
    let sig_magic = u16::from_le_bytes(footer[2..4].try_into().unwrap());
    let comment_size = u16::from_le_bytes(footer[4..6].try_into().unwrap());

    if sig_magic != 0xffff {
        return Err(Error::OtaMagicNotFound);
    }

    // RecoverySystem.verifyPackage() always assumes a non-zip64 EOCD, so we'll
    // do the same.
    let eocd_size = u64::from(22 + comment_size);
    if file_size < eocd_size {
        return Err(Error::ZipTooSmall);
    } else if u64::from(abs_eoc_offset) > eocd_size {
        return Err(Error::SignatureOffsetTooLarge);
    }

    reader
        .seek(SeekFrom::Start(file_size - eocd_size))
        .map_err(|e| Error::DataRead("eocd", e))?;
    let eocd = reader
        .read_vec_exact(eocd_size as usize)
        .map_err(|e| Error::DataRead("eocd", e))?;

    let mut eocd_magic_iter = memmem::find_iter(&eocd, ZIP_EOCD_MAGIC);
    if eocd_magic_iter.next() != Some(0) {
        return Err(Error::EocdMagicNotFound);
    }
    if let Some(offset) = eocd_magic_iter.next() {
        return Err(Error::EocdMagicInComment(offset));
    }

    let sig_offset = eocd_size as usize - usize::from(abs_eoc_offset);
    let signed_data =
        crypto::parse_cms(&eocd[sig_offset..eocd_size as usize - 6]).map_err(Error::CmsLoad)?;
    // The signature covers everything aside from the archive comment and its
    // length field.
    let hashed_size = file_size - 2 - u64::from(comment_size);

    Ok(RawOtaSignature {
        signed_data,
        hashed_size,
    })
}

/// Parse the signature information from the CMS signature embedded in the OTA
/// zip archive comment.
pub fn parse_ota_sig(reader: impl Read + Seek) -> Result<OtaSignature> {
    parse_raw_ota_sig(reader)?.try_into()
}

/// Get and parse the protobuf-encoded OTA metadata, the PEM-encoded otacert,
/// the payload header, and the payload properties from an OTA zip.
pub fn parse_zip_ota_info(
    reader: impl Read + Seek,
) -> Result<(OtaMetadata, Certificate, PayloadHeader, String)> {
    let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
    let archive = ZipArchive::from_seekable(reader, &mut buffer).map_err(Error::ZipOpen)?;

    let mut metadata_modern = None;
    let mut metadata_legacy = None;
    let mut certificate = None;
    let mut header = None;
    let mut properties = None;

    let mut entries = archive.entries_safe(&mut buffer);

    while let Some((cd_entry, entry)) = entries.next_entry().map_err(Error::ZipEntryList)? {
        let path = cd_entry.file_path_utf8().map_err(Error::ZipEntryList)?;

        if path == PATH_METADATA_PB {
            let mut reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(PATH_METADATA_PB.into(), e))?;
            let mut buf = Vec::new();

            reader
                .read_to_end(&mut buf)
                .map_err(|e| Error::ZipEntryRead(PATH_METADATA_PB.into(), e))?;

            metadata_modern = Some(parse_protobuf_metadata(&buf)?);
        } else if path == PATH_METADATA {
            let mut reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(PATH_METADATA.into(), e))?;
            let mut buf = String::new();

            reader
                .read_to_string(&mut buf)
                .map_err(|e| Error::ZipEntryRead(PATH_METADATA.into(), e))?;

            metadata_legacy = Some(parse_legacy_metadata(&buf)?);
        } else if path == PATH_OTACERT {
            let reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(PATH_OTACERT.into(), e))?;

            certificate = Some(
                crypto::read_pem_cert(Path::new(PATH_OTACERT), reader)
                    .map_err(Error::OtaCertLoad)?,
            );
        } else if path == PATH_PAYLOAD {
            // No CRC validation because we only read the header.
            let reader = zip::compressed_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(PATH_PAYLOAD.into(), e))?;

            header = Some(PayloadHeader::from_reader(reader).map_err(Error::PayloadLoad)?);
        } else if path == PATH_PROPERTIES {
            let mut reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(PATH_PROPERTIES.into(), e))?;
            let mut buf = String::new();

            reader
                .read_to_string(&mut buf)
                .map_err(|e| Error::ZipEntryRead(PATH_PROPERTIES.into(), e))?;

            properties = Some(buf);
        }
    }

    let metadata = metadata_modern
        .or(metadata_legacy)
        .ok_or_else(|| Error::ZipEntryMissing(PATH_METADATA_PB.into()))?;
    let certificate = certificate.ok_or_else(|| Error::ZipEntryMissing(PATH_OTACERT.into()))?;
    let header = header.ok_or_else(|| Error::ZipEntryMissing(PATH_PAYLOAD.into()))?;
    let properties = properties.ok_or_else(|| Error::ZipEntryMissing(PATH_PROPERTIES.into()))?;

    Ok((metadata, certificate, header, properties))
}

/// Ensure that we're using a non-zip64 EOCD and there's no archive comment.
fn validate_eocd(eocd: &[u8]) -> Result<()> {
    if &eocd[..4] != b"PK\x05\x06" {
        return Err(Error::EocdMagicNotFound);
    } else if &eocd[20..22] != b"\0\0" {
        let size = u16::from_le_bytes(eocd[20..22].try_into().unwrap());
        return Err(Error::ZipNonEmptyComment(size));
    }

    Ok(())
}

/// Compute the digital signature for the specified digest, formatted as a zip
/// file archive comment. The returned buffer includes both the 2-byte comment
/// size field and the comment itself. It should be written to the end of the
/// zip file after truncating the original 2-byte comment size field.
fn compute_signature_comment(
    key: &RsaSigningKey,
    cert: &Certificate,
    digest: ring::digest::Digest,
) -> Result<Vec<u8>> {
    let cms_signature =
        crypto::cms_sign_external(key, cert, digest.as_ref()).map_err(Error::CmsSign)?;
    let cms_signature_der = cms_signature.to_der().map_err(Error::CmsSave)?;

    // Includes placeholder for the EOCD comment size field.
    let mut buf = vec![0; 2];

    // NULL-terminated readable message and actual signature.
    buf.extend(COMMENT_MESSAGE);
    buf.extend(&cms_signature_der);

    // 6-byte OTA footer.
    let comment_size = buf.len() - 2 + 6;

    // Absolute value of the offset of the signature from the end of the archive
    // comment.
    buf.extend((cms_signature_der.len() as u16 + 6).to_le_bytes());

    // Magic value.
    buf.extend(b"\xff\xff");

    // Archive comment size (for use by the OTA signature verifier).
    buf.extend(((comment_size) as u16).to_le_bytes());

    if let Some(offset) = memmem::find(&buf[2..], ZIP_EOCD_MAGIC) {
        return Err(Error::EocdMagicInComment(offset));
    }

    // Archive comment size (for the EOCD comment size field).
    buf[..2].copy_from_slice(&((comment_size) as u16).to_le_bytes());

    Ok(buf)
}

/// A writer that produces a signapk-style signed zip file with a whole-file
/// signature stored in the zip archive comment. The data will be left in an
/// unusable state if [`Self::finish()`] is not called.
///
/// This writer works with streaming zip files created with data descriptors.
/// The data is hashed as it is being written.
pub struct StreamingSigningWriter<W> {
    inner: HashingWriter<W>,
    // Android only supports non-zip64 EOCD.
    queue: [u8; 22],
    used: usize,
}

impl<W: Write> StreamingSigningWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner: HashingWriter::new(inner, Context::new(&ring::digest::SHA256)),
            queue: Default::default(),
            used: 0,
        }
    }

    pub fn finish(mut self, key: &RsaSigningKey, cert: &Certificate) -> Result<W> {
        if self.used < self.queue.len() {
            return Err(Error::ZipTooSmall);
        }

        validate_eocd(&self.queue)?;

        // Chop off the archive comment size field and write the remaining data.
        self.inner
            .write_all(&self.queue[..20])
            .map_err(|e| Error::DataWrite("eocd_minus_comment", e))?;

        let (mut raw_writer, context) = self.inner.finish();
        let digest = context.finish();

        let size_and_comment = compute_signature_comment(key, cert, digest)?;
        raw_writer
            .write_all(&size_and_comment)
            .map_err(|e| Error::DataWrite("size_and_comment", e))?;

        Ok(raw_writer)
    }
}

impl<W: Write> Write for StreamingSigningWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (front, back) = buf.split_at(buf.len().saturating_sub(self.queue.len()));
        if front.is_empty() {
            // Write data from the front of the queue while keeping it as full
            // as possible.
            let n_from_queue = (self.used + back.len()).saturating_sub(self.queue.len());
            self.inner.write_all(&self.queue[..n_from_queue])?;

            // Move unused queued bytes to the front.
            self.queue.rotate_left(n_from_queue);
            self.used -= n_from_queue;

            // Add the remaining data to the queue.
            self.queue[self.used..self.used + back.len()].copy_from_slice(back);
            self.used += back.len();
        } else {
            // We have enough data in the back to fill the entire queue.
            self.inner.write_all(&self.queue[..self.used])?;
            self.inner.write_all(front)?;

            self.queue.copy_from_slice(back);
            self.used = self.queue.len();
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A writer that produces a signapk-style signed zip file with a whole-file
/// signature stored in the zip archive comment. The data will be left in an
/// unusable state if [`Self::finish()`] is not called.
///
/// This writer works with zip files written without data descriptors. The data
/// is hashed during [`Self::finish()`].
pub struct SeekableSigningWriter<W> {
    inner: W,
}

impl<W: Read + Write + Seek> SeekableSigningWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn finish(
        mut self,
        key: &RsaSigningKey,
        cert: &Certificate,
        cancel_signal: &AtomicBool,
    ) -> Result<W> {
        // We always write a streaming zip because that is what rawzip supports.
        // Convert it to not be streaming. This will leave the data descriptors
        // behind, but that is fine.
        zip::make_non_streaming(&mut self.inner).map_err(Error::MakeNonStreaming)?;

        let file_size = self
            .seek(SeekFrom::End(0))
            .map_err(|e| Error::DataRead("file_size", e))?;

        // Android only supports non-zip64 EOCD.
        if file_size < 22 {
            return Err(Error::ZipTooSmall);
        }

        self.seek_relative(-22)
            .map_err(|e| Error::DataRead("eocd", e))?;
        let eocd = self
            .read_array_exact::<22>()
            .map_err(|e| Error::DataRead("eocd", e))?;

        validate_eocd(&eocd)?;

        // Compute the digest of everything up until the comment size field.
        let mut hashing_writer = HashingWriter::new(
            io::sink(),
            ring::digest::Context::new(&ring::digest::SHA256),
        );

        self.rewind().map_err(|e| Error::DataRead("raw_data", e))?;
        stream::copy_n(&mut self, &mut hashing_writer, file_size - 2, cancel_signal)
            .map_err(|e| Error::DataRead("raw_data", e))?;

        let digest = hashing_writer.finish().1.finish();

        let size_and_comment = compute_signature_comment(key, cert, digest)?;
        self.inner
            .write_all(&size_and_comment)
            .map_err(|e| Error::DataWrite("size_and_comment", e))?;

        Ok(self.inner)
    }
}

impl<W: Read> Read for SeekableSigningWriter<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<W: Write> Write for SeekableSigningWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for SeekableSigningWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[allow(clippy::large_enum_variant)]
enum SigningWriterInner<W> {
    Streaming {
        inner: StreamingSigningWriter<W>,
    },
    Seekable {
        inner: SeekableSigningWriter<W>,
        /// We need to store this because [`SigningWriter::finish`] needs to be
        /// in `impl<W: Write>`, where [`SeekableSigningWriter::finish`] is not
        /// available.
        finish: fn(
            SeekableSigningWriter<W>,
            key: &RsaSigningKey,
            cert: &Certificate,
            cancel_signal: &AtomicBool,
        ) -> Result<W>,
    },
}

/// A writer that produces a signapk-style signed zip file with a whole-file
/// signature stored in the zip archive comment. The data will be left in an
/// unusable state if [`Self::finish()`] is not called.
///
/// This is a partially type-erased wrapper around [`StreamingSigningWriter`]
/// and [`SeekableSigningWriter`].
pub struct SigningWriter<W>(SigningWriterInner<W>);

impl<W: Write> SigningWriter<W> {
    pub fn new_streaming(inner: W) -> Self {
        Self(SigningWriterInner::Streaming {
            inner: StreamingSigningWriter::new(inner),
        })
    }

    pub fn finish(
        self,
        key: &RsaSigningKey,
        cert: &Certificate,
        cancel_signal: &AtomicBool,
    ) -> Result<W> {
        match self.0 {
            SigningWriterInner::Streaming { inner } => inner.finish(key, cert),
            SigningWriterInner::Seekable { inner, finish } => {
                finish(inner, key, cert, cancel_signal)
            }
        }
    }
}

impl<W: Read + Write + Seek> SigningWriter<W> {
    pub fn new_seekable(inner: W) -> Self {
        Self(SigningWriterInner::Seekable {
            inner: SeekableSigningWriter::new(inner),
            finish: SeekableSigningWriter::finish,
        })
    }
}

impl<W: Read> Read for SigningWriter<W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.0 {
            SigningWriterInner::Streaming { .. } => panic!("Called with streaming writer"),
            SigningWriterInner::Seekable { inner, .. } => inner.read(buf),
        }
    }
}

impl<W: Write> Write for SigningWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            SigningWriterInner::Streaming { inner } => inner.write(buf),
            SigningWriterInner::Seekable { inner, .. } => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            SigningWriterInner::Streaming { inner } => inner.flush(),
            SigningWriterInner::Seekable { inner, .. } => inner.flush(),
        }
    }
}

impl<W: Seek> Seek for SigningWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.0 {
            SigningWriterInner::Streaming { .. } => panic!("Called with streaming writer"),
            SigningWriterInner::Seekable { inner, .. } => inner.seek(pos),
        }
    }
}
