// SPDX-FileCopyrightText: 2022-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    ops::Range,
    sync::atomic::AtomicBool,
};

use aws_lc_rs::digest::{Context, Digest};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bzip2::write::BzDecoder;
use flate2::{write::GzEncoder, Compression};
use liblzma::{
    stream::{Check, Stream},
    write::XzDecoder,
    write::XzEncoder,
};
use prost::Message;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator},
    prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_cert::Certificate;
use zerocopy::{big_endian, FromBytes, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    crypto::{self, RsaPublicKeyExt, RsaSigningKey, SignatureAlgorithm},
    protobuf::chromeos_update_engine::{
        install_operation::Type, signatures::Signature, DeltaArchiveManifest, Extent,
        InstallOperation, PartitionInfo, PartitionUpdate, Signatures,
    },
    stream::{
        self, CountingReader, FromReader, HashingWriter, ReadDiscardExt, ReadFixedSizeExt,
        ReadSeekReopen, WriteSeek, WriteSeekReopen,
    },
    util::{self, OutOfBoundsError},
};

const PAYLOAD_MAGIC: &[u8; 4] = b"CrAU";
const PAYLOAD_VERSION: u64 = 2;

const MANIFEST_MAX_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown magic: {0:?}")]
    UnknownMagic([u8; 4]),
    #[error("Unsupported payload version: {0}")]
    UnsupportedVersion(u64),
    #[error("Payload contains no signatures")]
    NoSignatures,
    #[error("Blob offset should be {expected}, but is {actual}")]
    InvalidBlobOffset { expected: u64, actual: u64 },
    #[error("Payload signatures offset should be {expected}, but is {actual}")]
    InvalidPayloadSignaturesOffset { expected: u64, actual: u64 },
    #[error("Invalid payload properties line: {0:?}")]
    InvalidPropertiesLine(String),
    #[error("Duplicate payload property: {0:?}")]
    DuplicateProperty(String),
    #[error("Payload property {key:?} ({actual:?}) does not match expected value {expected:?}")]
    InvalidProperty {
        key: String,
        expected: Option<String>,
        actual: String,
    },
    #[error("Unsupported partition operation: {0:?}")]
    UnsupportedOperation(Type),
    #[error("Expected sha256 {expected:?}, but have {actual:?}")]
    MismatchedDigest {
        expected: Option<String>,
        actual: String,
    },
    #[error("Size of {name} ({size}) is not aligned to the block size ({block_size})")]
    InvalidPartitionSize {
        name: String,
        size: u64,
        block_size: u32,
    },
    #[error("Destination extents are not in order")]
    ExtentsNotInOrder,
    #[error("Partition not found in payload: {0}")]
    MissingPartition(String),
    #[error("Partitions not found in payload: {0:?}")]
    MissingPartitions(HashSet<String>),
    #[error("{0:?} field is missing")]
    MissingField(&'static str),
    #[error("{0:?} field is out of bounds")]
    IntOutOfBounds(&'static str, #[source] OutOfBoundsError),
    #[error("{0:?} overflowed integer bounds during calculations")]
    IntOverflow(&'static str),
    #[error("Failed to decode payload manifest protobuf message")]
    ManifestDecode(#[source] prost::DecodeError),
    #[error("Failed to decode payload signatures protobuf message")]
    SignaturesDecode(#[source] prost::DecodeError),
    #[error("Failed to generate payload signature")]
    SignatureGenerate(#[source] crypto::Error),
    #[error("Failed to verify payload signature")]
    SignatureVerify(#[source] crypto::Error),
    #[error("Failed to read payload data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write payload data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
    #[error("Expected {expected} bytes, but only wrote {actual} bytes")]
    UnwrittenData { actual: u64, expected: u64 },
    #[error("I/O error when applying {op_type:?} operation for {num_blocks} blocks starting at {start_block}")]
    OperationApply {
        op_type: Type,
        start_block: u64,
        num_blocks: u64,
        source: io::Error,
    },
    #[error("Failed to reopen payload")]
    PayloadReopen(#[source] io::Error),
    #[error("Failed to open input file for partition: {0}")]
    InputOpen(String, #[source] io::Error),
    #[error("Failed to open output file for partition: {0}")]
    OutputOpen(String, #[source] io::Error),
    #[error("Failed to GZ compress partition image chunk")]
    GzCompress(#[source] io::Error),
    #[error("Failed to initialize XZ encoder")]
    XzInit(#[source] liblzma::stream::Error),
    #[error("Failed to XZ compress partition image chunk")]
    XzCompress(#[source] io::Error),
    #[error("Failed to read uncompressed input partition image chunk")]
    ChunkRead(#[source] io::Error),
    #[error("Failed to write XZ-compressed output partition image chunk")]
    ChunkWrite(#[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Raw on-disk layout for the payload header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHeader {
    /// Magic value. This should be equal to [`PAYLOAD_MAGIC`].
    magic: [u8; 4],
    /// Image version. This should be equal to [`PAYLOAD_VERSION`].
    file_format_version: big_endian::U64,
    /// Size of the [`DeltaArchiveManifest`] blob.
    manifest_size: big_endian::U64,
    /// Size of the [`Signatures`] blob.
    metadata_signature_size: big_endian::U32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PayloadHeader {
    pub version: u64,
    pub manifest: DeltaArchiveManifest,
    #[serde(skip)]
    pub metadata_signature_size: u32,
    #[serde(skip)]
    pub blob_offset: u64,
}

impl PayloadHeader {
    pub fn is_full_ota(&self) -> bool {
        self.manifest
            .partitions
            .iter()
            .all(|p| p.old_partition_info.is_none())
    }
}

impl<R: Read> FromReader<R> for PayloadHeader {
    type Error = Error;

    /// Parse the header from an OTA payload file. After this function returns,
    /// the file position is set to the beginning of the blob section.
    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let header =
            RawHeader::read_from_io(&mut reader).map_err(|e| Error::DataRead("header", e))?;

        if header.magic != *PAYLOAD_MAGIC {
            return Err(Error::UnknownMagic(header.magic));
        }

        if header.file_format_version != PAYLOAD_VERSION {
            return Err(Error::UnsupportedVersion(header.file_format_version.get()));
        }

        let manifest_size: usize = util::try_cast(header.manifest_size.get())
            .and_then(|s| util::check_bounds(s, ..=MANIFEST_MAX_SIZE))
            .map_err(|e| Error::IntOutOfBounds("manifest_size", e))?;

        let manifest_raw = reader
            .read_vec_exact(manifest_size)
            .map_err(|e| Error::DataRead("manifest", e))?;
        let manifest =
            DeltaArchiveManifest::decode(manifest_raw.as_slice()).map_err(Error::ManifestDecode)?;

        // Skip manifest signatures.
        reader
            .read_discard_exact(header.metadata_signature_size.into())
            .map_err(|e| Error::DataRead("metadata_signatures", e))?;

        Ok(Self {
            version: header.file_format_version.get(),
            manifest,
            metadata_signature_size: header.metadata_signature_size.get(),
            blob_offset: reader
                .stream_position()
                .map_err(|e| Error::DataRead("blob_offset", e))?,
        })
    }
}

/// Sign `digest` with `key` and return a [`Signatures`] protobuf struct with
/// the signature padded to the maximum size.
fn sign_digest(digest: &[u8], key: &RsaSigningKey) -> Result<Signatures> {
    let mut digest_signed = key
        .sign(SignatureAlgorithm::Sha256WithRsa, digest)
        .map_err(Error::SignatureGenerate)?;
    assert!(
        digest_signed.len() <= key.size(),
        "Signature exceeds maximum size",
    );

    let unpadded_size = digest_signed.len();
    digest_signed.resize(key.size(), 0);

    let signature = Signature {
        data: Some(digest_signed),
        // Always fits in even a u16.
        unpadded_signature_size: Some(unpadded_size as u32),
        ..Default::default()
    };

    let signatures = Signatures {
        signatures: vec![signature],
    };

    Ok(signatures)
}

/// Verify `digest` inside `signatures` using `cert`.
fn verify_digest(digest: &[u8], signatures: &Signatures, cert: &Certificate) -> Result<()> {
    let public_key = crypto::get_public_key(cert).map_err(Error::SignatureVerify)?;
    let mut last_error = None;

    for signature in &signatures.signatures {
        let Some(data) = &signature.data else {
            continue;
        };
        let size = signature
            .unpadded_signature_size
            .map_or(data.len(), |s| s as usize);
        let without_padding = &data[..size];

        match public_key.verify_sig(SignatureAlgorithm::Sha256WithRsa, digest, without_padding) {
            Ok(()) => return Ok(()),
            Err(e) => last_error = Some(Error::SignatureVerify(e)),
        }
    }

    Err(last_error.unwrap_or(Error::NoSignatures))
}

fn parse_properties(data: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();

    for line in data.split('\n') {
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::InvalidPropertiesLine(line.to_owned()));
        };

        if result.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(Error::DuplicateProperty(key.to_owned()));
        }
    }

    Ok(result)
}

/// Generate `payload_properties.txt` contents. The file hash and size include
/// the signature sections, but the metadata hash and size do not.
fn generate_properties(
    file_hash: &[u8],
    file_size: u64,
    metadata_hash: &[u8],
    metadata_size: u64,
) -> String {
    let mut properties = String::new();

    properties.push_str("FILE_HASH=");
    STANDARD.encode_string(file_hash, &mut properties);
    properties.push('\n');

    properties.push_str("FILE_SIZE=");
    properties.push_str(&file_size.to_string());
    properties.push('\n');

    properties.push_str("METADATA_HASH=");
    STANDARD.encode_string(metadata_hash, &mut properties);
    properties.push('\n');

    properties.push_str("METADATA_SIZE=");
    properties.push_str(&metadata_size.to_string());
    properties.push('\n');

    properties
}

/// A writer for producing signed `payload.bin` files.
pub struct PayloadWriter<W: Write> {
    inner: W,
    header: PayloadHeader,
    /// Metadata (header + manifest) only, excluding the metadata signature.
    metadata_hash: Digest,
    metadata_size: usize,
    /// Index of `header.manifest.partitions[]` for current entry.
    partition_index: Option<usize>,
    /// Index of `header.manifest.partitions[].operations[]` for current entry.
    operation_index: Option<usize>,
    /// Whether a next entry exists.
    done: bool,
    /// Number of bytes written for the current entry.
    written: u64,
    /// Excludes signatures (hashes are for signing).
    h_partial: Context,
    /// Includes signatures (hashes are for properties file).
    h_full: Context,
    key: RsaSigningKey,
}

/// Write data to a writer and one or more hashers.
macro_rules! write_hash {
    ($writer:expr, [$($hasher:expr),+], $data:expr $(,)?) => {
        {
            let data = $data;
            $(
                $hasher.update(data);
            )+
            $writer.write_all(data)
        }
    };
}

impl<W: Write> PayloadWriter<W> {
    /// Create a new payload writer. All information in `header` is final and
    /// cannot be changed after this function returns since it'll already have
    /// been committed to the writer. The [`InstallOperation::data_offset`]
    /// fields are ignored and internally recomputed to guarantee that there are
    /// no gaps. All partitions' install operation data is written to the blob
    /// section in order.
    pub fn new(mut inner: W, mut header: PayloadHeader, key: RsaSigningKey) -> Result<Self> {
        let mut blob_size = 0;

        // The blob must contain all data in sequential order with no gaps.
        for p in &mut header.manifest.partitions {
            for op in &mut p.operations {
                if let Some(length) = op.data_length {
                    // The field must be left unset when the blob contains no
                    // data for the operation.
                    op.data_offset = Some(blob_size);
                    blob_size += length;
                }
            }
        }

        // Get the length of an dummy signature struct since the length fields
        // are part of the data to be signed.
        let dummy_sig = sign_digest(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"").as_ref(),
            &key,
        )?;
        let dummy_sig_size = dummy_sig.encoded_len();

        // Fill out the new payload signature information.
        header.manifest.signatures_offset = Some(blob_size);
        header.manifest.signatures_size = Some(dummy_sig_size as u64);

        // Build new manifest.
        let manifest_raw_new = header.manifest.encode_to_vec();

        // Excludes signatures (hashes are for signing).
        let mut h_partial = Context::new(&aws_lc_rs::digest::SHA256);
        // Includes signatures (hashes are for properties file).
        let mut h_full = Context::new(&aws_lc_rs::digest::SHA256);

        // Write header to output file.
        let raw_header = RawHeader {
            magic: *PAYLOAD_MAGIC,
            file_format_version: header.version.into(),
            manifest_size: (manifest_raw_new.len() as u64).into(),
            metadata_signature_size: (dummy_sig_size as u32).into(),
        };
        write_hash!(inner, [h_partial, h_full], raw_header.as_bytes())
            .map_err(|e| Error::DataWrite("header", e))?;

        // Write new manifest.
        write_hash!(inner, [h_partial, h_full], &manifest_raw_new)
            .map_err(|e| Error::DataWrite("manifest", e))?;

        // Sign metadata (header + manifest) hash. The signature is not included
        // in the payload hash.
        let metadata_hash = h_partial.clone().finish();
        let metadata_sig = sign_digest(metadata_hash.as_ref(), &key)?;
        let metadata_sig_raw = metadata_sig.encode_to_vec();
        write_hash!(inner, [h_full], &metadata_sig_raw)
            .map_err(|e| Error::DataWrite("metadata_signatures", e))?;

        Ok(Self {
            inner,
            header,
            metadata_hash,
            metadata_size: raw_header.as_bytes().len() + manifest_raw_new.len(),
            partition_index: None,
            operation_index: None,
            done: false,
            written: 0,
            h_partial,
            h_full,
            key,
        })
    }

    /// Finalize the payload. If this function is not called, the payload will
    /// be left in an incomplete state. Returns the original writer, the final
    /// header, the contents that should be written for `payload_properties.txt`
    /// and the length of the header + manifest + manifest signature sections
    /// (for constructing the `payload_metadata.bin` OTA metadata property files
    /// entry).
    pub fn finish(mut self) -> Result<(W, PayloadHeader, String, u64)> {
        // Append payload signature.
        let payload_partial_hash = self.h_partial.clone().finish();
        let payload_sig = sign_digest(payload_partial_hash.as_ref(), &self.key)?;
        let payload_sig_raw = payload_sig.encode_to_vec();
        write_hash!(self.inner, [self.h_full], &payload_sig_raw)
            .map_err(|e| Error::DataWrite("payload_signatures", e))?;

        // Everything before the blob.
        let metadata_with_sig_size =
            self.metadata_size as u64 + self.header.manifest.signatures_size.unwrap();
        // Whole file, including both signatures.
        let new_file_size = metadata_with_sig_size
            + self.header.manifest.signatures_offset.unwrap()
            + self.header.manifest.signatures_size.unwrap();

        let full_digest = self.h_full.finish();

        let properties = generate_properties(
            full_digest.as_ref(),
            new_file_size,
            self.metadata_hash.as_ref(),
            self.metadata_size as u64,
        );

        Ok((self.inner, self.header, properties, metadata_with_sig_size))
    }

    /// Prepare for writing the next source data blob corresponding to an
    /// [`InstallOperation`]. To write all of the payload data, call this method
    /// followed by [`Self::write()`] repeatedly until `Ok(false)` is returned
    /// or an error occurs. [`Error::UnwrittenData`] will be returned if the
    /// amount of data written for the previous operation does not match
    /// [`InstallOperation::data_length`].
    pub fn begin_next_operation(&mut self) -> Result<bool> {
        if let Some(operation) = self.operation() {
            // Only operations that reference data in the blob will have a
            // length set.
            let expected = operation.data_length.unwrap_or(0);

            if self.written < expected {
                return Err(Error::UnwrittenData {
                    actual: self.written,
                    expected,
                });
            }
        }

        if let Some(pi) = &mut self.partition_index {
            // Move to next entry.
            loop {
                // Try to move to next operation.
                if let Some(oi) = &mut self.operation_index {
                    *oi += 1;

                    if *oi < self.header.manifest.partitions[*pi].operations.len() {
                        break;
                    } else {
                        self.operation_index = None;
                    }
                }

                // Try to move to next partition.
                *pi += 1;

                if *pi < self.header.manifest.partitions.len() {
                    if !self.header.manifest.partitions[*pi].operations.is_empty() {
                        self.operation_index = Some(0);
                        break;
                    }
                } else {
                    // No more partitions.
                    self.partition_index = None;
                    break;
                }
            }
        } else if !self.done {
            // Move to first entry.
            if !self.header.manifest.partitions.is_empty()
                && !self.header.manifest.partitions[0].operations.is_empty()
            {
                self.partition_index = Some(0);
                self.operation_index = Some(0);
            }
        }

        self.done = self.partition_index.is_none();
        self.written = 0;

        Ok(!self.done)
    }

    /// Get the partition index for the current entry. This is only valid when
    /// [`Self::begin_next_operation()`] returns `true`.
    pub fn partition_index(&self) -> Option<usize> {
        self.partition_index
    }

    /// Get the install operation index for the current entry. This is only
    /// valid when [`Self::begin_next_operation()`] returns `true`.
    pub fn operation_index(&self) -> Option<usize> {
        self.operation_index
    }

    /// Get the [`PartitionUpdate`] instance for the current entry. This is only
    /// valid when [`Self::begin_next_operation()`] returns `true`.
    pub fn partition(&self) -> Option<&PartitionUpdate> {
        self.partition_index
            .map(|pi| &self.header.manifest.partitions[pi])
    }

    /// Get the [`InstallOperation`] instance for the current entry. This is
    /// only valid when [`Self::begin_next_operation()`] returns `true`.
    pub fn operation(&self) -> Option<&InstallOperation> {
        self.operation_index
            .map(|oi| &self.partition().unwrap().operations[oi])
    }
}

impl<W: Write> Write for PayloadWriter<W> {
    /// Write data for the current partition install operation. The amount of
    /// data written in total must match [`InstallOperation::data_length`].
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let pi = self.partition_index.expect("No partition selected");
        let oi = self.operation_index.expect("No operation selected");
        let partition = &self.header.manifest.partitions[pi];
        let operation = &partition.operations[oi];

        let to_write =
            (operation.data_length.unwrap() - self.written).min(buf.len() as u64) as usize;
        let n = self.inner.write(&buf[..to_write])?;

        self.h_full.update(&buf[..n]);
        self.h_partial.update(&buf[..n]);

        self.written += n as u64;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Verify the payload signatures using the specified certificate and check that
/// the digests in `payload_properties.txt` are correct.
pub fn verify_payload(
    mut reader: impl Read + Seek,
    cert: &Certificate,
    properties_raw: &str,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let header = PayloadHeader::from_reader(&mut reader)?;
    reader.rewind().map_err(|e| Error::DataRead("header", e))?;

    let payload_signatures_offset = header
        .manifest
        .signatures_offset
        .ok_or(Error::MissingField("signatures_offset"))?;
    let payload_signatures_size = header
        .manifest
        .signatures_size
        .ok_or(Error::MissingField("signatures_size"))?;

    // Excludes signatures (hashes are for signing).
    let mut h_partial = Context::new(&aws_lc_rs::digest::SHA256);
    // Includes signatures (hashes are for properties file).
    let mut h_full = Context::new(&aws_lc_rs::digest::SHA256);

    // Read from the beginning to the metadata signature.
    let metadata_size = header.blob_offset - u64::from(header.metadata_signature_size);
    stream::copy_n_inspect(
        &mut reader,
        io::sink(),
        metadata_size,
        |data| {
            h_partial.update(data);
            h_full.update(data);
        },
        cancel_signal,
    )
    .map_err(|e| Error::DataRead("metadata", e))?;
    let metadata_hash = h_partial.clone().finish();

    // Read the metadata signatures.
    let metadata_sigs = {
        let mut writer = Cursor::new(Vec::new());

        stream::copy_n_inspect(
            &mut reader,
            &mut writer,
            header.metadata_signature_size.into(),
            |data| h_full.update(data),
            cancel_signal,
        )
        .map_err(|e| Error::DataRead("metadata_signatures", e))?;

        let buf = writer.into_inner();
        Signatures::decode(buf.as_slice()).map_err(Error::SignaturesDecode)?
    };

    // Check the metadata signatures.
    verify_digest(metadata_hash.as_ref(), &metadata_sigs, cert)?;

    // Check the blob offset.
    {
        let actual = reader
            .stream_position()
            .map_err(|e| Error::DataRead("blob_offset", e))?;
        if header.blob_offset != actual {
            return Err(Error::InvalidBlobOffset {
                expected: header.blob_offset,
                actual,
            });
        }
    }

    // Read (and discard) all the payload blobs.
    stream::copy_n_inspect(
        &mut reader,
        io::sink(),
        payload_signatures_offset,
        |data| {
            h_partial.update(data);
            h_full.update(data);
        },
        cancel_signal,
    )
    .map_err(|e| Error::DataRead("blob", e))?;
    let payload_hash = h_partial.clone().finish();

    // Check the payload signatures offset.
    {
        let expected = header.blob_offset + payload_signatures_offset;
        let actual = reader
            .stream_position()
            .map_err(|e| Error::DataRead("payload_signatures_offset", e))?;
        if expected != actual {
            return Err(Error::InvalidPayloadSignaturesOffset { expected, actual });
        }
    }

    // Read the payload signatures.
    let payload_sigs = {
        let mut writer = Cursor::new(Vec::new());

        stream::copy_n_inspect(
            &mut reader,
            &mut writer,
            payload_signatures_size,
            |data| h_full.update(data),
            cancel_signal,
        )
        .map_err(|e| Error::DataRead("payload_signatures", e))?;

        let buf = writer.into_inner();
        Signatures::decode(buf.as_slice()).map_err(Error::SignaturesDecode)?
    };

    // Check the payload signatures.
    verify_digest(payload_hash.as_ref(), &payload_sigs, cert)?;

    // Check properties file.
    let expected_properties_raw = generate_properties(
        h_full.finish().as_ref(),
        reader
            .stream_position()
            .map_err(|e| Error::DataRead("payload_size", e))?,
        metadata_hash.as_ref(),
        metadata_size,
    );

    let expected_properties = parse_properties(properties_raw)?;
    let actual_properties = parse_properties(&expected_properties_raw)?;

    for (key, actual_value) in actual_properties {
        let expected_value = expected_properties.get(&key);

        if expected_value != Some(&actual_value) {
            return Err(Error::InvalidProperty {
                key,
                expected: expected_value.cloned(),
                actual: actual_value,
            });
        }
    }

    Ok(())
}

/// Apply a partition operation from `reader` to `writer`.
pub fn apply_operation(
    mut reader: impl Read + Seek,
    mut writer: impl Write + Seek,
    block_size: u32,
    blob_offset: u64,
    op: &InstallOperation,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    for extent in &op.dst_extents {
        let start_block = extent
            .start_block
            .ok_or(Error::MissingField("start_block"))?;
        let num_blocks = extent.num_blocks.ok_or(Error::MissingField("num_blocks"))?;

        let out_offset = start_block
            .checked_mul(block_size.into())
            .ok_or(Error::IntOverflow("out_offset"))?;
        let out_data_length = num_blocks
            .checked_mul(block_size.into())
            .ok_or(Error::IntOverflow("out_data_length"))?;

        let error_fn = |e: io::Error| Error::OperationApply {
            op_type: op.r#type(),
            start_block,
            num_blocks,
            source: e,
        };

        writer.seek(SeekFrom::Start(out_offset)).map_err(error_fn)?;

        let mut hasher = Context::new(&aws_lc_rs::digest::SHA256);

        match op.r#type() {
            // Handle ZERO/DISCARD specially since they don't require access to
            // the payload blob.
            Type::Zero | Type::Discard => {
                stream::copy_n_inspect(
                    io::repeat(0),
                    &mut writer,
                    out_data_length,
                    |data| hasher.update(data),
                    cancel_signal,
                )
                .map_err(error_fn)?;
            }
            other => {
                let data_offset = op.data_offset.ok_or(Error::MissingField("data_offset"))?;
                let data_length = op.data_length.ok_or(Error::MissingField("data_length"))?;
                let in_offset = blob_offset
                    .checked_add(data_offset)
                    .ok_or(Error::IntOverflow("in_offset"))?;

                reader.seek(SeekFrom::Start(in_offset)).map_err(error_fn)?;

                match other {
                    Type::Replace => {
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut writer,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )
                        .map_err(error_fn)?;
                    }
                    Type::ReplaceBz => {
                        let mut decoder = BzDecoder::new(&mut writer);
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut decoder,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )
                        .and_then(|()| decoder.finish())
                        .map_err(error_fn)?;
                    }
                    Type::ReplaceXz => {
                        let mut decoder = XzDecoder::new(&mut writer);
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut decoder,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )
                        .and_then(|()| decoder.finish())
                        .map_err(error_fn)?;
                    }
                    _ => return Err(Error::UnsupportedOperation(op.r#type())),
                }
            }
        }

        let expected_digest = op.data_sha256_hash.as_deref();
        let digest = hasher.finish();

        if expected_digest != Some(digest.as_ref()) && op.r#type() != Type::Zero {
            return Err(Error::MismatchedDigest {
                expected: expected_digest.map(hex::encode),
                actual: hex::encode(digest.as_ref()),
            });
        }
    }

    Ok(())
}

/// Extract the specified image from the payload. This is done multithreaded and
/// uses rayon's global thread pool. Both the `payload` and `output` streams
/// will be reopened from multiple threads.
pub fn extract_image(
    payload: &(dyn ReadSeekReopen + Sync),
    output: &(dyn WriteSeekReopen + Sync),
    header: &PayloadHeader,
    partition_name: &str,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let partition = header
        .manifest
        .partitions
        .iter()
        .find(|p| p.partition_name == partition_name)
        .ok_or_else(|| Error::MissingPartition(partition_name.to_owned()))?;

    partition
        .operations
        .par_iter()
        .map(|op| -> Result<()> {
            let reader = payload.reopen_boxed().map_err(Error::PayloadReopen)?;
            let writer = output
                .reopen_boxed()
                .map_err(|e| Error::OutputOpen(partition_name.to_owned(), e))?;

            apply_operation(
                reader,
                writer,
                header.manifest.block_size(),
                header.blob_offset,
                op,
                cancel_signal,
            )?;

            Ok(())
        })
        .collect::<Result<_>>()
}

/// Extract the specified partition images from the payload into writers. This
/// is done multithreaded and uses rayon's global thread pool. `open_payload`
/// and `open_output` will be called from multiple threads.
pub fn extract_images<'a>(
    payload: &(dyn ReadSeekReopen + Sync),
    open_output: impl Fn(&str) -> io::Result<Box<dyn WriteSeek>> + Sync,
    header: &PayloadHeader,
    partition_names: impl IntoIterator<Item = &'a str>,
    cancel_signal: &AtomicBool,
) -> Result<()> {
    let mut remaining = partition_names.into_iter().collect::<HashSet<_>>();
    // We parallelize at the operation level or else one thread might get stuck
    // processing a giant image.
    let mut operations = vec![];

    for p in &header.manifest.partitions {
        if remaining.remove(p.partition_name.as_str()) {
            for op in &p.operations {
                operations.push((p.partition_name.as_str(), op));
            }
        }
    }

    if !remaining.is_empty() {
        let remaining = remaining.iter().map(|&n| n.to_owned()).collect();
        return Err(Error::MissingPartitions(remaining));
    }

    operations
        .into_par_iter()
        .map(|(name, op)| -> Result<()> {
            let reader = payload.reopen_boxed().map_err(Error::PayloadReopen)?;
            let writer = open_output(name).map_err(|e| Error::OutputOpen(name.to_owned(), e))?;

            apply_operation(
                reader,
                writer,
                header.manifest.block_size(),
                header.blob_offset,
                op,
                cancel_signal,
            )?;

            Ok(())
        })
        .collect()
}

fn compress_chunk(raw_data: &[u8], cancel_signal: &AtomicBool) -> Result<(Vec<u8>, Digest)> {
    let reader = Cursor::new(raw_data);
    let writer = Cursor::new(Vec::new());
    let hashing_writer = HashingWriter::new(writer, Context::new(&aws_lc_rs::digest::SHA256));

    // AOSP's payload_consumer does not support checking CRC during
    // decompression. Also, we intentionally pick the lowest compression level
    // since we primarily care about squishing zeros. The non-zero portions of
    // boot images are usually already-compressed kernels and ramdisks.
    let stream = Stream::new_easy_encoder(0, Check::None).map_err(Error::XzInit)?;
    let mut xz_writer = XzEncoder::new_stream(hashing_writer, stream);

    stream::copy_n(reader, &mut xz_writer, raw_data.len() as u64, cancel_signal)
        .map_err(Error::XzCompress)?;

    let hashing_writer = xz_writer.finish().map_err(Error::XzCompress)?;
    let (writer, context_compressed) = hashing_writer.finish();
    let digest_compressed = context_compressed.finish();
    let data = writer.into_inner();

    Ok((data, digest_compressed))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum VabcAlgo {
    Lz4,
    Gzip,
}

impl VabcAlgo {
    pub fn new(name: &str) -> Option<Self> {
        match name {
            "lz4" => Some(Self::Lz4),
            "gz" => Some(Self::Gzip),
            _ => None,
        }
    }

    fn compressed_size(self, mut raw_data: &[u8], block_size: u32) -> Result<u64> {
        let mut total = 0;

        while !raw_data.is_empty() {
            let n = raw_data.len().min(block_size as usize);
            let (chunk, remaining) = raw_data.split_at(n);

            // This should match CompressWorker::GetDefaultCompressionLevel() in
            // AOSP's libsnapshot.
            let compressed = match self {
                Self::Lz4 => lz4_flex::block::compress(chunk),
                Self::Gzip => {
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
                    encoder.write_all(chunk).map_err(Error::GzCompress)?;
                    encoder.finish().map_err(Error::GzCompress)?
                }
            };

            total += compressed.len().min(n) as u64;

            raw_data = remaining;
        }

        Ok(total)
    }
}

impl fmt::Display for VabcAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lz4 => f.write_str("lz4"),
            Self::Gzip => f.write_str("gz"),
        }
    }
}

/// Compress the image and return the corresponding information to insert into
/// the payload manifest's [`PartitionUpdate`] instance. The uncompressed data
/// is split into 2 MiB chunks, which are read and compressed in parallel, and
/// then written in parallel (but in order) to the output. Each chunk will have
/// a corresponding [`InstallOperation`] in the return value. The caller must
/// update [`InstallOperation::data_offset`] in each operation manually because
/// the initial values are relative to 0.
///
/// If `vabc_algo` is set, the VABC CoW v2 size estimate will be computed. The
/// caller must update [`PartitionUpdate::estimate_cow_size`] with this value or
/// else update_engine may fail to flash the partition due to running out of
/// space on the CoW block device. CoW v2 + other algorithms and also CoW v3 are
/// currently unsupported because there currently are no known OTAs that use
/// those configurations.
pub fn compress_image(
    input: &(dyn ReadSeekReopen + Sync),
    output: &(dyn WriteSeekReopen + Sync),
    partition_name: &str,
    block_size: u32,
    vabc_algo: Option<VabcAlgo>,
    cancel_signal: &AtomicBool,
) -> Result<(PartitionInfo, Vec<InstallOperation>, Option<u64>)> {
    const CHUNK_SIZE: u64 = 2 * 1024 * 1024;
    const CHUNK_GROUP: u64 = 32;

    let file_size = input
        .reopen_boxed()
        .and_then(|mut r| r.seek(SeekFrom::End(0)))
        .map_err(|e| Error::InputOpen(partition_name.to_owned(), e))?;
    let final_chunk_different = file_size % CHUNK_SIZE != 0;

    if file_size % u64::from(block_size) != 0 || CHUNK_SIZE % u64::from(block_size) != 0 {
        return Err(Error::InvalidPartitionSize {
            name: partition_name.to_owned(),
            size: file_size,
            block_size,
        });
    }

    let chunks_total = file_size.div_ceil(CHUNK_SIZE);
    let mut bytes_compressed = 0;
    let mut context_uncompressed = Context::new(&aws_lc_rs::digest::SHA256);
    let mut cow_estimate = 0;
    let mut operations = vec![];

    // Read the file one group at a time. This allows for some parallelization
    // without reading the entire file into memory. This is necessary because we
    // need to compute the checksum of the entire file.
    while (operations.len() as u64) < chunks_total {
        let chunks_done = operations.len() as u64;
        let chunks_group = (chunks_total - chunks_done).min(CHUNK_GROUP);

        let uncompressed_data_group = (chunks_done..chunks_done + chunks_group)
            .into_par_iter()
            .map(|chunk| -> io::Result<(u64, Vec<u8>)> {
                let mut reader = input.reopen_boxed()?;
                let offset = reader.seek(SeekFrom::Start(chunk * CHUNK_SIZE))?;

                let chunk_size = if final_chunk_different && chunk == chunks_total - 1 {
                    file_size % CHUNK_SIZE
                } else {
                    CHUNK_SIZE
                };

                stream::check_cancel(cancel_signal)?;
                let data = reader.read_vec_exact(chunk_size as usize)?;

                Ok((offset, data))
            })
            .collect::<io::Result<Vec<_>>>()
            .map_err(Error::ChunkRead)?;

        for (_, data) in &uncompressed_data_group {
            context_uncompressed.update(data);
        }

        let mut compressed_data_group = uncompressed_data_group
            .into_par_iter()
            .map(
                |(raw_offset, raw_data)| -> Result<(Vec<u8>, InstallOperation, u64)> {
                    let (data, digest_compressed) = compress_chunk(&raw_data, cancel_signal)?;
                    let cow_size = vabc_algo
                        .map(|a| a.compressed_size(&raw_data, block_size))
                        .transpose()?
                        .unwrap_or(0);

                    let extent = Extent {
                        start_block: Some(raw_offset / u64::from(block_size)),
                        num_blocks: Some(raw_data.len() as u64 / u64::from(block_size)),
                    };

                    let mut operation = InstallOperation::default();
                    operation.set_type(Type::ReplaceXz);
                    operation.data_length = Some(data.len() as u64);
                    operation.dst_extents.push(extent);
                    operation.data_sha256_hash = Some(digest_compressed.as_ref().to_vec());

                    Ok((data, operation, cow_size))
                },
            )
            .collect::<Result<Vec<_>>>()?;

        for (data, operation, cow_size) in &mut compressed_data_group {
            operation.data_offset = Some(bytes_compressed);
            bytes_compressed += data.len() as u64;
            cow_estimate += *cow_size;
        }

        let group_operations = compressed_data_group
            .into_par_iter()
            .map(|(data, operation, _)| -> io::Result<InstallOperation> {
                let mut writer = output.reopen_boxed()?;
                writer.seek(SeekFrom::Start(operation.data_offset.unwrap()))?;
                writer.write_all(&data)?;

                Ok(operation)
            })
            .collect::<io::Result<Vec<_>>>()
            .map_err(Error::ChunkWrite)?;

        operations.extend(group_operations.into_iter());
    }

    let digest_uncompressed = context_uncompressed.finish();
    let partition_info = PartitionInfo {
        size: Some(file_size),
        hash: Some(digest_uncompressed.as_ref().to_vec()),
    };

    let cow_estimate = if vabc_algo.is_some() {
        // lz4_flex and miniz_oxide usually compress better than the lz4 and
        // zlib implementations used by libsnapshot_cow. Make up for this by
        // adding percentage-based overhead.
        cow_estimate += cow_estimate / 100;

        // We also need to account for constant overhead, especially with
        // smaller partitions. We can match what delta_generator normally adds
        // in CowWriterV2::InitPos() exactly. Since we only ever create full
        // OTAs, we can assume that all CoW operations are kCowReplaceOp.

        // sizeof(CowHeader).
        cow_estimate += 38;
        // header_.buffer_size (equal to BUFFER_REGION_DEFAULT_SIZE).
        cow_estimate += 2 * 1024 * 1024;
        // CowOptions::cluster_ops * sizeof(CowOperationV2).
        cow_estimate += 200 * 20;

        Some(cow_estimate)
    } else {
        None
    };

    Ok((partition_info, operations, cow_estimate))
}

fn extents_sorted(operations: &[InstallOperation]) -> bool {
    let mut offset = 0;

    for operation in operations {
        if operation.dst_extents.is_empty() {
            return false;
        }

        for extent in &operation.dst_extents {
            let Some(start) = extent.start_block else {
                return false;
            };
            let Some(size) = extent.num_blocks else {
                return false;
            };

            if start != offset {
                return false;
            }

            let Some(next) = start.checked_add(size) else {
                return false;
            };
            offset = next;
        }
    }

    true
}

/// Compress the modified image and update the specified [`PartitionInfo`] and
/// list of [`InstallOperation`]s. [`InstallOperation`]s that do not match any
/// byte range in `ranges` will not be compressed. The caller must update
/// [`InstallOperation::data_offset`] in each operation manually because the
/// initial values are relative to 0.
///
/// Returns the ranges of indices of `operations` that were updated.
pub fn compress_modified_image(
    input: &(dyn ReadSeekReopen + Sync),
    output: &(dyn WriteSeekReopen + Sync),
    block_size: u32,
    partition_info: &mut PartitionInfo,
    operations: &mut [InstallOperation],
    ranges: &[Range<u64>],
    cancel_signal: &AtomicBool,
) -> Result<Vec<Range<usize>>> {
    const OPERATION_GROUP: usize = 32;

    // Full OTAs created by payload_generator have one extent per operation and
    // they're all in order with no gaps. Verify this so we can take advantage
    // of this layout.
    if !extents_sorted(operations) {
        return Err(Error::ExtentsNotInOrder);
    }

    let groups_total = operations.len().div_ceil(OPERATION_GROUP);
    let mut bytes_compressed = 0;
    let mut context_uncompressed = Context::new(&aws_lc_rs::digest::SHA256);
    let mut modified_operations = vec![];

    // Read the file one group at a time. This allows for some parallelization
    // without reading the entire file into memory. This is necessary because we
    // need to compute the checksum of the entire file.
    for group in 0..groups_total {
        let operation_start = group * OPERATION_GROUP;
        let operation_size = (operations.len() - operation_start).min(OPERATION_GROUP);
        let operation_end = operation_start + operation_size;

        let uncompressed_data_group = operations[operation_start..operation_end]
            .par_iter()
            .map(|operation| -> Result<(Vec<u8>, bool)> {
                let extents_start = operation.dst_extents[0]
                    .start_block()
                    .checked_mul(u64::from(block_size))
                    .ok_or(Error::IntOverflow("extents_start"))?;
                let extents_size = operation
                    .dst_extents
                    .iter()
                    .map(|e| e.num_blocks())
                    .try_fold(0u64, |acc, n| acc.checked_add(n))
                    .and_then(|n| n.checked_mul(u64::from(block_size)))
                    .ok_or(Error::IntOverflow("extents_size"))?;
                let extents_end = extents_start
                    .checked_add(extents_size)
                    .ok_or(Error::IntOverflow("extents_end"))?;
                let extents_size: usize = util::try_cast(extents_size)
                    .map_err(|e| Error::IntOutOfBounds("extents_size", e))?;

                let mut reader = input.reopen_boxed().map_err(Error::ChunkRead)?;
                reader
                    .seek(SeekFrom::Start(extents_start))
                    .map_err(Error::ChunkRead)?;

                stream::check_cancel(cancel_signal).map_err(Error::ChunkRead)?;
                let data = reader
                    .read_vec_exact(extents_size)
                    .map_err(Error::ChunkRead)?;

                let was_modified = util::ranges_overlaps(ranges, &(extents_start..extents_end));

                Ok((data, was_modified))
            })
            .collect::<Result<Vec<_>>>()?;

        for (data, _) in &uncompressed_data_group {
            context_uncompressed.update(data);
        }

        // Only compress the modified chunks.
        let mut compressed_data_group = operations[operation_start..operation_end]
            .par_iter_mut()
            .enumerate()
            .zip(uncompressed_data_group)
            .filter(|(_, (_, was_modified))| *was_modified)
            .map(
                |((i_rel, operation), (raw_data, _))| -> Result<(Vec<u8>, usize, &mut InstallOperation)> {
                    let (data, digest_compressed) = compress_chunk(&raw_data, cancel_signal)?;

                    operation.set_type(Type::ReplaceXz);
                    operation.data_length = Some(data.len() as u64);
                    operation.data_sha256_hash = Some(digest_compressed.as_ref().to_vec());

                    Ok((data, i_rel + operation_start, operation))
                },
            )
            .collect::<Result<Vec<_>>>()?;

        for (data, _, operation) in &mut compressed_data_group {
            operation.data_offset = Some(bytes_compressed);
            bytes_compressed += data.len() as u64;
        }

        let modified_group_operations = compressed_data_group
            .into_par_iter()
            .map(|(data, i, operation)| {
                let mut writer = output.reopen_boxed()?;
                writer.seek(SeekFrom::Start(operation.data_offset.unwrap()))?;
                writer.write_all(&data)?;

                Ok(i..i + 1)
            })
            .collect::<io::Result<Vec<_>>>()
            .map_err(Error::ChunkWrite)?;

        modified_operations.extend(modified_group_operations);
    }

    let digest_uncompressed = context_uncompressed.finish();
    partition_info.hash = Some(digest_uncompressed.as_ref().to_vec());

    Ok(util::merge_overlapping(&modified_operations))
}
