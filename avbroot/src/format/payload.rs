/*
 * SPDX-FileCopyrightText: 2022-2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    collections::{HashMap, HashSet},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use byteorder::{BigEndian, ReadBytesExt};
use bzip2::write::BzDecoder;
use num_traits::ToPrimitive;
use quick_protobuf::MessageWrite;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use ring::digest::{Context, Digest};
use rsa::{traits::PublicKeyParts, Pkcs1v15Sign, RsaPrivateKey};
use sha2::Sha256;
use thiserror::Error;
use x509_cert::Certificate;
use xz2::{
    stream::{Check, Stream},
    write::XzDecoder,
    write::XzEncoder,
};

use crate::{
    crypto,
    protobuf::chromeos_update_engine::{
        mod_InstallOperation, mod_Signatures::Signature, DeltaArchiveManifest, Extent,
        InstallOperation, PartitionInfo, PartitionUpdate, Signatures,
    },
    stream::{
        self, CountingReader, CountingWriter, FromReader, HashingWriter, ReadDiscardExt, ReadSeek,
        SharedCursor, WriteSeek,
    },
    util,
};

const OTA_MAGIC: &[u8; 4] = b"CrAU";
const OTA_HEADER_SIZE: usize = OTA_MAGIC.len() + 8 + 8 + 4;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Unknown magic: {0:?}")]
    UnknownMagic([u8; 4]),
    #[error("Unsupported payload version: {0}")]
    UnsupportedVersion(u64),
    #[error("Payload contains no signatures")]
    NoSignatures,
    #[error("Blob offset should be {0}, but is {1}")]
    InvalidBlobOffset(u64, u64),
    #[error("Payload signatures offset should be {0}, but is {1}")]
    InvalidPayloadSignaturesOffset(u64, u64),
    #[error("Invalid payload properties line: {0:?}")]
    InvalidPropertiesLine(String),
    #[error("Duplicate payload property: {0:?}")]
    DuplicateProperty(String),
    #[error("Payload property {0:?} ({1:?}) does not match expected value {2:?}")]
    InvalidProperty(String, String, Option<String>),
    #[error("Unsupported partition operation: {0:?}")]
    UnsupportedOperation(mod_InstallOperation::Type),
    #[error("Expected sha256 {0:?}, but have {1:?}")]
    MismatchedDigest(Option<String>, String),
    #[error("Size of {0} ({1}) is not aligned to the block size ({2})")]
    InvalidPartitionSize(String, u64, u32),
    #[error("Partition not found in payload: {0}")]
    MissingPartition(String),
    #[error("Partitions not found in payload: {0:?}")]
    MissingPartitions(HashSet<String>),
    #[error("{0:?} field is missing")]
    MissingField(&'static str),
    #[error("{0:?} field exceeds integer bounds")]
    IntegerTooLarge(&'static str),
    #[error("Crypto error")]
    Crypto(#[from] crypto::Error),
    #[error("Protobuf error")]
    Protobuf(#[from] quick_protobuf::Error),
    #[error("XZ stream error")]
    XzStream(#[from] xz2::stream::Error),
    #[error("RSA error")]
    Rsa(#[from] rsa::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct PayloadHeader {
    pub version: u64,
    pub manifest: DeltaArchiveManifest,
    pub metadata_signature_size: u32,
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

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != *OTA_MAGIC {
            return Err(Error::UnknownMagic(magic));
        }

        let version = reader.read_u64::<BigEndian>()?;
        if version != 2 {
            return Err(Error::UnsupportedVersion(version));
        }

        let manifest_size = reader
            .read_u64::<BigEndian>()?
            .to_usize()
            .ok_or_else(|| Error::IntegerTooLarge("manifest_size"))?;
        let metadata_signature_size = reader.read_u32::<BigEndian>()?;

        let mut manifest_raw = vec![0u8; manifest_size];
        reader.read_exact(&mut manifest_raw)?;
        let manifest: DeltaArchiveManifest = util::read_protobuf(&manifest_raw)?;

        // Skip manifest signatures.
        reader.read_discard_exact(metadata_signature_size.into())?;

        Ok(Self {
            version,
            manifest,
            metadata_signature_size,
            blob_offset: reader.stream_position()?,
        })
    }
}

/// Sign `digest` with `key` and return a [`Signatures`] protobuf struct with
/// the signature padded to the maximum size.
fn sign_digest(digest: &[u8], key: &RsaPrivateKey) -> Result<Signatures> {
    let scheme = Pkcs1v15Sign::new::<Sha256>();
    let mut digest_signed = key.sign(scheme, digest)?;
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
    };

    let signatures = Signatures {
        signatures: vec![signature],
    };

    Ok(signatures)
}

/// Verify `digest` inside `signatures` using `cert`.
fn verify_digest(digest: &[u8], signatures: &Signatures, cert: &Certificate) -> Result<()> {
    let public_key = crypto::get_public_key(cert)?;
    let mut last_error = None;

    for signature in &signatures.signatures {
        let Some(data) = &signature.data else {
            continue;
        };
        let Some(size) = signature.unpadded_signature_size else {
            continue;
        };
        let without_padding = &data[..size as usize];

        let scheme = Pkcs1v15Sign::new::<Sha256>();
        match public_key.verify(scheme, digest, without_padding) {
            Ok(_) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.map_or(Error::NoSignatures, |e| e.into()))
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
    key: RsaPrivateKey,
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
    pub fn new(mut inner: W, mut header: PayloadHeader, key: RsaPrivateKey) -> Result<Self> {
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
            ring::digest::digest(&ring::digest::SHA256, b"").as_ref(),
            &key,
        )?;
        let dummy_sig_size = dummy_sig.get_size();

        // Fill out the new payload signature information.
        header.manifest.signatures_offset = Some(blob_size);
        header.manifest.signatures_size = Some(dummy_sig_size as u64);

        // Build new manifest.
        let manifest_raw_new = util::write_protobuf(&header.manifest)?;

        // Excludes signatures (hashes are for signing).
        let mut h_partial = Context::new(&ring::digest::SHA256);
        // Includes signatures (hashes are for properties file).
        let mut h_full = Context::new(&ring::digest::SHA256);

        // Write header to output file.
        write_hash!(inner, [h_partial, h_full], OTA_MAGIC)?;
        write_hash!(inner, [h_partial, h_full], &header.version.to_be_bytes())?;
        write_hash!(
            inner,
            [h_partial, h_full],
            &(manifest_raw_new.len() as u64).to_be_bytes(),
        )?;
        write_hash!(
            inner,
            [h_partial, h_full],
            &(dummy_sig_size as u32).to_be_bytes()
        )?;

        // Write new manifest.
        write_hash!(inner, [h_partial, h_full], &manifest_raw_new)?;

        // Sign metadata (header + manifest) hash. The signature is not included
        // in the payload hash.
        let metadata_hash = h_partial.clone().finish();
        let metadata_sig = sign_digest(metadata_hash.as_ref(), &key)?;
        let metadata_sig_raw = util::write_protobuf(&metadata_sig)?;
        write_hash!(inner, [h_full], &metadata_sig_raw)?;

        Ok(Self {
            inner,
            header,
            metadata_hash,
            metadata_size: OTA_HEADER_SIZE + manifest_raw_new.len(),
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
    /// be left in an incomplete state. Returns the original writer, the
    /// contents that should be written for `payload_properties.txt` and the
    /// length of the header + manifest + manifest signature sections (for
    /// constructing the `payload_metadata.bin` OTA metadata property files
    /// entry).
    pub fn finish(mut self) -> Result<(W, String, u64)> {
        // Append payload signature.
        let payload_partial_hash = self.h_partial.clone().finish();
        let payload_sig = sign_digest(payload_partial_hash.as_ref(), &self.key)?;
        let payload_sig_raw = util::write_protobuf(&payload_sig)?;
        write_hash!(self.inner, [self.h_full], &payload_sig_raw)?;

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

        Ok((self.inner, properties, metadata_with_sig_size))
    }

    /// Prepare for writing the next source data blob corresponding to an
    /// [`InstallOperation`]. To write all of the payload data, call this method
    /// followed by [`Self::write()`] repeatedly until `Ok(false)` is returned
    /// or an error occurs. This function will fail if the amount of data
    /// written for the previous operation does not match
    /// [`InstallOperation::data_length`].
    pub fn begin_next_operation(&mut self) -> Result<bool> {
        if let Some(operation) = self.operation() {
            // Only operations that reference data in the blob will have a
            // length set.
            if self.written < operation.data_length.unwrap_or(0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Expected {} bytes, but only wrote {} bytes",
                        operation.data_length.unwrap(),
                        self.written,
                    ),
                )
                .into());
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

/// A writer to produce a compressed partition image suitable for directly
/// inserting into a `payload.bin`'s blob section. The data is XZ-compressed at
/// a low compression level, primarily to collapse zeros, and the
/// [`PartitionUpdate`] instance is updated with the final size and hash. The
/// entire data will be represented as a single [`InstallOperation`] and
/// [`InstallOperation::data_offset`] will be set to `None`.
pub struct CompressedPartitionWriter<W: Write> {
    inner: XzEncoder<HashingWriter<CountingWriter<W>>>,
    block_size: u32,
    h_uncompressed: Context,
    written: u64,
}

impl<W: Write> CompressedPartitionWriter<W> {
    pub fn new(writer: W, block_size: u32) -> Result<Self> {
        let counting_writer = CountingWriter::new(writer);
        let hashing_writer =
            HashingWriter::new(counting_writer, Context::new(&ring::digest::SHA256));

        // AOSP's payload_consumer does not support CRC during decompression.
        // Also, we intentionally pick the lowest compression level since we
        // primarily care about squishing zeros. The non-zero portions of boot
        // images are usually already-compressed kernels and ramdisks.
        let stream = Stream::new_easy_encoder(0, Check::None)?;
        let xz_writer = XzEncoder::new_stream(hashing_writer, stream);

        Ok(Self {
            inner: xz_writer,
            block_size,
            h_uncompressed: Context::new(&ring::digest::SHA256),
            written: 0,
        })
    }

    /// Finish writing and update the [`PartitionUpdate`] instance with the new
    /// size, hash, and install operation metadata.
    pub fn finish(mut self, partition: &mut PartitionUpdate) -> Result<W> {
        if self.written % u64::from(self.block_size) != 0 {
            return Err(Error::InvalidPartitionSize(
                partition.partition_name.clone(),
                self.written,
                self.block_size,
            ));
        }

        self.inner.flush()?;

        let hashing_writer = self.inner.finish()?;
        let digest_uncompressed = self.h_uncompressed.finish();
        let (counting_writer, context_compressed) = hashing_writer.finish();
        let digest_compressed = context_compressed.finish();
        // XzEncoder::total_out() cannot be used for an exact byte count because
        // XzEncoder::finish() writes data.
        let (writer, size_compressed) = counting_writer.finish();

        partition.new_partition_info = Some(PartitionInfo {
            size: Some(self.written),
            hash: Some(digest_uncompressed.as_ref().to_vec()),
        });

        let extent = Extent {
            start_block: Some(0),
            num_blocks: Some(self.written / u64::from(self.block_size)),
        };

        let operation = InstallOperation {
            type_pb: mod_InstallOperation::Type::REPLACE_XZ,
            // Must be manually updated by the caller.
            data_offset: None,
            data_length: Some(size_compressed),
            src_extents: vec![],
            src_length: None,
            dst_extents: vec![extent],
            dst_length: None,
            data_sha256_hash: Some(digest_compressed.as_ref().to_vec()),
            src_sha256_hash: None,
        };

        partition.operations.clear();
        partition.operations.push(operation);

        Ok(writer)
    }
}

impl<W: Write> Write for CompressedPartitionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.h_uncompressed.update(&buf[..n]);
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
    reader.rewind()?;

    let payload_signatures_offset = header
        .manifest
        .signatures_offset
        .ok_or_else(|| Error::MissingField("signatures_offset"))?;
    let payload_signatures_size = header
        .manifest
        .signatures_size
        .ok_or_else(|| Error::MissingField("signatures_size"))?;

    // Excludes signatures (hashes are for signing).
    let mut h_partial = Context::new(&ring::digest::SHA256);
    // Includes signatures (hashes are for properties file).
    let mut h_full = Context::new(&ring::digest::SHA256);

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
    )?;
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
        )?;

        let buf = writer.into_inner();
        util::read_protobuf::<Signatures>(&buf)?
    };

    // Check the metadata signatures.
    verify_digest(metadata_hash.as_ref(), &metadata_sigs, cert)?;

    // Check the blob offset.
    {
        let actual = reader.stream_position()?;
        if header.blob_offset != actual {
            return Err(Error::InvalidBlobOffset(header.blob_offset, actual));
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
    )?;
    let payload_hash = h_partial.clone().finish();

    // Check the payload signatures offset.
    {
        let expected = header.blob_offset + payload_signatures_offset;
        let actual = reader.stream_position()?;
        if expected != actual {
            return Err(Error::InvalidPayloadSignaturesOffset(expected, actual));
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
        )?;

        let buf = writer.into_inner();
        util::read_protobuf::<Signatures>(&buf)?
    };

    // Check the payload signatures.
    verify_digest(payload_hash.as_ref(), &payload_sigs, cert)?;

    // Check properties file.
    let expected_properties_raw = generate_properties(
        h_full.finish().as_ref(),
        reader.stream_position()?,
        metadata_hash.as_ref(),
        metadata_size,
    );

    let expected_properties = parse_properties(properties_raw)?;
    let actual_properties = parse_properties(&expected_properties_raw)?;

    for (key, actual_value) in actual_properties {
        let expected_value = expected_properties.get(&key);

        if expected_value != Some(&actual_value) {
            return Err(Error::InvalidProperty(
                key,
                actual_value,
                expected_value.cloned(),
            ));
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
            .ok_or_else(|| Error::MissingField("start_block"))?;
        let num_blocks = extent
            .num_blocks
            .ok_or_else(|| Error::MissingField("num_blocks"))?;

        let out_offset = start_block
            .checked_mul(block_size.into())
            .ok_or_else(|| Error::IntegerTooLarge("out_offset"))?;
        let out_data_length = num_blocks
            .checked_mul(block_size.into())
            .ok_or_else(|| Error::IntegerTooLarge("out_data_length"))?;

        writer.seek(SeekFrom::Start(out_offset))?;

        let mut hasher = Context::new(&ring::digest::SHA256);

        match op.type_pb {
            // Handle ZERO/DISCARD specially since they don't require access to
            // the payload blob.
            mod_InstallOperation::Type::ZERO | mod_InstallOperation::Type::DISCARD => {
                stream::copy_n_inspect(
                    io::repeat(0),
                    &mut writer,
                    out_data_length,
                    |data| hasher.update(data),
                    cancel_signal,
                )?;
            }
            other => {
                let data_offset = op
                    .data_offset
                    .ok_or_else(|| Error::MissingField("data_offset"))?;
                let data_length = op
                    .data_length
                    .ok_or_else(|| Error::MissingField("data_length"))?;
                let in_offset = blob_offset
                    .checked_add(data_offset)
                    .ok_or_else(|| Error::IntegerTooLarge("in_offset"))?;

                reader.seek(SeekFrom::Start(in_offset))?;

                match other {
                    mod_InstallOperation::Type::REPLACE => {
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut writer,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )?;
                    }
                    mod_InstallOperation::Type::REPLACE_BZ => {
                        let mut decoder = BzDecoder::new(&mut writer);
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut decoder,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )?;
                        decoder.finish()?;
                    }
                    mod_InstallOperation::Type::REPLACE_XZ => {
                        let mut decoder = XzDecoder::new(&mut writer);
                        stream::copy_n_inspect(
                            &mut reader,
                            &mut decoder,
                            data_length,
                            |data| hasher.update(data),
                            cancel_signal,
                        )?;
                        decoder.finish()?;
                    }
                    _ => return Err(Error::UnsupportedOperation(op.type_pb)),
                }
            }
        }

        let expected_digest = op.data_sha256_hash.as_deref();
        let digest = hasher.finish();

        if expected_digest != Some(digest.as_ref())
            && op.type_pb != mod_InstallOperation::Type::ZERO
        {
            return Err(Error::MismatchedDigest(
                expected_digest.map(hex::encode),
                hex::encode(digest.as_ref()),
            ));
        }
    }

    Ok(())
}

/// Extract the specified image from the payload into memory. This is done
/// multithreaded and uses rayon's global thread pool. `open_payload` will be
/// called from multiple threads.
pub fn extract_image_to_memory(
    open_payload: impl Fn() -> io::Result<Box<dyn ReadSeek>> + Sync,
    header: &PayloadHeader,
    partition_name: &str,
    cancel_signal: &AtomicBool,
) -> Result<SharedCursor> {
    let partition = header
        .manifest
        .partitions
        .iter()
        .find(|p| p.partition_name == partition_name)
        .ok_or_else(|| Error::MissingPartition(partition_name.to_owned()))?;
    let stream = SharedCursor::default();

    partition
        .operations
        .par_iter()
        .map(|op| -> Result<()> {
            let reader = open_payload()?;
            let writer = stream.reopen();

            apply_operation(
                reader,
                writer,
                header.manifest.block_size,
                header.blob_offset,
                op,
                cancel_signal,
            )?;

            Ok(())
        })
        .collect::<Result<_>>()?;

    Ok(stream)
}

/// Extract the specified partition images from the payload into writers. This
/// is done multithreaded and uses rayon's global thread pool. `open_payload`
/// and `open_output` will be called from multiple threads.
pub fn extract_images<'a>(
    open_payload: impl Fn() -> io::Result<Box<dyn ReadSeek>> + Sync,
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
            let reader = open_payload()?;
            let writer = open_output(name)?;

            apply_operation(
                reader,
                writer,
                header.manifest.block_size,
                header.blob_offset,
                op,
                cancel_signal,
            )?;

            Ok(())
        })
        .collect()
}
