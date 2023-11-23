/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    cmp, fmt,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    str,
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::{ModInverse, ToBigInt};
use num_traits::{Pow, ToPrimitive};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use ring::digest::{Algorithm, Context};
use rsa::{traits::PublicKeyParts, BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::{
    escape,
    format::{
        fec::{self, Fec},
        padding,
    },
    stream::{
        self, CountingReader, FromReader, ReadDiscardExt, ReadSeekReopen, ReadStringExt, ToWriter,
        WriteSeekReopen, WriteStringExt, WriteZerosExt,
    },
    util,
};

pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 3;
pub const VERSION_SUB: u32 = 0;

pub const FOOTER_VERSION_MAJOR: u32 = 1;
pub const FOOTER_VERSION_MINOR: u32 = 0;

pub const HEADER_MAGIC: [u8; 4] = *b"AVB0";
pub const FOOTER_MAGIC: [u8; 4] = *b"AVBf";

/// Maximum header size. This is the same limit as what avbtool enforces. This
/// value is also used as the limit for individual descriptor fields to allow
/// for early fail. No individual field can actually be this size.
pub const HEADER_MAX_SIZE: u64 = 64 * 1024;

/// Maximum hash tree size. The current limit equals the hash tree size for a
/// 4GiB image using SHA512 digests and a block size of 4096.
pub const HASH_TREE_MAX_SIZE: u64 = 68_177_920;

/// Maximum FEC data size. The current limit equals the FEC data size for a 4GiB
/// image using 2 parity bytes per codeword.
pub const FEC_DATA_MAX_SIZE: u64 = 33_959_936;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read {0:?} field: {1}")]
    ReadFieldError(&'static str, io::Error),
    #[error("Failed to write {0:?} field: {1}")]
    WriteFieldError(&'static str, io::Error),
    #[error("{0:?} field does not have NULL terminator")]
    StringNotNullTerminated(&'static str),
    #[error("{0:?} field is not ASCII encoded: {1:?}")]
    StringNotAscii(&'static str, String),
    #[error("Header exceeds maximum size of {HEADER_MAX_SIZE}")]
    HeaderTooLarge,
    #[error("Descriptor padding is too long or data was not consumed")]
    PaddingTooLong,
    #[error("{0:?} field padding contains non-zero bytes")]
    PaddingNotZero(&'static str),
    #[error("{0:?} field is out of bounds")]
    FieldOutOfBounds(&'static str),
    #[error("Invalid VBMeta header magic: {0:?}")]
    InvalidHeaderMagic([u8; 4]),
    #[error("Invalid VBMeta footer magic: {0:?}")]
    InvalidFooterMagic([u8; 4]),
    #[error("RSA public key exponent not supported: {0}")]
    UnsupportedRsaPublicExponent(BigUint),
    #[error("Signature algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(AlgorithmType),
    #[error("Hashing algorithm not supported: {0:?}")]
    UnsupportedHashAlgorithm(String),
    #[error("Incorrect key size ({key_size} bytes) for algorithm {algo:?} ({} bytes)", algo.public_key_len())]
    IncorrectKeySize {
        key_size: usize,
        algo: AlgorithmType,
    },
    #[error("RSA key size (0) is not compatible with any AVB signing algorithm")]
    UnsupportedKey(usize),
    #[error("Expected root digest {expected}, but have {actual}")]
    InvalidRootDigest { expected: String, actual: String },
    #[error("Expected hash tree {expected}, but have {actual}")]
    InvalidHashTree { expected: String, actual: String },
    #[error("Hash tree does not immediately follow image data")]
    HashTreeGap,
    #[error("FEC data does not immediately follow hash tree")]
    FecDataGap,
    #[error("Cannot repair image because there is no FEC data")]
    FecMissing,
    #[error("FEC requires data block size ({data}) and hash block size ({hash}) to match")]
    MismatchedFecBlockSizes { data: u32, hash: u32 },
    #[error("Must have exactly one hash or hash tree descriptor")]
    NoAppendedDescriptor,
    #[error("Failed to RSA sign digest")]
    RsaSign(#[source] rsa::Error),
    #[error("Failed to RSA verify signature")]
    RsaVerify(#[source] rsa::Error),
    #[error("{0} byte image size is too small to fit header or footer")]
    ImageSizeTooSmall(u64),
    #[error("FEC error")]
    Fec(#[from] fec::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn ring_algorithm(name: &str, for_verify: bool) -> Result<&'static Algorithm> {
    match name {
        "sha1" if for_verify => Ok(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY),
        "sha256" => Ok(&ring::digest::SHA256),
        "sha512" => Ok(&ring::digest::SHA512),
        a => Err(Error::UnsupportedHashAlgorithm(a.to_owned())),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum AlgorithmType {
    None,
    Sha256Rsa2048,
    Sha256Rsa4096,
    Sha256Rsa8192,
    Sha512Rsa2048,
    Sha512Rsa4096,
    Sha512Rsa8192,
    Unknown(u32),
}

impl AlgorithmType {
    pub fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Sha256Rsa2048,
            2 => Self::Sha256Rsa4096,
            3 => Self::Sha256Rsa8192,
            4 => Self::Sha512Rsa2048,
            5 => Self::Sha512Rsa4096,
            6 => Self::Sha512Rsa8192,
            v => Self::Unknown(v),
        }
    }

    pub fn to_raw(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sha256Rsa2048 => 1,
            Self::Sha256Rsa4096 => 2,
            Self::Sha256Rsa8192 => 3,
            Self::Sha512Rsa2048 => 4,
            Self::Sha512Rsa4096 => 5,
            Self::Sha512Rsa8192 => 6,
            Self::Unknown(v) => v,
        }
    }

    pub fn hash_len(self) -> usize {
        match self {
            Self::None | Self::Unknown(_) => 0,
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => {
                Sha256::output_size()
            }
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => {
                Sha512::output_size()
            }
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            Self::None | Self::Unknown(_) => 0,
            Self::Sha256Rsa2048 | Self::Sha512Rsa2048 => 256,
            Self::Sha256Rsa4096 | Self::Sha512Rsa4096 => 512,
            Self::Sha256Rsa8192 | Self::Sha512Rsa8192 => 1024,
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Self::None | Self::Unknown(_) => 0,
            Self::Sha256Rsa2048 | Self::Sha512Rsa2048 => 8 + 2 * 2048 / 8,
            Self::Sha256Rsa4096 | Self::Sha512Rsa4096 => 8 + 2 * 4096 / 8,
            Self::Sha256Rsa8192 | Self::Sha512Rsa8192 => 8 + 2 * 8192 / 8,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::None | Self::Unknown(_) => vec![],
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => {
                Sha256::digest(data).to_vec()
            }
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => {
                Sha512::digest(data).to_vec()
            }
        }
    }

    pub fn sign(self, key: &RsaPrivateKey, digest: &[u8]) -> Result<Vec<u8>> {
        let signature = match self {
            Self::None | Self::Unknown(_) => vec![],
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => {
                let scheme = Pkcs1v15Sign::new::<Sha256>();
                key.sign(scheme, digest).map_err(Error::RsaSign)?
            }
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => {
                let scheme = Pkcs1v15Sign::new::<Sha512>();
                key.sign(scheme, digest).map_err(Error::RsaSign)?
            }
        };

        Ok(signature)
    }

    pub fn verify(self, key: &RsaPublicKey, digest: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::None | Self::Unknown(_) => {}
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => {
                let scheme = Pkcs1v15Sign::new::<Sha256>();
                key.verify(scheme, digest, signature)
                    .map_err(Error::RsaVerify)?;
            }
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => {
                let scheme = Pkcs1v15Sign::new::<Sha512>();
                key.verify(scheme, digest, signature)
                    .map_err(Error::RsaVerify)?;
            }
        }

        Ok(())
    }
}

trait DescriptorTag {
    const TAG: u64;

    fn get_tag(&self) -> u64 {
        Self::TAG
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct PropertyDescriptor {
    pub key: String,
    #[serde(with = "escape")]
    pub value: Vec<u8>,
}

impl fmt::Debug for PropertyDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropertyDescriptor")
            .field("key", &self.key)
            .field("value", &self.value.as_bstr())
            .finish()
    }
}

impl DescriptorTag for PropertyDescriptor {
    const TAG: u64 = 0;
}

impl<R: Read> FromReader<R> for PropertyDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let key_size = reader.read_u64::<BigEndian>()?;
        let value_size = reader.read_u64::<BigEndian>()?;

        if key_size > HEADER_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("key_size"));
        } else if value_size > HEADER_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("value_size"));
        }

        let key = reader
            .read_string_exact(key_size as usize)
            .map_err(|e| Error::ReadFieldError("key", e))?;

        let mut null = [0u8; 1];
        reader
            .read_exact(&mut null)
            .map_err(|e| Error::ReadFieldError("key_null", e))?;
        if null[0] != b'\0' {
            return Err(Error::StringNotNullTerminated("key"));
        }

        let mut value = vec![0u8; value_size as usize];
        reader.read_exact(&mut value)?;

        // The non-string value is also null terminated.
        reader
            .read_exact(&mut null)
            .map_err(|e| Error::ReadFieldError("value_null", e))?;
        if null[0] != b'\0' {
            return Err(Error::StringNotNullTerminated("value"));
        }

        Ok(Self { key, value })
    }
}

impl<W: Write> ToWriter<W> for PropertyDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        if self.key.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("key_size"));
        } else if self.value.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("value_size"));
        }

        writer.write_u64::<BigEndian>(self.key.len() as u64)?;
        writer.write_u64::<BigEndian>(self.value.len() as u64)?;
        writer.write_all(self.key.as_bytes())?;
        writer.write_all(b"\0")?;
        writer.write_all(&self.value)?;
        writer.write_all(b"\0")?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct HashTreeDescriptor {
    pub dm_verity_version: u32,
    pub image_size: u64,
    pub tree_offset: u64,
    pub tree_size: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub fec_num_roots: u32,
    pub fec_offset: u64,
    pub fec_size: u64,
    pub hash_algorithm: String,
    pub partition_name: String,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
    #[serde(with = "hex")]
    pub root_digest: Vec<u8>,
    pub flags: u32,
    #[serde(with = "hex")]
    pub reserved: [u8; 60],
}

impl fmt::Debug for HashTreeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashTreeDescriptor")
            .field("dm_verity_version", &self.dm_verity_version)
            .field("image_size", &self.image_size)
            .field("tree_offset", &self.tree_offset)
            .field("tree_size", &self.tree_size)
            .field("data_block_size", &self.data_block_size)
            .field("hash_block_size", &self.hash_block_size)
            .field("fec_num_roots", &self.fec_num_roots)
            .field("fec_offset", &self.fec_offset)
            .field("fec_size", &self.fec_size)
            .field("hash_algorithm", &self.hash_algorithm)
            .field("partition_name", &self.partition_name)
            .field("salt", &hex::encode(&self.salt))
            .field("root_digest", &hex::encode(&self.root_digest))
            .field("flags", &self.flags)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl HashTreeDescriptor {
    pub const FLAG_DO_NOT_USE_AB: u32 = 1 << 0;
    pub const FLAG_CHECK_AT_MOST_ONCE: u32 = 1 << 1;

    /// Calculate the hash tree digests for a single level of the tree. If the
    /// reader's position is block-aligned and `image_size` is a multiple of the
    /// block size, then this function can also be used to calculate the digests
    /// for a portion of a level.
    ///
    /// NOTE: The result is **not** padded to the block size.
    fn hash_one_level(
        mut reader: impl Read,
        mut image_size: u64,
        block_size: u32,
        algorithm: &'static Algorithm,
        salt: &[u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<Vec<u8>> {
        // Each digest must be a power of 2.
        let digest_padding = algorithm.output_len().next_power_of_two() - algorithm.output_len();
        let mut buf = vec![0u8; block_size as usize];
        let mut result = vec![];

        while image_size > 0 {
            stream::check_cancel(cancel_signal)?;

            let n = image_size.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..n])?;

            // For undersized blocks, we still hash the whole buffer, except
            // with padding.
            buf[n..].fill(0);

            let mut context = Context::new(algorithm);
            context.update(salt);
            context.update(&buf);

            // Add the digest to the tree level. Each tree node must be a power
            // of two.
            let digest = context.finish();
            result.extend(digest.as_ref());
            result.resize(result.len() + digest_padding, 0);

            image_size -= n as u64;
        }

        Ok(result)
    }

    /// Calls [`Self::hash_one_level()`] in parallel.
    ///
    /// NOTE: The result is **not** padded to the block size.
    fn hash_one_level_parallel(
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        block_size: u32,
        algorithm: &'static Algorithm,
        salt: &[u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<Vec<u8>> {
        assert!(
            image_size > block_size as u64,
            "Images smaller than block size must use a normal hash",
        );

        // Parallelize in 16 MiB chunks to avoid too much seek thrashing.
        let chunk_size = padding::round(16 * 1024 * 1024, u64::from(block_size)).unwrap();
        let chunk_count = image_size / chunk_size + u64::from(image_size % chunk_size != 0);

        let pieces = (0..chunk_count)
            .into_par_iter()
            .map(|c| -> io::Result<Vec<u8>> {
                let start = c * chunk_size;
                let size = chunk_size.min(image_size - start);

                let mut reader = input.reopen_boxed()?;
                reader.seek(SeekFrom::Start(start))?;

                Self::hash_one_level(reader, size, block_size, algorithm, salt, cancel_signal)
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(pieces.into_iter().flatten().collect())
    }

    /// Calculate the hash tree for the given input in parallel.
    fn calculate_hash_tree(
        input: &(dyn ReadSeekReopen + Sync),
        image_size: u64,
        block_size: u32,
        algorithm: &'static Algorithm,
        salt: &[u8],
        cancel_signal: &AtomicBool,
    ) -> io::Result<(Vec<u8>, Vec<u8>)> {
        // Small files are hashed directly, exactly like a hash descriptor.
        if image_size <= u64::from(block_size) {
            let mut reader = input.reopen_boxed()?;
            let mut buf = vec![0u8; block_size as usize];
            reader.read_exact(&mut buf)?;

            let mut context = Context::new(algorithm);
            context.update(salt);
            context.update(&buf);
            let digest = context.finish();

            return Ok((digest.as_ref().to_vec(), vec![]));
        }

        // Large files use the hash tree.
        let mut levels = Vec::<Vec<u8>>::new();
        let mut level_size = image_size;

        while level_size > u64::from(block_size) {
            let mut level = if let Some(prev_level) = levels.last() {
                // Hash the previous level.
                Self::hash_one_level(
                    Cursor::new(prev_level),
                    level_size,
                    block_size,
                    algorithm,
                    salt,
                    cancel_signal,
                )?
            } else {
                // Initially read from file.
                Self::hash_one_level_parallel(
                    input,
                    level_size,
                    block_size,
                    algorithm,
                    salt,
                    cancel_signal,
                )?
            };

            // Pad to the block size.
            level.resize(padding::round(level.len(), block_size as usize).unwrap(), 0);

            level_size = level.len() as u64;
            levels.push(level);
        }

        // Calculate the root hash.
        let mut context = Context::new(algorithm);
        context.update(salt);
        context.update(levels.last().unwrap());
        let root_hash = context.finish().as_ref().to_vec();

        // The tree is oriented such that the leaves are at the end.
        let hash_tree = levels.into_iter().rev().flatten().collect();

        Ok((root_hash, hash_tree))
    }

    /// Ensure that the image data is immediately followed by the hash tree and
    /// then the FEC data.
    fn check_offsets(&self) -> Result<()> {
        if self.tree_offset != self.image_size {
            return Err(Error::HashTreeGap);
        }

        // The FEC data section is optional.
        if self.fec_num_roots != 0 {
            if self.fec_offset != self.tree_offset + self.tree_size {
                return Err(Error::FecDataGap);
            } else if self.data_block_size != self.hash_block_size {
                return Err(Error::MismatchedFecBlockSizes {
                    data: self.data_block_size,
                    hash: self.hash_block_size,
                });
            }
        }

        Ok(())
    }

    /// Get [`Fec`] instance with the parameters from this descriptor.
    fn get_fec(&self) -> Result<(Fec, usize)> {
        if self.fec_num_roots == 0 {
            return Err(Error::FecMissing);
        } else if self.fec_size > FEC_DATA_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("fec_size"));
        }

        // Fec will check the validity of this field.
        let parity = self
            .fec_num_roots
            .to_u8()
            .ok_or_else(|| Error::FieldOutOfBounds("fec_num_roots"))?;

        // The FEC covers the hash tree as well.
        let fec = Fec::new(
            self.image_size + self.tree_size,
            self.data_block_size,
            parity,
        )?;

        Ok((fec, self.fec_size as usize))
    }

    /// Update the root hash, hash tree, and FEC data. The hash tree and FEC
    /// data will be written immediately following the image data at offset
    /// [`Self::image_size`]. Both `open_input` and `open_output` may be called
    /// from multiple threads and must return independently seekable handles to
    /// the same file. It is guaranteed that every thread will read and write
    /// disjoint file offsets.
    ///
    /// Due to the nature of the file access patterns needed to generate the
    /// hash tree and FEC data, the entire file will be read twice. However, if
    /// [`Self::fec_num_roots`] is 0, no FEC data will be computed nor written.
    ///
    /// The fields in this instance are updated atomically. No fields are
    /// updated if an error occurs. The input file can be restored back to its
    /// original state by truncating it to [`Self::image_size`].
    pub fn update(
        &mut self,
        input: &(dyn ReadSeekReopen + Sync),
        output: &(dyn WriteSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let algorithm = ring_algorithm(&self.hash_algorithm, false)?;
        let (root_digest, hash_tree) = Self::calculate_hash_tree(
            input,
            self.image_size,
            self.data_block_size,
            algorithm,
            &self.salt,
            cancel_signal,
        )?;

        if hash_tree.len() > HASH_TREE_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("tree_size"));
        }

        let tree_size = hash_tree.len() as u64;

        let mut writer = output.reopen_boxed()?;
        writer.seek(SeekFrom::Start(self.image_size))?;
        writer
            .write_all(&hash_tree)
            .map_err(|e| Error::WriteFieldError("hash_tree", e))?;

        // The FEC data section is optional.
        if self.fec_num_roots != 0 {
            if self.data_block_size != self.hash_block_size {
                return Err(Error::MismatchedFecBlockSizes {
                    data: self.data_block_size,
                    hash: self.hash_block_size,
                });
            }

            let parity = self
                .fec_num_roots
                .to_u8()
                .ok_or_else(|| Error::FieldOutOfBounds("fec_num_roots"))?;

            // The FEC covers the hash tree as well.
            let fec = Fec::new(self.image_size + tree_size, self.data_block_size, parity)?;

            let fec_data = fec.generate(input, cancel_signal)?;
            let fec_size = fec_data
                .len()
                .to_u64()
                .ok_or_else(|| Error::FieldOutOfBounds("fec_size"))?;

            // Already seeked to FEC.
            writer
                .write_all(&fec_data)
                .map_err(|e| Error::WriteFieldError("fec_data", e))?;

            self.fec_offset = self.image_size + tree_size;
            self.fec_size = fec_size;
        }

        self.tree_offset = self.image_size;
        self.tree_size = tree_size;
        self.root_digest = root_digest;

        Ok(())
    }

    /// Verify the root hash, hash tree, and FEC data. `open_input` will be
    /// called from multiple threads and must return independently seekable
    /// handles to the same file.
    pub fn verify(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        self.check_offsets()?;

        let algorithm = ring_algorithm(&self.hash_algorithm, true)?;

        if self.tree_size > HASH_TREE_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("tree_size"));
        }

        let (actual_root_digest, actual_hash_tree) = Self::calculate_hash_tree(
            input,
            self.image_size,
            self.data_block_size,
            algorithm,
            &self.salt,
            cancel_signal,
        )?;

        if self.root_digest != actual_root_digest {
            return Err(Error::InvalidRootDigest {
                expected: hex::encode(&self.root_digest),
                actual: hex::encode(actual_root_digest),
            });
        }

        let mut reader = input.reopen_boxed()?;
        reader.seek(SeekFrom::Start(self.tree_offset))?;

        let mut hash_tree = vec![0u8; self.tree_size as usize];
        reader
            .read_exact(&mut hash_tree)
            .map_err(|e| Error::ReadFieldError("hash_tree", e))?;

        if hash_tree != actual_hash_tree {
            // These are multiple megabytes, so only report the hashes.
            let expected = ring::digest::digest(algorithm, &hash_tree);
            let actual = ring::digest::digest(algorithm, &actual_hash_tree);

            return Err(Error::InvalidHashTree {
                expected: hex::encode(expected),
                actual: hex::encode(actual),
            });
        }

        // The FEC data section is optional.
        if self.fec_num_roots != 0 {
            let (fec, fec_size) = self.get_fec()?;

            let mut fec_data = vec![0u8; fec_size];
            // Already seeked to FEC.
            reader
                .read_exact(&mut fec_data)
                .map_err(|e| Error::ReadFieldError("fec_data", e))?;

            fec.verify(input, &fec_data, cancel_signal)?;
        }

        Ok(())
    }

    /// Try to repair errors in the input file using the FEC data. Both
    /// `open_input` and `open_output` may be called from multiple threads and
    /// must return independently seekable handles to the same file.
    ///
    /// Due to the nature of FEC, when there are too many errors, it's possible
    /// for the data to be miscorrected to a "valid" state. [`Self::verify()`]
    /// should be called after the repair is complete to ensure that the data is
    /// actually valid.
    pub fn repair(
        &self,
        input: &(dyn ReadSeekReopen + Sync),
        output: &(dyn WriteSeekReopen + Sync),
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        self.check_offsets()?;

        // The FEC data section is optional.
        if self.fec_size == 0 {
            return Err(Error::FecMissing);
        }

        let mut reader = input.reopen_boxed()?;
        reader.seek(SeekFrom::Start(self.fec_offset))?;

        let (fec, fec_size) = self.get_fec()?;

        let mut fec_data = vec![0u8; fec_size];
        // Already seeked to FEC.
        reader
            .read_exact(&mut fec_data)
            .map_err(|e| Error::ReadFieldError("fec_data", e))?;

        fec.repair(input, output, &fec_data, cancel_signal)?;

        Ok(())
    }
}

impl DescriptorTag for HashTreeDescriptor {
    const TAG: u64 = 1;
}

impl<R: Read> FromReader<R> for HashTreeDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let dm_verity_version = reader.read_u32::<BigEndian>()?;
        let image_size = reader.read_u64::<BigEndian>()?;
        let tree_offset = reader.read_u64::<BigEndian>()?;
        let tree_size = reader.read_u64::<BigEndian>()?;
        let data_block_size = reader.read_u32::<BigEndian>()?;
        let hash_block_size = reader.read_u32::<BigEndian>()?;
        let fec_num_roots = reader.read_u32::<BigEndian>()?;
        let fec_offset = reader.read_u64::<BigEndian>()?;
        let fec_size = reader.read_u64::<BigEndian>()?;

        let hash_algorithm = reader
            .read_string_padded(32)
            .map_err(|e| Error::ReadFieldError("hash_algorithm", e))?;
        if !hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii("hash_algorithm", hash_algorithm));
        }

        let partition_name_len = reader.read_u32::<BigEndian>()?;
        let salt_len = reader.read_u32::<BigEndian>()?;
        let root_digest_len = reader.read_u32::<BigEndian>()?;
        let flags = reader.read_u32::<BigEndian>()?;

        if partition_name_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if salt_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("salt_len"));
        } else if root_digest_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("root_digest_len"));
        }

        let mut reserved = [0u8; 60];
        reader.read_exact(&mut reserved)?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_string_exact(partition_name_len as usize)
            .map_err(|e| Error::ReadFieldError("partition_name", e))?;

        let mut salt = vec![0u8; salt_len as usize];
        reader.read_exact(&mut salt)?;

        let mut root_digest = vec![0u8; root_digest_len as usize];
        reader.read_exact(&mut root_digest)?;

        let descriptor = Self {
            dm_verity_version,
            image_size,
            tree_offset,
            tree_size,
            data_block_size,
            hash_block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            flags,
            reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for HashTreeDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        if self.partition_name.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if self.salt.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("salt_len"));
        } else if self.root_digest.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("root_digest_len"));
        }

        writer.write_u32::<BigEndian>(self.dm_verity_version)?;
        writer.write_u64::<BigEndian>(self.image_size)?;
        writer.write_u64::<BigEndian>(self.tree_offset)?;
        writer.write_u64::<BigEndian>(self.tree_size)?;
        writer.write_u32::<BigEndian>(self.data_block_size)?;
        writer.write_u32::<BigEndian>(self.hash_block_size)?;
        writer.write_u32::<BigEndian>(self.fec_num_roots)?;
        writer.write_u64::<BigEndian>(self.fec_offset)?;
        writer.write_u64::<BigEndian>(self.fec_size)?;

        if !self.hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "hash_algorithm",
                self.hash_algorithm.clone(),
            ));
        }
        writer
            .write_string_padded(&self.hash_algorithm, 32)
            .map_err(|e| Error::WriteFieldError("hash_algorithm", e))?;

        writer.write_u32::<BigEndian>(self.partition_name.len() as u32)?;
        writer.write_u32::<BigEndian>(self.salt.len() as u32)?;
        writer.write_u32::<BigEndian>(self.root_digest.len() as u32)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_all(&self.reserved)?;
        writer.write_all(self.partition_name.as_bytes())?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.root_digest)?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct HashDescriptor {
    pub image_size: u64,
    pub hash_algorithm: String,
    pub partition_name: String,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
    #[serde(with = "hex")]
    pub root_digest: Vec<u8>,
    pub flags: u32,
    #[serde(with = "hex")]
    pub reserved: [u8; 60],
}

impl fmt::Debug for HashDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashDescriptor")
            .field("image_size", &self.image_size)
            .field("hash_algorithm", &self.hash_algorithm)
            .field("partition_name", &self.partition_name)
            .field("salt", &hex::encode(&self.salt))
            .field("root_digest", &hex::encode(&self.root_digest))
            .field("flags", &self.flags)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl HashDescriptor {
    fn calculate(
        &self,
        reader: impl Read,
        for_verify: bool,
        cancel_signal: &AtomicBool,
    ) -> Result<ring::digest::Digest> {
        let algorithm = ring_algorithm(&self.hash_algorithm, for_verify)?;
        let mut context = Context::new(algorithm);
        context.update(&self.salt);

        stream::copy_n_inspect(
            reader,
            io::sink(),
            self.image_size,
            |data| context.update(data),
            cancel_signal,
        )?;

        Ok(context.finish())
    }

    /// Update the root hash from the input reader's contents.
    pub fn update(&mut self, reader: impl Read, cancel_signal: &AtomicBool) -> Result<()> {
        let digest = self.calculate(reader, false, cancel_signal)?;
        self.root_digest = digest.as_ref().to_vec();
        Ok(())
    }

    /// Verify the root hash against the input reader.
    pub fn verify(&self, reader: impl Read, cancel_signal: &AtomicBool) -> Result<()> {
        let digest = self.calculate(reader, true, cancel_signal)?;

        if self.root_digest != digest.as_ref() {
            return Err(Error::InvalidRootDigest {
                expected: hex::encode(&self.root_digest),
                actual: hex::encode(digest),
            });
        }

        Ok(())
    }
}

impl DescriptorTag for HashDescriptor {
    const TAG: u64 = 2;
}

impl<R: Read> FromReader<R> for HashDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let image_size = reader.read_u64::<BigEndian>()?;

        let hash_algorithm = reader
            .read_string_padded(32)
            .map_err(|e| Error::ReadFieldError("hash_algorithm", e))?;
        if !hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii("hash_algorithm", hash_algorithm));
        }

        let partition_name_len = reader.read_u32::<BigEndian>()?;
        let salt_len = reader.read_u32::<BigEndian>()?;
        let root_digest_len = reader.read_u32::<BigEndian>()?;
        let flags = reader.read_u32::<BigEndian>()?;

        if partition_name_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if salt_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("salt_len"));
        } else if root_digest_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("root_digest_len"));
        }

        let mut reserved = [0u8; 60];
        reader.read_exact(&mut reserved)?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_string_exact(partition_name_len as usize)
            .map_err(|e| Error::ReadFieldError("partition_name", e))?;

        let mut salt = vec![0u8; salt_len as usize];
        reader.read_exact(&mut salt)?;

        let mut root_digest = vec![0u8; root_digest_len as usize];
        reader.read_exact(&mut root_digest)?;

        let descriptor = Self {
            image_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            flags,
            reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for HashDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        if self.partition_name.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if self.salt.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("salt_len"));
        } else if self.root_digest.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("root_digest_len"));
        }

        writer.write_u64::<BigEndian>(self.image_size)?;

        if !self.hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "hash_algorithm",
                self.hash_algorithm.clone(),
            ));
        }
        writer
            .write_string_padded(&self.hash_algorithm, 32)
            .map_err(|e| Error::WriteFieldError("hash_algorithm", e))?;

        writer.write_u32::<BigEndian>(self.partition_name.len() as u32)?;
        writer.write_u32::<BigEndian>(self.salt.len() as u32)?;
        writer.write_u32::<BigEndian>(self.root_digest.len() as u32)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_all(&self.reserved)?;
        writer.write_all(self.partition_name.as_bytes())?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.root_digest)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct KernelCmdlineDescriptor {
    pub flags: u32,
    pub cmdline: String,
}

impl KernelCmdlineDescriptor {
    pub const FLAG_USE_ONLY_IF_HASHTREE_NOT_DISABLED: u32 = 1 << 0;
    pub const FLAG_USE_ONLY_IF_HASHTREE_DISABLED: u32 = 1 << 1;
}

impl DescriptorTag for KernelCmdlineDescriptor {
    const TAG: u64 = 3;
}

impl<R: Read> FromReader<R> for KernelCmdlineDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let flags = reader.read_u32::<BigEndian>()?;
        let cmdline_len = reader.read_u32::<BigEndian>()?;

        if cmdline_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("cmdline_len"));
        }

        // Not NULL-terminated.
        let cmdline = reader
            .read_string_exact(cmdline_len as usize)
            .map_err(|e| Error::ReadFieldError("cmdline", e))?;

        let descriptor = Self { flags, cmdline };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for KernelCmdlineDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        if self.cmdline.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("cmdline_len"));
        }

        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_u32::<BigEndian>(self.cmdline.len() as u32)?;
        writer.write_all(self.cmdline.as_bytes())?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChainPartitionDescriptor {
    pub rollback_index_location: u32,
    pub partition_name: String,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    pub flags: u32,
    #[serde(with = "hex")]
    pub reserved: [u8; 60],
}

impl ChainPartitionDescriptor {
    pub const FLAG_DO_NOT_USE_AB: u32 = 1 << 0;
}

impl fmt::Debug for ChainPartitionDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainPartitionDescriptor")
            .field("rollback_index_location", &self.rollback_index_location)
            .field("partition_name", &self.partition_name)
            .field("public_key", &hex::encode(&self.public_key))
            .field("flags", &self.flags)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl DescriptorTag for ChainPartitionDescriptor {
    const TAG: u64 = 4;
}

impl<R: Read> FromReader<R> for ChainPartitionDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let rollback_index_location = reader.read_u32::<BigEndian>()?;
        let partition_name_len = reader.read_u32::<BigEndian>()?;
        let public_key_len = reader.read_u32::<BigEndian>()?;

        if partition_name_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if public_key_len > HEADER_MAX_SIZE as u32 {
            return Err(Error::FieldOutOfBounds("public_key_len"));
        }

        let flags = reader.read_u32::<BigEndian>()?;

        let mut reserved = [0u8; 60];
        reader.read_exact(&mut reserved)?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_string_padded(partition_name_len as usize)
            .map_err(|e| Error::ReadFieldError("partition_name", e))?;

        let mut public_key = vec![0u8; public_key_len as usize];
        reader.read_exact(&mut public_key)?;

        let descriptor = Self {
            rollback_index_location,
            partition_name,
            public_key,
            flags,
            reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for ChainPartitionDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        if self.partition_name.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("partition_name_len"));
        } else if self.public_key.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("public_key_len"));
        }

        writer.write_u32::<BigEndian>(self.rollback_index_location)?;
        writer.write_u32::<BigEndian>(self.partition_name.len() as u32)?;
        writer.write_u32::<BigEndian>(self.public_key.len() as u32)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_all(&self.reserved)?;
        writer.write_all(self.partition_name.as_bytes())?;
        writer.write_all(&self.public_key)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Descriptor {
    Property(PropertyDescriptor),
    HashTree(HashTreeDescriptor),
    Hash(HashDescriptor),
    KernelCmdline(KernelCmdlineDescriptor),
    ChainPartition(ChainPartitionDescriptor),
    Unknown {
        tag: u64,
        #[serde(with = "hex")]
        data: Vec<u8>,
    },
}

impl Descriptor {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Property(_) => "Property",
            Self::HashTree(_) => "HashTree",
            Self::Hash(_) => "Hash",
            Self::KernelCmdline(_) => "KernelCmdline",
            Self::ChainPartition(_) => "ChainPartition",
            Self::Unknown { .. } => "Unknown",
        }
    }

    pub fn partition_name(&self) -> Option<&str> {
        match self {
            Self::HashTree(d) => Some(&d.partition_name),
            Self::Hash(d) => Some(&d.partition_name),
            Self::ChainPartition(d) => Some(&d.partition_name),
            _ => None,
        }
    }
}

impl<R: Read> FromReader<R> for Descriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let tag = reader.read_u64::<BigEndian>()?;
        let nbf = reader.read_u64::<BigEndian>()?;

        if nbf > HEADER_MAX_SIZE {
            return Err(Error::FieldOutOfBounds("num_bytes_following"));
        }

        let mut inner_reader = CountingReader::new(reader.take(nbf));

        let descriptor = match tag {
            PropertyDescriptor::TAG => {
                let d = PropertyDescriptor::from_reader(&mut inner_reader)?;
                Self::Property(d)
            }
            HashTreeDescriptor::TAG => {
                let d = HashTreeDescriptor::from_reader(&mut inner_reader)?;
                Self::HashTree(d)
            }
            HashDescriptor::TAG => {
                let d = HashDescriptor::from_reader(&mut inner_reader)?;
                Self::Hash(d)
            }
            KernelCmdlineDescriptor::TAG => {
                let d = KernelCmdlineDescriptor::from_reader(&mut inner_reader)?;
                Self::KernelCmdline(d)
            }
            ChainPartitionDescriptor::TAG => {
                let d = ChainPartitionDescriptor::from_reader(&mut inner_reader)?;
                Self::ChainPartition(d)
            }
            _ => {
                let mut data = vec![0u8; nbf as usize];
                inner_reader.read_exact(&mut data)?;

                Self::Unknown { tag, data }
            }
        };

        // The descriptor data is always aligned to 8 bytes.
        padding::read_discard(&mut inner_reader, 8)?;
        if inner_reader.stream_position()? != nbf {
            return Err(Error::PaddingTooLong);
        }

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for Descriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        let mut inner_writer = Cursor::new(Vec::new());

        let tag = match self {
            Self::Property(d) => {
                d.to_writer(&mut inner_writer)?;
                d.get_tag()
            }
            Self::HashTree(d) => {
                d.to_writer(&mut inner_writer)?;
                d.get_tag()
            }
            Self::Hash(d) => {
                d.to_writer(&mut inner_writer)?;
                d.get_tag()
            }
            Self::KernelCmdline(d) => {
                d.to_writer(&mut inner_writer)?;
                d.get_tag()
            }
            Self::ChainPartition(d) => {
                d.to_writer(&mut inner_writer)?;
                d.get_tag()
            }
            Self::Unknown { tag, data } => {
                inner_writer.write_all(data)?;
                *tag
            }
        };

        let inner_data = inner_writer.into_inner();

        if inner_data.len() > HEADER_MAX_SIZE as usize {
            return Err(Error::FieldOutOfBounds("num_bytes_following"));
        }

        let padding_len = padding::calc(inner_data.len(), 8);
        let nbf = inner_data.len() + padding_len;

        writer.write_u64::<BigEndian>(tag)?;
        writer.write_u64::<BigEndian>(nbf as u64)?;
        writer.write_all(&inner_data)?;
        writer.write_zeros_exact(padding_len as u64)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendedDescriptorRef<'a> {
    HashTree(&'a HashTreeDescriptor),
    Hash(&'a HashDescriptor),
}

impl<'a> TryFrom<&'a Descriptor> for AppendedDescriptorRef<'a> {
    type Error = Error;

    fn try_from(value: &'a Descriptor) -> Result<Self> {
        match value {
            Descriptor::HashTree(d) => Ok(Self::HashTree(d)),
            Descriptor::Hash(d) => Ok(Self::Hash(d)),
            _ => Err(Error::NoAppendedDescriptor),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum AppendedDescriptorMut<'a> {
    HashTree(&'a mut HashTreeDescriptor),
    Hash(&'a mut HashDescriptor),
}

impl<'a> TryFrom<&'a mut Descriptor> for AppendedDescriptorMut<'a> {
    type Error = Error;

    fn try_from(value: &'a mut Descriptor) -> Result<Self> {
        match value {
            Descriptor::HashTree(d) => Ok(Self::HashTree(d)),
            Descriptor::Hash(d) => Ok(Self::Hash(d)),
            _ => Err(Error::NoAppendedDescriptor),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Header {
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub algorithm_type: AlgorithmType,
    #[serde(with = "hex")]
    pub hash: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex")]
    pub public_key_metadata: Vec<u8>,
    pub descriptors: Vec<Descriptor>,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release_string: String,
    #[serde(with = "hex")]
    pub reserved: [u8; 80],
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field(
                "required_libavb_version_major",
                &self.required_libavb_version_major,
            )
            .field(
                "required_libavb_version_minor",
                &self.required_libavb_version_minor,
            )
            .field("algorithm_type", &self.algorithm_type)
            .field("hash", &hex::encode(&self.hash))
            .field("signature", &hex::encode(&self.signature))
            .field("public_key", &hex::encode(&self.public_key))
            .field(
                "public_key_metadata",
                &hex::encode(&self.public_key_metadata),
            )
            .field("descriptors", &self.descriptors)
            .field("rollback_index", &self.rollback_index)
            .field("flags", &self.flags)
            .field("rollback_index_location", &self.rollback_index_location)
            .field("release_string", &self.release_string)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl Header {
    pub const SIZE: usize = 256;

    fn to_writer_internal(&self, mut writer: impl Write, skip_auth_block: bool) -> Result<()> {
        let mut descriptors_writer = Cursor::new(Vec::new());
        for d in &self.descriptors {
            d.to_writer(&mut descriptors_writer)?;
        }
        let descriptors_raw = descriptors_writer.into_inner();

        // Auth block.

        let auth_block_data_size = self
            .hash
            .len()
            .checked_add(self.signature.len())
            .ok_or_else(|| Error::FieldOutOfBounds("auth_block_data_size"))?;
        let auth_block_padding_size = padding::calc(auth_block_data_size, 64);
        let auth_block_size = auth_block_data_size
            .checked_add(auth_block_padding_size)
            .ok_or_else(|| Error::FieldOutOfBounds("auth_block_size"))?;

        let hash_offset = 0usize;
        let signature_offset = hash_offset + self.hash.len();

        // Aux block.

        let aux_block_data_size = descriptors_raw
            .len()
            .checked_add(self.public_key.len())
            .and_then(|s| s.checked_add(self.public_key_metadata.len()))
            .ok_or_else(|| Error::FieldOutOfBounds("aux_block_data_size"))?;
        let aux_block_padding_size = padding::calc(aux_block_data_size, 64);
        let aux_block_size = aux_block_data_size
            .checked_add(aux_block_padding_size)
            .ok_or_else(|| Error::FieldOutOfBounds("aux_block_size"))?;

        let descriptors_offset = 0usize;
        let public_key_offset = descriptors_offset + descriptors_raw.len();
        let public_key_metadata_offset = public_key_offset + self.public_key.len();

        let total_size = Self::SIZE
            .checked_add(auth_block_data_size)
            .and_then(|s| s.checked_add(aux_block_data_size))
            .ok_or_else(|| Error::FieldOutOfBounds("total_size"))?;
        if total_size > HEADER_MAX_SIZE as usize {
            return Err(Error::HeaderTooLarge);
        }

        // All sizes and offsets are now guaranteed to fit in a u64.

        writer.write_all(&HEADER_MAGIC)?;
        writer.write_u32::<BigEndian>(self.required_libavb_version_major)?;
        writer.write_u32::<BigEndian>(self.required_libavb_version_minor)?;
        writer.write_u64::<BigEndian>(auth_block_size as u64)?;
        writer.write_u64::<BigEndian>(aux_block_size as u64)?;
        writer.write_u32::<BigEndian>(self.algorithm_type.to_raw())?;
        writer.write_u64::<BigEndian>(hash_offset as u64)?;
        writer.write_u64::<BigEndian>(self.hash.len() as u64)?;
        writer.write_u64::<BigEndian>(signature_offset as u64)?;
        writer.write_u64::<BigEndian>(self.signature.len() as u64)?;
        writer.write_u64::<BigEndian>(public_key_offset as u64)?;
        writer.write_u64::<BigEndian>(self.public_key.len() as u64)?;
        writer.write_u64::<BigEndian>(public_key_metadata_offset as u64)?;
        writer.write_u64::<BigEndian>(self.public_key_metadata.len() as u64)?;
        writer.write_u64::<BigEndian>(descriptors_offset as u64)?;
        writer.write_u64::<BigEndian>(descriptors_raw.len() as u64)?;
        writer.write_u64::<BigEndian>(self.rollback_index)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        writer.write_u32::<BigEndian>(self.rollback_index_location)?;

        writer
            .write_string_padded(&self.release_string, 48)
            .map_err(|e| Error::WriteFieldError("release_string", e))?;

        writer.write_all(&self.reserved)?;

        // Auth block.
        if !skip_auth_block {
            writer.write_all(&self.hash)?;
            writer.write_all(&self.signature)?;
            writer.write_zeros_exact(auth_block_padding_size as u64)?;
        }

        // Aux block.
        writer.write_all(&descriptors_raw)?;
        writer.write_all(&self.public_key)?;
        writer.write_all(&self.public_key_metadata)?;
        writer.write_zeros_exact(aux_block_padding_size as u64)?;

        Ok(())
    }

    /// Get the first hash or hash tree descriptor if there is only one. This is
    /// the case for appended AVB images.
    pub fn appended_descriptor(&self) -> Result<AppendedDescriptorRef> {
        let mut result = None;

        for descriptor in &self.descriptors {
            match descriptor {
                Descriptor::HashTree(d) => {
                    if result.is_some() {
                        return Err(Error::NoAppendedDescriptor);
                    }
                    result = Some(AppendedDescriptorRef::HashTree(d));
                }
                Descriptor::Hash(d) => {
                    if result.is_some() {
                        return Err(Error::NoAppendedDescriptor);
                    }
                    result = Some(AppendedDescriptorRef::Hash(d));
                }
                _ => {}
            }
        }

        result.ok_or(Error::NoAppendedDescriptor)
    }

    /// Get the first hash or hash tree descriptor if there is only one. This is
    /// the case for appended AVB images.
    pub fn appended_descriptor_mut(&mut self) -> Result<AppendedDescriptorMut> {
        let mut result = None;

        for descriptor in &mut self.descriptors {
            match descriptor {
                Descriptor::HashTree(d) => {
                    if result.is_some() {
                        return Err(Error::NoAppendedDescriptor);
                    }
                    result = Some(AppendedDescriptorMut::HashTree(d));
                }
                Descriptor::Hash(d) => {
                    if result.is_some() {
                        return Err(Error::NoAppendedDescriptor);
                    }
                    result = Some(AppendedDescriptorMut::Hash(d));
                }
                _ => {}
            }
        }

        result.ok_or(Error::NoAppendedDescriptor)
    }

    pub fn set_algo_for_key(&mut self, key: &RsaPrivateKey) -> Result<()> {
        let key_raw = encode_public_key(&key.to_public_key())?;

        for algo in [AlgorithmType::Sha256Rsa2048, AlgorithmType::Sha256Rsa4096] {
            if key_raw.len() == algo.public_key_len() {
                self.algorithm_type = algo;
                return Ok(());
            }
        }

        Err(Error::UnsupportedKey(key.size()))
    }

    pub fn clear_sig(&mut self) {
        self.hash.clear();
        self.signature.clear();
        self.public_key.clear();
        self.public_key_metadata.clear();
    }

    pub fn sign(&mut self, key: &RsaPrivateKey) -> Result<()> {
        let key_raw = encode_public_key(&key.to_public_key())?;

        // RustCrypto does not support 8192-bit keys.
        match self.algorithm_type {
            AlgorithmType::Sha256Rsa8192
            | AlgorithmType::Sha512Rsa8192
            | AlgorithmType::Unknown(_) => {
                return Err(Error::UnsupportedAlgorithm(self.algorithm_type));
            }
            _ => {}
        }

        if key_raw.len() != self.algorithm_type.public_key_len() {
            return Err(Error::IncorrectKeySize {
                key_size: key_raw.len(),
                algo: self.algorithm_type,
            });
        }

        // The public key and the sizes of the hash and signature are included
        // in the data that's about to be signed.
        self.public_key = key_raw;
        self.hash.resize(self.algorithm_type.hash_len(), 0);
        self.signature
            .resize(self.algorithm_type.signature_len(), 0);

        let mut without_auth_writer = Cursor::new(Vec::new());
        self.to_writer_internal(&mut without_auth_writer, true)?;
        let without_auth = without_auth_writer.into_inner();

        let hash = self.algorithm_type.hash(&without_auth);
        let signature = self.algorithm_type.sign(key, &hash)?;

        self.hash = hash;
        self.signature = signature;

        Ok(())
    }

    /// Verify the header's digest and signature against the embedded public key
    /// and return the public key. If the header is not signed, then `None` is
    /// returned.
    pub fn verify(&self) -> Result<Option<RsaPublicKey>> {
        // RustCrypto does not support 8192-bit keys.
        match self.algorithm_type {
            AlgorithmType::None => return Ok(None),
            a @ AlgorithmType::Sha256Rsa8192
            | a @ AlgorithmType::Sha512Rsa8192
            | a @ AlgorithmType::Unknown(_) => return Err(Error::UnsupportedAlgorithm(a)),
            _ => {}
        }

        // Reconstruct the public key.
        let public_key = decode_public_key(&self.public_key)?;

        let mut without_auth_writer = Cursor::new(Vec::new());
        self.to_writer_internal(&mut without_auth_writer, true)?;
        let without_auth = without_auth_writer.into_inner();

        let hash = self.algorithm_type.hash(&without_auth);
        self.algorithm_type
            .verify(&public_key, &hash, &self.signature)?;

        Ok(Some(public_key))
    }
}

impl<R: Read> FromReader<R> for Header {
    type Error = Error;

    fn from_reader(reader: R) -> Result<Self> {
        let mut reader = CountingReader::new(reader);

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if magic != HEADER_MAGIC {
            return Err(Error::InvalidHeaderMagic(magic));
        }

        let required_libavb_version_major = reader.read_u32::<BigEndian>()?;
        let required_libavb_version_minor = reader.read_u32::<BigEndian>()?;
        let auth_block_size = reader.read_u64::<BigEndian>()?;
        let aux_block_size = reader.read_u64::<BigEndian>()?;

        let algorithm_type_raw = reader.read_u32::<BigEndian>()?;
        let algorithm_type = AlgorithmType::from_raw(algorithm_type_raw);

        let hash_offset = reader.read_u64::<BigEndian>()?;
        let hash_size = reader.read_u64::<BigEndian>()?;
        let signature_offset = reader.read_u64::<BigEndian>()?;
        let signature_size = reader.read_u64::<BigEndian>()?;

        let auth_block_combined = hash_size
            .checked_add(signature_size)
            .ok_or_else(|| Error::FieldOutOfBounds("auth_block_combined"))?;
        let auth_block_padding = padding::calc(auth_block_combined, 64);
        if auth_block_combined.checked_add(auth_block_padding) != Some(auth_block_size) {
            return Err(Error::FieldOutOfBounds("auth_block_size"));
        } else if hash_offset > auth_block_combined - hash_size {
            return Err(Error::FieldOutOfBounds("hash_offset"));
        } else if signature_offset > auth_block_combined - signature_size {
            return Err(Error::FieldOutOfBounds("signature_offset"));
        }

        let public_key_offset = reader.read_u64::<BigEndian>()?;
        let public_key_size = reader.read_u64::<BigEndian>()?;
        let public_key_metadata_offset = reader.read_u64::<BigEndian>()?;
        let public_key_metadata_size = reader.read_u64::<BigEndian>()?;
        let descriptors_offset = reader.read_u64::<BigEndian>()?;
        let descriptors_size = reader.read_u64::<BigEndian>()?;

        let aux_block_combined = public_key_size
            .checked_add(public_key_metadata_size)
            .and_then(|s| s.checked_add(descriptors_size))
            .ok_or_else(|| Error::FieldOutOfBounds("aux_block_combined"))?;
        let aux_block_padding = padding::calc(aux_block_combined, 64);
        if aux_block_combined.checked_add(aux_block_padding) != Some(aux_block_size) {
            return Err(Error::FieldOutOfBounds("aux_block_size"));
        } else if public_key_offset > aux_block_combined - public_key_size {
            return Err(Error::FieldOutOfBounds("public_key_offset"));
        } else if public_key_metadata_offset > aux_block_combined - public_key_metadata_size {
            return Err(Error::FieldOutOfBounds("public_key_metadata_size"));
        } else if descriptors_offset > aux_block_combined - descriptors_size {
            return Err(Error::FieldOutOfBounds("descriptors_offset"));
        }

        let rollback_index = reader.read_u64::<BigEndian>()?;
        let flags = reader.read_u32::<BigEndian>()?;
        let rollback_index_location = reader.read_u32::<BigEndian>()?;

        let release_string = reader
            .read_string_padded(48)
            .map_err(|e| Error::ReadFieldError("release_string", e))?;

        let mut reserved = [0u8; 80];
        reader.read_exact(&mut reserved)?;

        let header_size = reader.stream_position()?;
        let total_size = header_size
            .checked_add(auth_block_size)
            .and_then(|v| v.checked_add(aux_block_size))
            .ok_or_else(|| Error::FieldOutOfBounds("total_size"))?;
        if total_size > HEADER_MAX_SIZE {
            return Err(Error::HeaderTooLarge);
        }

        // All of the size fields above are now guaranteed to fit in usize.

        let mut auth_block = vec![0u8; auth_block_size as usize];
        reader.read_exact(&mut auth_block)?;

        let mut aux_block = vec![0u8; aux_block_size as usize];
        reader.read_exact(&mut aux_block)?;

        // When we verify() the signatures, we're doing so on re-serialized
        // fields. The padding is the only thing that can escape this, so make
        // sure they don't contain any data.
        if !util::is_zero(
            &auth_block[auth_block_combined as usize..][..auth_block_padding as usize],
        ) {
            return Err(Error::PaddingNotZero("auth_block"));
        }
        if !util::is_zero(&aux_block[aux_block_combined as usize..][..aux_block_padding as usize]) {
            return Err(Error::PaddingNotZero("aux_block"));
        }

        // Auth block data.
        let hash = &auth_block[hash_offset as usize..][..hash_size as usize];
        let signature = &auth_block[signature_offset as usize..][..signature_size as usize];

        // Aux block data.
        let public_key = &aux_block[public_key_offset as usize..][..public_key_size as usize];
        let public_key_metadata =
            &aux_block[public_key_metadata_offset as usize..][..public_key_metadata_size as usize];

        let mut descriptors: Vec<Descriptor> = vec![];
        let mut descriptor_reader = Cursor::new(&aux_block);
        let mut pos = descriptor_reader.seek(SeekFrom::Start(descriptors_offset))?;

        while pos < descriptors_offset + descriptors_size {
            let descriptor = Descriptor::from_reader(&mut descriptor_reader)?;
            descriptors.push(descriptor);
            pos = descriptor_reader.stream_position()?;
        }

        let header = Self {
            required_libavb_version_major,
            required_libavb_version_minor,
            algorithm_type,
            hash: hash.to_owned(),
            signature: signature.to_owned(),
            public_key: public_key.to_owned(),
            public_key_metadata: public_key_metadata.to_owned(),
            descriptors,
            rollback_index,
            flags,
            rollback_index_location,
            release_string,
            reserved,
        };

        Ok(header)
    }
}

impl<W: Write> ToWriter<W> for Header {
    type Error = Error;

    fn to_writer(&self, writer: W) -> Result<()> {
        self.to_writer_internal(writer, false)
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Footer {
    pub version_major: u32,
    pub version_minor: u32,
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
    #[serde(with = "hex")]
    pub reserved: [u8; 28],
}

impl fmt::Debug for Footer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Footer")
            .field("version_major", &self.version_major)
            .field("version_minor", &self.version_minor)
            .field("original_image_size", &self.original_image_size)
            .field("vbmeta_offset", &self.vbmeta_offset)
            .field("vbmeta_size", &self.vbmeta_size)
            .field("reserved", &hex::encode(self.reserved))
            .finish()
    }
}

impl Footer {
    pub const SIZE: usize = 64;
}

impl<R: Read> FromReader<R> for Footer {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if magic != FOOTER_MAGIC {
            return Err(Error::InvalidFooterMagic(magic));
        }

        let version_major = reader.read_u32::<BigEndian>()?;
        let version_minor = reader.read_u32::<BigEndian>()?;
        let original_image_size = reader.read_u64::<BigEndian>()?;
        let vbmeta_offset = reader.read_u64::<BigEndian>()?;
        let vbmeta_size = reader.read_u64::<BigEndian>()?;

        let mut reserved = [0u8; 28];
        reader.read_exact(&mut reserved)?;

        let footer = Self {
            version_major,
            version_minor,
            original_image_size,
            vbmeta_offset,
            vbmeta_size,
            reserved,
        };

        Ok(footer)
    }
}

impl<W: Write> ToWriter<W> for Footer {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        writer.write_all(&FOOTER_MAGIC)?;
        writer.write_u32::<BigEndian>(self.version_major)?;
        writer.write_u32::<BigEndian>(self.version_minor)?;
        writer.write_u64::<BigEndian>(self.original_image_size)?;
        writer.write_u64::<BigEndian>(self.vbmeta_offset)?;
        writer.write_u64::<BigEndian>(self.vbmeta_size)?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }
}

/// Encode a public key in the AVB binary format.
pub fn encode_public_key(key: &RsaPublicKey) -> Result<Vec<u8>> {
    if key.e() != &BigUint::from(65537u32) {
        return Err(Error::UnsupportedRsaPublicExponent(key.e().clone()));
    }

    // libavb expects certain values to be precomputed so that the bootloader's
    // verification operations can run faster.
    //
    // Values:
    //   n0inv = -1 / n[0] (mod 2 ^ 32)
    //     - Guaranteed to fit in a u32
    //   r = 2 ^ (key size in bits)
    //   rr = r^2 (mod N)
    //     - Guaranteed to fit in key size bits

    let b = BigUint::from(2u64.pow(32));
    let n0inv = b.to_bigint().unwrap() - key.n().mod_inverse(&b).unwrap();
    let r = BigUint::from(2u32).pow(key.n().bits());
    let rrmodn = r.modpow(&BigUint::from(2u32), key.n());

    let key_bits = (key.size() * 8).to_u32().unwrap();

    let mut data = vec![];
    data.extend_from_slice(&key_bits.to_be_bytes());
    data.extend_from_slice(&n0inv.to_u32().unwrap().to_be_bytes());

    let modulus_raw = key.n().to_bytes_be();
    data.resize(data.len() + key.size() - modulus_raw.len(), 0);
    data.extend_from_slice(&modulus_raw);

    let rrmodn_raw = rrmodn.to_bytes_be();
    data.resize(data.len() + key.size() - rrmodn_raw.len(), 0);
    data.extend_from_slice(&rrmodn_raw);

    Ok(data)
}

/// Decode a public key from the AVB binary format.
pub fn decode_public_key(data: &[u8]) -> Result<RsaPublicKey> {
    let mut reader = Cursor::new(data);
    let key_bits = reader
        .read_u32::<BigEndian>()?
        .to_usize()
        .ok_or_else(|| Error::FieldOutOfBounds("key_bits"))?;

    // Skip n0inv.
    reader.read_discard_exact(4)?;

    let mut modulus_raw = vec![0u8; key_bits / 8];
    reader.read_exact(&mut modulus_raw)?;

    let modulus = BigUint::from_bytes_be(&modulus_raw);
    let public_key =
        RsaPublicKey::new(modulus, BigUint::from(65537u32)).map_err(Error::RsaVerify)?;

    Ok(public_key)
}

/// Load the vbmeta header and footer from the specified reader. A footer is
/// present only if the file is not a vbmeta partition image (ie. the header
/// follows actual data).
pub fn load_image(mut reader: impl Read + Seek) -> Result<(Header, Option<Footer>, u64)> {
    let image_size = reader.seek(SeekFrom::End(0))?;

    reader.seek(SeekFrom::End(-(Footer::SIZE as i64)))?;

    let footer = match Footer::from_reader(&mut reader) {
        Ok(f) => Some(f),
        Err(e @ Error::Io(_)) => return Err(e),
        Err(_) => None,
    };

    let vbmeta_offset = footer.as_ref().map_or(0, |f| f.vbmeta_offset);

    reader.seek(SeekFrom::Start(vbmeta_offset))?;
    let header = Header::from_reader(&mut reader)?;

    Ok((header, footer, image_size))
}

/// Write a vbmeta header to the specified writer. If a footer is specified, it
/// will be used as the basis of the newly written footer, with the original
/// image size, vbmeta header offset, and vbmeta header size fields updated
/// appropriately.
///
/// The writer must not have an existing vbmeta header or footer.
fn write_image_internal(
    mut writer: impl Write + Seek,
    header: &Header,
    footer: Option<&mut Footer>,
    image_size: Option<u64>,
    block_size: u64,
) -> Result<()> {
    let eof_image_size = writer.seek(SeekFrom::End(0))?;

    // The header must be block-aligned.
    let vbmeta_offset = if block_size > 0 {
        let padding_size = padding::write_zeros(&mut writer, block_size)?;
        eof_image_size
            .checked_add(padding_size)
            .ok_or_else(|| Error::FieldOutOfBounds("vbmeta_offset"))?
    } else {
        eof_image_size
    };

    header.to_writer(&mut writer)?;
    let vbmeta_end = writer.stream_position()?;

    if let Some(s) = image_size {
        let footer_space = if footer.is_some() {
            cmp::max(block_size, Footer::SIZE as u64)
        } else {
            0
        };

        if s < footer_space || vbmeta_end > s - footer_space {
            return Err(Error::ImageSizeTooSmall(s));
        }
    }

    if block_size > 0 {
        padding::write_zeros(&mut writer, block_size)?;
    }

    if let Some(f) = footer {
        let footer_offset = image_size.unwrap() - Footer::SIZE as u64;
        writer.seek(SeekFrom::Start(footer_offset))?;

        let original_image_size = match header.appended_descriptor()? {
            AppendedDescriptorRef::HashTree(d) => d.image_size,
            AppendedDescriptorRef::Hash(d) => d.image_size,
        };

        f.original_image_size = original_image_size;
        f.vbmeta_offset = vbmeta_offset;
        f.vbmeta_size = vbmeta_end - vbmeta_offset;

        f.to_writer(&mut writer)?;
    }

    Ok(())
}

/// Write a vbmeta header to the specified writer. This is meant for writing
/// vbmeta partition images, not appended vbmeta images. The writer must refer
/// to an empty file.
pub fn write_root_image(writer: impl Write + Seek, header: &Header, block_size: u64) -> Result<()> {
    write_image_internal(writer, header, None, None, block_size)
}

/// Write a vbmeta header and footer to the specified writer. This is meant for
/// appending vbmeta data to existing partition data, not writing vbmeta images.
pub fn write_appended_image(
    writer: impl Write + Seek,
    header: &Header,
    footer: &mut Footer,
    image_size: u64,
) -> Result<()> {
    // avbtool hardcodes a 4096 block size for appended non-sparse images.
    write_image_internal(writer, header, Some(footer), Some(image_size), 4096)
}
