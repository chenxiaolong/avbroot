// SPDX-FileCopyrightText: 2023-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    mem,
    ops::Range,
    str::{self, Utf8Error},
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use num_bigint_dig::{ModInverse, ToBigInt};
use num_traits::{Pow, ToPrimitive};
use ring::digest::{Algorithm, Context};
use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes, big_endian};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    crypto::{self, RsaPublicKeyExt, RsaSigningKey, SignatureAlgorithm},
    escape,
    format::{
        fec::{self, Fec},
        hashtree::{self, HashTree},
        padding::{self, ZeroPadding},
    },
    stream::{
        self, CountingReader, CountingWriter, FromReader, ReadFixedSizeExt, ReadSeekReopen,
        ToWriter, WriteSeekReopen, WriteZerosExt,
    },
    util::{self, OutOfBoundsError},
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

/// Maximum hash tree size. The current limit equals the hash tree size for an
/// 8GiB image using SHA256 digests and a block size of 4096. This is equal to:
///
/// ```rust
/// use avbroot::format::hashtree::HashTree;
/// let size = HashTree::new(4096, &ring::digest::SHA256, b"")
///     .compute_level_offsets(8 * 1024 * 1024 * 1024)
///     .unwrap()
///    .first()
///    .map(|r| r.end)
///    .unwrap_or(0);
/// ```
pub const HASH_TREE_MAX_SIZE: u64 = 67_637_248;

/// Maximum FEC data size. The current limit equals the FEC data size for an
/// 8GiB image using 2 parity bytes per codeword. This is equal to:
///
/// ```rust
/// use avbroot::format::fec::Fec;
/// let size = Fec::new(8 * 1024 * 1024 * 1024, 4096, 2)
///     .unwrap()
///     .fec_size();
/// ```
pub const FEC_DATA_MAX_SIZE: u64 = 67_911_680;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0:?} field does not have NULL terminator")]
    StringNotNullTerminated(&'static str),
    #[error("{0:?} field is not ASCII encoded: {1:?}")]
    StringNotAscii(&'static str, String),
    #[error("{0:?} field is not UTF-8 encoded: {data:?}", data = .2.as_bstr())]
    StringNotUtf8(&'static str, #[source] Utf8Error, Vec<u8>),
    #[error("{0:?} field is too long: {1:?}")]
    StringTooLong(&'static str, String),
    #[error("Header exceeds maximum size of {HEADER_MAX_SIZE}")]
    HeaderTooLarge,
    #[error("Descriptor padding is too long or data was not consumed")]
    PaddingTooLong,
    #[error("{0:?} field padding contains non-zero bytes")]
    PaddingNotZero(&'static str),
    #[error("{0:?} field is out of bounds")]
    IntOutOfBounds(&'static str, #[source] OutOfBoundsError),
    #[error("{0:?} overflowed integer bounds during calculations")]
    IntOverflow(&'static str),
    #[error("Invalid VBMeta header magic: {0:?}")]
    InvalidHeaderMagic([u8; 4]),
    #[error("Invalid VBMeta footer magic: {0:?}")]
    InvalidFooterMagic([u8; 4]),
    #[error("RSA public key exponent not supported by AVB binary public key format: {0}")]
    UnsupportedRsaPublicExponent(BigUint),
    #[error("AVB binary public key data is too small")]
    BinaryPublicKeyTooSmall,
    #[error("Invalid RSA modulus: {0}")]
    InvalidRsaModulus(BigUint, #[source] Box<rsa::Error>),
    #[error("Signature algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(AlgorithmType),
    #[error("Hashing algorithm not supported: {0:?}")]
    UnsupportedHashAlgorithm(String),
    #[error("Incorrect key size ({bits}) for algorithm {1:?}", bits = .0 * 8)]
    IncorrectKeySize(usize, AlgorithmType),
    #[error("RSA key size ({}) is not compatible with any AVB signing algorithm", .0 * 8)]
    UnsupportedKeySize(usize),
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
    #[error("{0} byte image size is too small to fit header")]
    TooSmallForHeader(u64),
    #[error("{0} byte image size is too small to fit footer")]
    TooSmallForFooter(u64),
    #[error("Failed to sign AVB header")]
    HeaderSign(#[source] crypto::Error),
    #[error("Failed to verify AVB header signature")]
    HeaderVerify(#[source] crypto::Error),
    #[error("Expected root digest {expected}, but have {actual}")]
    InvalidRootDigest { expected: String, actual: String },
    #[error("Failed to generate hash tree data")]
    HashTreeGenerate(#[source] hashtree::Error),
    #[error("Failed to update hash tree data")]
    HashTreeUpdate(#[source] hashtree::Error),
    #[error("Failed to verify hash tree data")]
    HashTreeVerify(#[source] hashtree::Error),
    #[error("Failed to initialize FEC instance")]
    FecInit(#[source] fec::Error),
    #[error("Failed to generate FEC data")]
    FecGenerate(#[source] fec::Error),
    #[error("Failed to update FEC data")]
    FecUpdate(#[source] fec::Error),
    #[error("Failed to verify FEC data")]
    FecVerify(#[source] fec::Error),
    #[error("Failed to repair file with FEC data")]
    FecRepair(#[source] fec::Error),
    #[error("Failed to reopen input file")]
    InputReopen(#[source] io::Error),
    #[error("Failed to reopen output file")]
    OutputReopen(#[source] io::Error),
    #[error("Failed to compute hash of input file")]
    InputDigest(#[source] io::Error),
    #[error("Failed to read AVB data: {0}")]
    DataRead(&'static str, #[source] io::Error),
    #[error("Failed to write AVB data: {0}")]
    DataWrite(&'static str, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub(crate) fn digest_algorithm(name: &str, for_verify: bool) -> Result<&'static Algorithm> {
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
    #[serde(untagged)]
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

    pub fn to_digest_algorithm(self) -> Option<SignatureAlgorithm> {
        match self {
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => {
                Some(SignatureAlgorithm::Sha256WithRsa)
            }
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => {
                Some(SignatureAlgorithm::Sha512WithRsa)
            }
            _ => None,
        }
    }

    pub fn digest_len(self) -> usize {
        self.to_digest_algorithm()
            .map(|a| a.digest_len())
            .unwrap_or_default()
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
        let Some(algo) = self.to_digest_algorithm() else {
            return vec![];
        };

        algo.hash(data)
    }

    pub fn sign(self, key: &RsaSigningKey, digest: &[u8]) -> Result<Vec<u8>> {
        let Some(algo) = self.to_digest_algorithm() else {
            return if self == Self::None {
                Ok(vec![])
            } else {
                Err(Error::UnsupportedAlgorithm(self))
            };
        };

        key.sign(algo, digest).map_err(Error::HeaderSign)
    }

    pub fn verify(self, key: &RsaPublicKey, digest: &[u8], signature: &[u8]) -> Result<()> {
        let Some(algo) = self.to_digest_algorithm() else {
            return if self == Self::None {
                Ok(())
            } else {
                Err(Error::UnsupportedAlgorithm(self))
            };
        };

        key.verify_sig(algo, digest, signature)
            .map_err(Error::HeaderVerify)
    }
}

trait DescriptorTag {
    const TAG: u64;

    fn get_tag(&self) -> u64 {
        Self::TAG
    }
}

/// Raw on-disk layout for the AVB property descriptor after the prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawPropertyDescriptor {
    key_size: big_endian::U64,
    value_size: big_endian::U64,
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
        let raw_descriptor = RawPropertyDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Property::descriptor", e))?;

        let key_size = util::check_bounds(raw_descriptor.key_size.get(), ..=HEADER_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Property::key_size", e))?;
        let value_size = util::check_bounds(raw_descriptor.value_size.get(), ..=HEADER_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Property::value_size", e))?;

        let key = reader
            .read_vec_exact(key_size as usize)
            .map_err(|e| Error::DataRead("Property::key", e))?;
        let key = String::from_utf8(key)
            .map_err(|e| Error::StringNotUtf8("Property::key", e.utf8_error(), e.into_bytes()))?;

        let null = reader
            .read_array_exact::<1>()
            .map_err(|e| Error::DataRead("Property::key", e))?;
        if null[0] != b'\0' {
            return Err(Error::StringNotNullTerminated("Property::key"));
        }

        let value = reader
            .read_vec_exact(value_size as usize)
            .map_err(|e| Error::DataRead("Property::value", e))?;

        // The non-string value is also null terminated.
        let null = reader
            .read_array_exact::<1>()
            .map_err(|e| Error::DataRead("Property::value", e))?;
        if null[0] != b'\0' {
            return Err(Error::StringNotNullTerminated("Property::value"));
        }

        Ok(Self { key, value })
    }
}

impl<W: Write> ToWriter<W> for PropertyDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        util::check_bounds(self.key.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Property::key_size", e))?;
        util::check_bounds(self.value.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Property::value_size", e))?;

        let raw_descriptor = RawPropertyDescriptor {
            key_size: (self.key.len() as u64).into(),
            value_size: (self.value.len() as u64).into(),
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Property::descriptor", e))?;
        writer
            .write_all(self.key.as_bytes())
            .map_err(|e| Error::DataWrite("Property::key", e))?;
        writer
            .write_all(b"\0")
            .map_err(|e| Error::DataWrite("Property::key", e))?;
        writer
            .write_all(&self.value)
            .map_err(|e| Error::DataWrite("Property::value", e))?;
        writer
            .write_all(b"\0")
            .map_err(|e| Error::DataWrite("Property::value", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB hash tree descriptor after the prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHashTreeDescriptor {
    dm_verity_version: big_endian::U32,
    image_size: big_endian::U64,
    tree_offset: big_endian::U64,
    tree_size: big_endian::U64,
    data_block_size: big_endian::U32,
    hash_block_size: big_endian::U32,
    fec_num_roots: big_endian::U32,
    fec_offset: big_endian::U64,
    fec_size: big_endian::U64,
    hash_algorithm: [u8; 32],
    partition_name_len: big_endian::U32,
    salt_len: big_endian::U32,
    root_digest_len: big_endian::U32,
    flags: big_endian::U32,
    reserved: [u8; 60],
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
        }

        util::check_bounds(self.fec_size, ..=FEC_DATA_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("HashTree::fec_size", e))?;

        // Fec will check the validity of this field.
        let parity: u8 = util::try_cast(self.fec_num_roots)
            .map_err(|e| Error::IntOutOfBounds("HashTree::fec_num_roots", e))?;

        // The FEC covers the hash tree as well.
        let fec = Fec::new(
            self.image_size + self.tree_size,
            self.data_block_size,
            parity,
        )
        .map_err(Error::FecInit)?;

        Ok((fec, self.fec_size as usize))
    }

    /// Update the root hash, hash tree, and FEC data. The hash tree and FEC
    /// data will be written immediately following the image data at offset
    /// [`Self::image_size`]. Both `open_input` and `open_output` may be called
    /// from multiple threads and must return independently seekable handles to
    /// the same file. It is guaranteed that every thread will read and write
    /// disjoint file offsets.
    ///
    /// If `ranges` is [`Option::None`], then the hash tree and FEC data are
    /// updated for the whole while. Due to the nature of the file access
    /// patterns, the entire file will be read twice. However, if
    /// [`Self::fec_num_roots`] is 0, no FEC data will be computed nor written.
    ///
    /// If `ranges` is specified, only the hash tree and FEC data corresponding
    /// to those ranges are updated. It may be necessary read a bit more data
    /// that what is specified in order to perform the computations.
    ///
    /// The fields in this instance are updated atomically. No fields are
    /// updated if an error occurs. The input file can be restored back to its
    /// original state by truncating it to [`Self::image_size`].
    pub fn update(
        &mut self,
        input: &(dyn ReadSeekReopen + Sync),
        output: &(dyn WriteSeekReopen + Sync),
        ranges: Option<&[Range<u64>]>,
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        let algorithm = digest_algorithm(&self.hash_algorithm, false)?;
        let hash_tree = HashTree::new(self.data_block_size, algorithm, &self.salt);
        let (root_digest, hash_tree_data) = match ranges {
            Some(r) => {
                let mut reader = input.reopen_boxed().map_err(Error::InputReopen)?;
                reader
                    .seek(SeekFrom::Start(self.tree_offset))
                    .map_err(|e| Error::DataRead("HashTree::tree_data", e))?;

                let mut hash_tree_data = reader
                    .read_vec_exact(self.tree_size as usize)
                    .map_err(|e| Error::DataRead("HashTree::tree_data", e))?;

                let root_digest = hash_tree
                    .update(
                        input,
                        self.image_size,
                        r,
                        &mut hash_tree_data,
                        cancel_signal,
                    )
                    .map_err(Error::HashTreeUpdate)?;

                (root_digest, hash_tree_data)
            }
            None => hash_tree
                .generate(input, self.image_size, cancel_signal)
                .map_err(Error::HashTreeGenerate)?,
        };

        util::check_bounds(hash_tree_data.len(), ..=HASH_TREE_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("HashTree::tree_size", e))?;

        let tree_size = hash_tree_data.len() as u64;

        let mut writer = output.reopen_boxed().map_err(Error::OutputReopen)?;
        writer
            .seek(SeekFrom::Start(self.image_size))
            .map_err(|e| Error::DataWrite("HashTree::tree_data", e))?;
        writer
            .write_all(&hash_tree_data)
            .map_err(|e| Error::DataWrite("HashTree::tree_data", e))?;

        // The FEC data section is optional.
        if self.fec_num_roots != 0 {
            if self.data_block_size != self.hash_block_size {
                return Err(Error::MismatchedFecBlockSizes {
                    data: self.data_block_size,
                    hash: self.hash_block_size,
                });
            }

            let parity: u8 = util::try_cast(self.fec_num_roots)
                .map_err(|e| Error::IntOutOfBounds("HashTree::fec_num_roots", e))?;

            let fec_data = if let Some(r) = ranges {
                let mut r_with_hash_tree = r.to_vec();
                r_with_hash_tree.push(self.tree_offset..self.tree_offset + tree_size);

                let (fec, fec_size) = self.get_fec()?;

                let mut reader = input.reopen_boxed().map_err(Error::InputReopen)?;
                reader
                    .seek(SeekFrom::Start(self.fec_offset))
                    .map_err(|e| Error::DataRead("HashTree::fec_data", e))?;

                let mut fec_data = reader
                    .read_vec_exact(fec_size)
                    .map_err(|e| Error::DataRead("HashTree::fec_data", e))?;

                fec.update(input, &r_with_hash_tree, &mut fec_data, cancel_signal)
                    .map_err(Error::FecUpdate)?;

                fec_data
            } else {
                // The FEC covers the hash tree as well.
                let fec = Fec::new(self.image_size + tree_size, self.data_block_size, parity)
                    .map_err(Error::FecInit)?;
                fec.generate(input, cancel_signal)
                    .map_err(Error::FecGenerate)?
            };

            // Already seeked to FEC.
            writer
                .write_all(&fec_data)
                .map_err(|e| Error::DataWrite("HashTree::fec_data", e))?;

            self.fec_offset = self.image_size + tree_size;
            self.fec_size = fec_data.len() as u64;
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

        let algorithm = digest_algorithm(&self.hash_algorithm, true)?;

        util::check_bounds(self.tree_size, ..=HASH_TREE_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("HashTree::tree_size", e))?;

        let mut reader = input.reopen_boxed().map_err(Error::InputReopen)?;
        reader
            .seek(SeekFrom::Start(self.tree_offset))
            .map_err(|e| Error::DataRead("HashTree::tree_data", e))?;

        let hash_tree_data = reader
            .read_vec_exact(self.tree_size as usize)
            .map_err(|e| Error::DataRead("HashTree::tree_data", e))?;

        let hash_tree = HashTree::new(self.data_block_size, algorithm, &self.salt);

        hash_tree
            .verify(
                input,
                self.image_size,
                &self.root_digest,
                &hash_tree_data,
                cancel_signal,
            )
            .map_err(Error::HashTreeVerify)?;

        // The FEC data section is optional.
        if self.fec_num_roots != 0 {
            let (fec, fec_size) = self.get_fec()?;

            // Already seeked to FEC.
            let fec_data = reader
                .read_vec_exact(fec_size)
                .map_err(|e| Error::DataRead("HashTree::fec_data", e))?;

            fec.verify(input, &fec_data, cancel_signal)
                .map_err(Error::FecVerify)?;
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

        let mut reader = input.reopen_boxed().map_err(Error::InputReopen)?;
        reader
            .seek(SeekFrom::Start(self.fec_offset))
            .map_err(|e| Error::DataRead("HashTree::fec_data", e))?;

        let (fec, fec_size) = self.get_fec()?;

        // Already seeked to FEC.
        let fec_data = reader
            .read_vec_exact(fec_size)
            .map_err(|e| Error::DataRead("HashTree::fec_data", e))?;

        fec.repair(input, output, &fec_data, cancel_signal)
            .map_err(Error::FecRepair)?;

        Ok(())
    }
}

impl DescriptorTag for HashTreeDescriptor {
    const TAG: u64 = 1;
}

impl<R: Read> FromReader<R> for HashTreeDescriptor {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let raw_descriptor = RawHashTreeDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("HashTree::descriptor", e))?;

        let hash_algorithm = raw_descriptor.hash_algorithm.trim_end_padding();
        let hash_algorithm = str::from_utf8(hash_algorithm).map_err(|e| {
            Error::StringNotUtf8("HashTree::hash_algorithm", e, hash_algorithm.to_vec())
        })?;
        if !hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "HashTree::hash_algorithm",
                hash_algorithm.to_owned(),
            ));
        }

        let partition_name_len = util::check_bounds(
            raw_descriptor.partition_name_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("HashTree::partition_name_len", e))?;
        let salt_len = util::check_bounds(raw_descriptor.salt_len.get(), ..=HEADER_MAX_SIZE as u32)
            .map_err(|e| Error::IntOutOfBounds("HashTree::salt_len", e))?;
        let root_digest_len = util::check_bounds(
            raw_descriptor.root_digest_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("HashTree::root_digest_len", e))?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_vec_exact(partition_name_len as usize)
            .map_err(|e| Error::DataRead("HashTree::partition_name", e))?;
        let partition_name = String::from_utf8(partition_name).map_err(|e| {
            Error::StringNotUtf8("HashTree::partition_name", e.utf8_error(), e.into_bytes())
        })?;

        let salt = reader
            .read_vec_exact(salt_len as usize)
            .map_err(|e| Error::DataRead("HashTree::salt", e))?;

        let root_digest = reader
            .read_vec_exact(root_digest_len as usize)
            .map_err(|e| Error::DataRead("HashTree::root_digest", e))?;

        let descriptor = Self {
            dm_verity_version: raw_descriptor.dm_verity_version.into(),
            image_size: raw_descriptor.image_size.into(),
            tree_offset: raw_descriptor.tree_offset.into(),
            tree_size: raw_descriptor.tree_size.into(),
            data_block_size: raw_descriptor.data_block_size.into(),
            hash_block_size: raw_descriptor.hash_block_size.into(),
            fec_num_roots: raw_descriptor.fec_num_roots.into(),
            fec_offset: raw_descriptor.fec_offset.into(),
            fec_size: raw_descriptor.fec_size.into(),
            hash_algorithm: hash_algorithm.to_owned(),
            partition_name,
            salt,
            root_digest,
            flags: raw_descriptor.flags.get(),
            reserved: raw_descriptor.reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for HashTreeDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        util::check_bounds(self.partition_name.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("HashTree::partition_name_len", e))?;
        util::check_bounds(self.salt.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("HashTree::salt_len", e))?;
        util::check_bounds(self.root_digest.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("HashTree::root_digest_len", e))?;

        if !self.hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "HashTree::hash_algorithm",
                self.hash_algorithm.clone(),
            ));
        }

        let hash_algorithm = self
            .hash_algorithm
            .as_bytes()
            .to_padded_array::<32>()
            .ok_or_else(|| {
                Error::StringTooLong("HashTree::hash_algorithm", self.hash_algorithm.clone())
            })?;

        let raw_descriptor = RawHashTreeDescriptor {
            dm_verity_version: self.dm_verity_version.into(),
            image_size: self.image_size.into(),
            tree_offset: self.tree_offset.into(),
            tree_size: self.tree_size.into(),
            data_block_size: self.data_block_size.into(),
            hash_block_size: self.hash_block_size.into(),
            fec_num_roots: self.fec_num_roots.into(),
            fec_offset: self.fec_offset.into(),
            fec_size: self.fec_size.into(),
            hash_algorithm,
            partition_name_len: (self.partition_name.len() as u32).into(),
            salt_len: (self.salt.len() as u32).into(),
            root_digest_len: (self.root_digest.len() as u32).into(),
            flags: self.flags.into(),
            reserved: self.reserved,
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("HashTree::descriptor", e))?;
        writer
            .write_all(self.partition_name.as_bytes())
            .map_err(|e| Error::DataWrite("HashTree::partition_name", e))?;
        writer
            .write_all(&self.salt)
            .map_err(|e| Error::DataWrite("HashTree::salt", e))?;
        writer
            .write_all(&self.root_digest)
            .map_err(|e| Error::DataWrite("HashTree::root_digest", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB hash descriptor after the prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHashDescriptor {
    image_size: big_endian::U64,
    hash_algorithm: [u8; 32],
    partition_name_len: big_endian::U32,
    salt_len: big_endian::U32,
    root_digest_len: big_endian::U32,
    flags: big_endian::U32,
    reserved: [u8; 60],
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
        let algorithm = digest_algorithm(&self.hash_algorithm, for_verify)?;
        let mut context = Context::new(algorithm);
        context.update(&self.salt);

        stream::copy_n_inspect(
            reader,
            io::sink(),
            self.image_size,
            |data| context.update(data),
            cancel_signal,
        )
        .map_err(Error::InputDigest)?;

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
        let raw_descriptor = RawHashDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Hash::descriptor", e))?;

        let hash_algorithm = raw_descriptor.hash_algorithm.trim_end_padding();
        let hash_algorithm = str::from_utf8(hash_algorithm).map_err(|e| {
            Error::StringNotUtf8("Hash::hash_algorithm", e, hash_algorithm.to_vec())
        })?;
        if !hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "Hash::hash_algorithm",
                hash_algorithm.to_owned(),
            ));
        }

        let partition_name_len = util::check_bounds(
            raw_descriptor.partition_name_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("Hash::partition_name_len", e))?;
        let salt_len = util::check_bounds(raw_descriptor.salt_len.get(), ..=HEADER_MAX_SIZE as u32)
            .map_err(|e| Error::IntOutOfBounds("Hash::salt_len", e))?;
        let root_digest_len = util::check_bounds(
            raw_descriptor.root_digest_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("Hash::root_digest_len", e))?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_vec_exact(partition_name_len as usize)
            .map_err(|e| Error::DataRead("Hash::partition_name", e))?;
        let partition_name = String::from_utf8(partition_name).map_err(|e| {
            Error::StringNotUtf8("Hash::partition_name", e.utf8_error(), e.into_bytes())
        })?;

        let salt = reader
            .read_vec_exact(salt_len as usize)
            .map_err(|e| Error::DataRead("Hash::salt", e))?;

        let root_digest = reader
            .read_vec_exact(root_digest_len as usize)
            .map_err(|e| Error::DataRead("Hash::root_digest", e))?;

        let descriptor = Self {
            image_size: raw_descriptor.image_size.get(),
            hash_algorithm: hash_algorithm.to_owned(),
            partition_name,
            salt,
            root_digest,
            flags: raw_descriptor.flags.get(),
            reserved: raw_descriptor.reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for HashDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        util::check_bounds(self.partition_name.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Hash::partition_name_len", e))?;
        util::check_bounds(self.salt.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Hash::salt_len", e))?;
        util::check_bounds(self.root_digest.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Hash::root_digest_len", e))?;

        if !self.hash_algorithm.is_ascii() {
            return Err(Error::StringNotAscii(
                "Hash::hash_algorithm",
                self.hash_algorithm.clone(),
            ));
        }

        let hash_algorithm = self
            .hash_algorithm
            .as_bytes()
            .to_padded_array::<32>()
            .ok_or_else(|| {
                Error::StringTooLong("Hash::hash_algorithm", self.hash_algorithm.clone())
            })?;

        let raw_descriptor = RawHashDescriptor {
            image_size: self.image_size.into(),
            hash_algorithm,
            partition_name_len: (self.partition_name.len() as u32).into(),
            salt_len: (self.salt.len() as u32).into(),
            root_digest_len: (self.root_digest.len() as u32).into(),
            flags: self.flags.into(),
            reserved: self.reserved,
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Hash::descriptor", e))?;
        writer
            .write_all(self.partition_name.as_bytes())
            .map_err(|e| Error::DataWrite("Hash::partition_name", e))?;
        writer
            .write_all(&self.salt)
            .map_err(|e| Error::DataWrite("Hash::salt", e))?;
        writer
            .write_all(&self.root_digest)
            .map_err(|e| Error::DataWrite("Hash::root_digest", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB kernel command line descriptor after the
/// prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawKernelCmdlineDescriptor {
    flags: big_endian::U32,
    cmdline_len: big_endian::U32,
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
        let raw_descriptor = RawKernelCmdlineDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("KernelCmdline::descriptor", e))?;

        let cmdline_len =
            util::check_bounds(raw_descriptor.cmdline_len.get(), ..=HEADER_MAX_SIZE as u32)
                .map_err(|e| Error::IntOutOfBounds("KernelCmdline::cmdline_len", e))?;

        // Not NULL-terminated.
        let cmdline = reader
            .read_vec_exact(cmdline_len as usize)
            .map_err(|e| Error::DataRead("KernelCmdline::cmdline", e))?;
        let cmdline = String::from_utf8(cmdline).map_err(|e| {
            Error::StringNotUtf8("KernelCmdline::cmdline", e.utf8_error(), e.into_bytes())
        })?;

        let descriptor = Self {
            flags: raw_descriptor.flags.get(),
            cmdline,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for KernelCmdlineDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        util::check_bounds(self.cmdline.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("KernelCmdline::cmdline_len", e))?;

        let raw_descriptor = RawKernelCmdlineDescriptor {
            flags: self.flags.into(),
            cmdline_len: (self.cmdline.len() as u32).into(),
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("KernelCmdline::descriptor", e))?;
        writer
            .write_all(self.cmdline.as_bytes())
            .map_err(|e| Error::DataWrite("KernelCmdline::cmdline", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB chain partition descriptor after the prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawChainPartitionDescriptor {
    rollback_index_location: big_endian::U32,
    partition_name_len: big_endian::U32,
    public_key_len: big_endian::U32,
    flags: big_endian::U32,
    reserved: [u8; 60],
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
        let raw_descriptor = RawChainPartitionDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("ChainPartition::descriptor", e))?;

        let partition_name_len = util::check_bounds(
            raw_descriptor.partition_name_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("ChainPartition::partition_name_len", e))?;
        let public_key_len = util::check_bounds(
            raw_descriptor.public_key_len.get(),
            ..=HEADER_MAX_SIZE as u32,
        )
        .map_err(|e| Error::IntOutOfBounds("ChainPartition::public_key_len", e))?;

        // Not NULL-terminated.
        let partition_name = reader
            .read_vec_exact(partition_name_len as usize)
            .map_err(|e| Error::DataRead("ChainPartition::partition_name", e))?;
        let partition_name = String::from_utf8(partition_name).map_err(|e| {
            Error::StringNotUtf8(
                "ChainPartition::partition_name",
                e.utf8_error(),
                e.into_bytes(),
            )
        })?;

        let public_key = reader
            .read_vec_exact(public_key_len as usize)
            .map_err(|e| Error::DataRead("ChainPartition::public_key", e))?;

        let descriptor = Self {
            rollback_index_location: raw_descriptor.rollback_index_location.get(),
            partition_name,
            public_key,
            flags: raw_descriptor.flags.get(),
            reserved: raw_descriptor.reserved,
        };

        Ok(descriptor)
    }
}

impl<W: Write> ToWriter<W> for ChainPartitionDescriptor {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        util::check_bounds(self.partition_name.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("ChainPartition::partition_name_len", e))?;
        util::check_bounds(self.public_key.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("ChainPartition::public_key_len", e))?;

        let raw_descriptor = RawChainPartitionDescriptor {
            rollback_index_location: self.rollback_index_location.into(),
            partition_name_len: (self.partition_name.len() as u32).into(),
            public_key_len: (self.public_key.len() as u32).into(),
            flags: self.flags.into(),
            reserved: self.reserved,
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("ChainPartition::descriptor", e))?;
        writer
            .write_all(self.partition_name.as_bytes())
            .map_err(|e| Error::DataWrite("ChainPartition::partition_name", e))?;
        writer
            .write_all(&self.public_key)
            .map_err(|e| Error::DataWrite("ChainPartition::public_key", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB descriptor prefix.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawDescriptor {
    tag: big_endian::U64,
    num_bytes_following: big_endian::U64,
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
        let raw_descriptor = RawDescriptor::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Descriptor::prefix", e))?;

        let nbf = util::check_bounds(raw_descriptor.num_bytes_following.get(), ..=HEADER_MAX_SIZE)
            .map_err(|e| Error::IntOutOfBounds("Descriptor::num_bytes_following", e))?;

        let mut inner_reader = CountingReader::new(reader.take(nbf));

        let descriptor = match raw_descriptor.tag.get() {
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
            tag => {
                let data = inner_reader
                    .read_vec_exact(nbf as usize)
                    .map_err(|e| Error::DataRead("Descriptor::unknown", e))?;

                Self::Unknown { tag, data }
            }
        };

        // The descriptor data is always aligned to 8 bytes.
        padding::read_discard(&mut inner_reader, 8)
            .map_err(|e| Error::DataRead("Descriptor::padding", e))?;
        if inner_reader
            .stream_position()
            .map_err(|e| Error::DataRead("Descriptor::padding", e))?
            != nbf
        {
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
                inner_writer
                    .write_all(data)
                    .map_err(|e| Error::DataWrite("Descriptor::unknown", e))?;
                *tag
            }
        };

        let inner_data = inner_writer.into_inner();

        let nbf_unpadded = util::check_bounds(inner_data.len(), ..=HEADER_MAX_SIZE as usize)
            .map_err(|e| Error::IntOutOfBounds("Descriptor::num_bytes_following", e))?;

        let padding_len = padding::calc(nbf_unpadded, 8);
        let nbf = nbf_unpadded + padding_len;

        let raw_descriptor = RawDescriptor {
            tag: tag.into(),
            num_bytes_following: (nbf as u64).into(),
        };

        raw_descriptor
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Descriptor::prefix", e))?;
        writer
            .write_all(&inner_data)
            .map_err(|e| Error::DataWrite("Descriptor::descriptors", e))?;
        writer
            .write_zeros_exact(padding_len as u64)
            .map_err(|e| Error::DataWrite("Descriptor::padding", e))?;

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

/// Raw on-disk layout for the AVB header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawHeader {
    /// Magic value. This should be equal to [`HEADER_MAGIC`].
    magic: [u8; 4],
    required_libavb_version_major: big_endian::U32,
    required_libavb_version_minor: big_endian::U32,
    auth_block_size: big_endian::U64,
    aux_block_size: big_endian::U64,
    algorithm_type: big_endian::U32,
    hash_offset: big_endian::U64,
    hash_size: big_endian::U64,
    signature_offset: big_endian::U64,
    signature_size: big_endian::U64,
    public_key_offset: big_endian::U64,
    public_key_size: big_endian::U64,
    public_key_metadata_offset: big_endian::U64,
    public_key_metadata_size: big_endian::U64,
    descriptors_offset: big_endian::U64,
    descriptors_size: big_endian::U64,
    rollback_index: big_endian::U64,
    flags: big_endian::U32,
    rollback_index_location: big_endian::U32,
    /// Unlike all other fixed-size header strings, this one must be NULL
    /// terminated.
    release_string: [u8; 47],
    _release_string_terminator: u8,
    reserved: [u8; 80],
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
    pub const SIZE: usize = mem::size_of::<RawHeader>();

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
            .ok_or(Error::IntOverflow("Header::auth_block_data_size"))?;
        let auth_block_padding_size = padding::calc(auth_block_data_size, 64);
        let auth_block_size = auth_block_data_size
            .checked_add(auth_block_padding_size)
            .ok_or(Error::IntOverflow("Header::auth_block_size"))?;

        let hash_offset = 0usize;
        let signature_offset = hash_offset + self.hash.len();

        // Aux block.

        let aux_block_data_size = descriptors_raw
            .len()
            .checked_add(self.public_key.len())
            .and_then(|s| s.checked_add(self.public_key_metadata.len()))
            .ok_or(Error::IntOverflow("Header::aux_block_data_size"))?;
        let aux_block_padding_size = padding::calc(aux_block_data_size, 64);
        let aux_block_size = aux_block_data_size
            .checked_add(aux_block_padding_size)
            .ok_or(Error::IntOverflow("Header::aux_block_size"))?;

        let descriptors_offset = 0usize;
        let public_key_offset = descriptors_offset + descriptors_raw.len();
        let public_key_metadata_offset = public_key_offset + self.public_key.len();

        let total_size = Self::SIZE
            .checked_add(auth_block_data_size)
            .and_then(|s| s.checked_add(aux_block_data_size))
            .ok_or(Error::IntOverflow("Header::total_size"))?;
        if total_size > HEADER_MAX_SIZE as usize {
            return Err(Error::HeaderTooLarge);
        }

        // All sizes and offsets are now guaranteed to fit in a u64.

        let release_string = self
            .release_string
            .as_bytes()
            .to_padded_array::<47>()
            .ok_or_else(|| {
                Error::StringTooLong("Header::release_string", self.release_string.clone())
            })?;

        let raw_header = RawHeader {
            magic: HEADER_MAGIC,
            required_libavb_version_major: self.required_libavb_version_major.into(),
            required_libavb_version_minor: self.required_libavb_version_minor.into(),
            auth_block_size: (auth_block_size as u64).into(),
            aux_block_size: (aux_block_size as u64).into(),
            algorithm_type: self.algorithm_type.to_raw().into(),
            hash_offset: (hash_offset as u64).into(),
            hash_size: (self.hash.len() as u64).into(),
            signature_offset: (signature_offset as u64).into(),
            signature_size: (self.signature.len() as u64).into(),
            public_key_offset: (public_key_offset as u64).into(),
            public_key_size: (self.public_key.len() as u64).into(),
            public_key_metadata_offset: (public_key_metadata_offset as u64).into(),
            public_key_metadata_size: (self.public_key_metadata.len() as u64).into(),
            descriptors_offset: (descriptors_offset as u64).into(),
            descriptors_size: (descriptors_raw.len() as u64).into(),
            rollback_index: self.rollback_index.into(),
            flags: self.flags.into(),
            rollback_index_location: self.rollback_index_location.into(),
            release_string,
            _release_string_terminator: 0,
            reserved: self.reserved,
        };

        raw_header
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Header::header", e))?;

        // Auth block.
        if !skip_auth_block {
            writer
                .write_all(&self.hash)
                .map_err(|e| Error::DataWrite("Header::hash", e))?;
            writer
                .write_all(&self.signature)
                .map_err(|e| Error::DataWrite("Header::signature", e))?;
            writer
                .write_zeros_exact(auth_block_padding_size as u64)
                .map_err(|e| Error::DataWrite("Header::auth_block_padding", e))?;
        }

        // Aux block.
        writer
            .write_all(&descriptors_raw)
            .map_err(|e| Error::DataWrite("Header::descriptors", e))?;
        writer
            .write_all(&self.public_key)
            .map_err(|e| Error::DataWrite("Header::public_key", e))?;
        writer
            .write_all(&self.public_key_metadata)
            .map_err(|e| Error::DataWrite("Header::public_key_metadata", e))?;
        writer
            .write_zeros_exact(aux_block_padding_size as u64)
            .map_err(|e| Error::DataWrite("Header::aux_block_padding", e))?;

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

    pub fn set_algo_for_key(&mut self, key: &RsaSigningKey) -> Result<()> {
        let key_raw = encode_public_key(&key.to_public_key())?;

        for algo in [AlgorithmType::Sha256Rsa2048, AlgorithmType::Sha256Rsa4096] {
            if key_raw.len() == algo.public_key_len() {
                self.algorithm_type = algo;
                return Ok(());
            }
        }

        Err(Error::UnsupportedKeySize(key.size()))
    }

    pub fn clear_sig(&mut self) {
        self.hash.clear();
        self.signature.clear();
        self.public_key.clear();
        self.public_key_metadata.clear();
    }

    pub fn sign(&mut self, key: &RsaSigningKey) -> Result<()> {
        let key_raw = encode_public_key(&key.to_public_key())?;

        if key_raw.len() != self.algorithm_type.public_key_len() {
            return Err(Error::IncorrectKeySize(key.size(), self.algorithm_type));
        }

        // The public key and the sizes of the hash and signature are included
        // in the data that's about to be signed.
        self.public_key = key_raw;
        self.hash.resize(self.algorithm_type.digest_len(), 0);
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
        // Reconstruct the public key.
        let public_key = decode_public_key(&self.public_key)?;

        if self.public_key.len() != self.algorithm_type.public_key_len() {
            return Err(Error::IncorrectKeySize(
                public_key.size(),
                self.algorithm_type,
            ));
        }

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

        let raw_header = RawHeader::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Header::header", e))?;

        if raw_header.magic != HEADER_MAGIC {
            return Err(Error::InvalidHeaderMagic(raw_header.magic));
        }

        let auth_block_size = raw_header.auth_block_size.get();
        let aux_block_size = raw_header.aux_block_size.get();
        let algorithm_type = AlgorithmType::from_raw(raw_header.algorithm_type.get());
        let hash_offset = raw_header.hash_offset.get();
        let hash_size = raw_header.hash_size.get();
        let signature_offset = raw_header.signature_offset.get();
        let signature_size = raw_header.signature_size.get();

        let auth_block_combined = hash_size
            .checked_add(signature_size)
            .ok_or(Error::IntOverflow("Header::auth_block_combined"))?;
        let auth_block_padding = padding::calc(auth_block_combined, 64);
        if auth_block_combined.checked_add(auth_block_padding) != Some(auth_block_size) {
            return Err(Error::IntOverflow("Header::auth_block_size"));
        } else if hash_offset > auth_block_combined - hash_size {
            return Err(Error::IntOverflow("Header::hash_offset"));
        } else if signature_offset > auth_block_combined - signature_size {
            return Err(Error::IntOverflow("Header::signature_offset"));
        }

        let public_key_offset = raw_header.public_key_offset.get();
        let public_key_size = raw_header.public_key_size.get();
        let public_key_metadata_offset = raw_header.public_key_metadata_offset.get();
        let public_key_metadata_size = raw_header.public_key_metadata_size.get();
        let descriptors_offset = raw_header.descriptors_offset.get();
        let descriptors_size = raw_header.descriptors_size.get();

        let aux_block_combined = public_key_size
            .checked_add(public_key_metadata_size)
            .and_then(|s| s.checked_add(descriptors_size))
            .ok_or(Error::IntOverflow("Header::aux_block_combined"))?;
        let aux_block_padding = padding::calc(aux_block_combined, 64);
        if aux_block_combined.checked_add(aux_block_padding) != Some(aux_block_size) {
            return Err(Error::IntOverflow("Header::aux_block_size"));
        } else if public_key_offset > aux_block_combined - public_key_size {
            return Err(Error::IntOverflow("Header::public_key_offset"));
        } else if public_key_metadata_offset > aux_block_combined - public_key_metadata_size {
            return Err(Error::IntOverflow("Header::public_key_metadata_size"));
        } else if descriptors_offset > aux_block_combined - descriptors_size {
            return Err(Error::IntOverflow("Header::descriptors_offset"));
        }

        let release_string = raw_header.release_string.trim_end_padding();
        let release_string = str::from_utf8(release_string).map_err(|e| {
            Error::StringNotUtf8("Header::release_string", e, release_string.to_vec())
        })?;

        let header_size = reader
            .stream_position()
            .map_err(|e| Error::DataRead("Header::header_size", e))?;
        let total_size = header_size
            .checked_add(auth_block_size)
            .and_then(|v| v.checked_add(aux_block_size))
            .ok_or(Error::IntOverflow("Header::total_size"))?;
        if total_size > HEADER_MAX_SIZE {
            return Err(Error::HeaderTooLarge);
        }

        // All of the size fields above are now guaranteed to fit in usize.

        let auth_block = reader
            .read_vec_exact(auth_block_size as usize)
            .map_err(|e| Error::DataRead("Header::auth_block", e))?;

        let aux_block = reader
            .read_vec_exact(aux_block_size as usize)
            .map_err(|e| Error::DataRead("Header::aux_block", e))?;

        // When we verify() the signatures, we're doing so on re-serialized
        // fields. The padding is the only thing that can escape this, so make
        // sure they don't contain any data.
        if !util::is_zero(
            &auth_block[auth_block_combined as usize..][..auth_block_padding as usize],
        ) {
            return Err(Error::PaddingNotZero("Header::auth_block"));
        }
        if !util::is_zero(&aux_block[aux_block_combined as usize..][..aux_block_padding as usize]) {
            return Err(Error::PaddingNotZero("Header::aux_block"));
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
        let mut pos = descriptor_reader
            .seek(SeekFrom::Start(descriptors_offset))
            .map_err(|e| Error::DataRead("Header::descriptors_offset", e))?;

        while pos < descriptors_offset + descriptors_size {
            let descriptor = Descriptor::from_reader(&mut descriptor_reader)?;
            descriptors.push(descriptor);
            pos = descriptor_reader
                .stream_position()
                .map_err(|e| Error::DataRead("Header::descriptors_offset", e))?;
        }

        let header = Self {
            required_libavb_version_major: raw_header.required_libavb_version_major.get(),
            required_libavb_version_minor: raw_header.required_libavb_version_minor.get(),
            algorithm_type,
            hash: hash.to_owned(),
            signature: signature.to_owned(),
            public_key: public_key.to_owned(),
            public_key_metadata: public_key_metadata.to_owned(),
            descriptors,
            rollback_index: raw_header.rollback_index.get(),
            flags: raw_header.flags.get(),
            rollback_index_location: raw_header.rollback_index_location.get(),
            release_string: release_string.to_owned(),
            reserved: raw_header.reserved,
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

/// Raw on-disk layout for the AVB footer.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawFooter {
    /// Magic value. This should be equal to [`FOOTER_MAGIC`].
    magic: [u8; 4],
    version_major: big_endian::U32,
    version_minor: big_endian::U32,
    original_image_size: big_endian::U64,
    vbmeta_offset: big_endian::U64,
    vbmeta_size: big_endian::U64,
    reserved: [u8; 28],
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
    pub const SIZE: usize = mem::size_of::<RawFooter>();
}

impl<R: Read> FromReader<R> for Footer {
    type Error = Error;

    fn from_reader(mut reader: R) -> Result<Self> {
        let raw_footer = RawFooter::read_from_io(&mut reader)
            .map_err(|e| Error::DataRead("Footer::footer", e))?;

        if raw_footer.magic != FOOTER_MAGIC {
            return Err(Error::InvalidFooterMagic(raw_footer.magic));
        }

        let footer = Self {
            version_major: raw_footer.version_major.get(),
            version_minor: raw_footer.version_minor.get(),
            original_image_size: raw_footer.original_image_size.get(),
            vbmeta_offset: raw_footer.vbmeta_offset.get(),
            vbmeta_size: raw_footer.vbmeta_size.get(),
            reserved: raw_footer.reserved,
        };

        Ok(footer)
    }
}

impl<W: Write> ToWriter<W> for Footer {
    type Error = Error;

    fn to_writer(&self, mut writer: W) -> Result<()> {
        let raw_footer = RawFooter {
            magic: FOOTER_MAGIC,
            version_major: self.version_major.into(),
            version_minor: self.version_minor.into(),
            original_image_size: self.original_image_size.into(),
            vbmeta_offset: self.vbmeta_offset.into(),
            vbmeta_size: self.vbmeta_size.into(),
            reserved: self.reserved,
        };

        raw_footer
            .write_to_io(&mut writer)
            .map_err(|e| Error::DataWrite("Footer::footer", e))?;

        Ok(())
    }
}

/// Raw on-disk layout for the AVB binary public key header.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct RawPublicKey {
    key_num_bits: big_endian::U32,
    n0inv: big_endian::U32,
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

    let raw_header = RawPublicKey {
        key_num_bits: (key.size() * 8).to_u32().unwrap().into(),
        n0inv: n0inv.to_u32().unwrap().into(),
    };

    let mut data = vec![];
    data.extend_from_slice(raw_header.as_bytes());

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
    let (raw_header, suffix) =
        RawPublicKey::ref_from_prefix(data).map_err(|_| Error::BinaryPublicKeyTooSmall)?;

    let key_bits = raw_header.key_num_bits.get() as usize;

    if suffix.len() < key_bits / 8 {
        return Err(Error::BinaryPublicKeyTooSmall);
    }

    let modulus = BigUint::from_bytes_be(&suffix[..key_bits / 8]);
    let public_key = RsaPublicKey::new(modulus.clone(), BigUint::from(65537u32))
        .map_err(|e| Error::InvalidRsaModulus(modulus, Box::new(e)))?;

    Ok(public_key)
}

/// Load the vbmeta header and footer from the specified reader. A footer is
/// present only if the file is not a vbmeta partition image (ie. the header
/// follows actual data).
pub fn load_image(mut reader: impl Read + Seek) -> Result<(Header, Option<Footer>, u64)> {
    let image_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| Error::DataRead("image_size", e))?;

    reader
        .seek(SeekFrom::End(-(Footer::SIZE as i64)))
        .map_err(|e| Error::DataRead("footer_offset", e))?;

    let footer = match Footer::from_reader(&mut reader) {
        Ok(f) => Some(f),
        Err(e @ Error::DataRead(_, _)) => return Err(e),
        Err(_) => None,
    };

    let vbmeta_offset = footer.as_ref().map_or(0, |f| f.vbmeta_offset);

    reader
        .seek(SeekFrom::Start(vbmeta_offset))
        .map_err(|e| Error::DataRead("vbmeta_offset", e))?;
    let header = Header::from_reader(&mut reader)?;

    Ok((header, footer, image_size))
}

/// Write a vbmeta header to the specified writer. This is meant for writing
/// vbmeta partition images, not appended vbmeta images. The writer must refer
/// to an empty file. Returns the size of the new file.
pub fn write_root_image(writer: impl Write, header: &Header, block_size: u64) -> Result<u64> {
    let mut counting_writer = CountingWriter::new(writer);

    header.to_writer(&mut counting_writer)?;
    padding::write_zeros(&mut counting_writer, block_size)
        .map_err(|e| Error::DataWrite("Root::header_padding", e))?;

    let image_size = counting_writer
        .stream_position()
        .map_err(|e| Error::DataWrite("Root::image_size", e))?;

    Ok(image_size)
}

/// Write a vbmeta header and footer to the specified writer. This is meant for
/// appending vbmeta data to existing partition data, not writing vbmeta images.
/// If `image_size` is specified, then the writer is guaranteed to not grow
/// past that size and an error is returned if the header and footer won't fit.
/// Otherwise, the writer will grow to the necessary size. Returns the size of
/// the new file.
pub fn write_appended_image(
    mut writer: impl Write + Seek,
    header: &Header,
    footer: &mut Footer,
    image_size: Option<u64>,
) -> Result<u64> {
    // avbtool hardcodes a 4096 block size for appended non-sparse images.
    const BLOCK_SIZE: u64 = 4096;

    // Logical image size, excluding the AVB header and footer.
    let logical_image_size = match header.appended_descriptor()? {
        AppendedDescriptorRef::HashTree(d) => d
            .image_size
            .checked_add(d.tree_size)
            .and_then(|s| s.checked_add(d.fec_size))
            .ok_or(Error::IntOverflow("Appended::logical_image_size"))?,
        AppendedDescriptorRef::Hash(d) => d.image_size,
    };

    writer
        .seek(SeekFrom::Start(logical_image_size))
        .map_err(|e| Error::DataWrite("Appended::logical_image_size", e))?;

    // The header start offset must be block aligned.
    let header_offset = {
        let padding_size = padding::write_zeros(&mut writer, BLOCK_SIZE)
            .map_err(|e| Error::DataWrite("Appended::pre_header_padding", e))?;
        logical_image_size
            .checked_add(padding_size)
            .ok_or(Error::IntOverflow("Appended::header_offset"))?
    };

    // The header lives at the beginning of the empty space.
    let mut header_buf = Cursor::new(Vec::new());
    header.to_writer(&mut header_buf)?;
    let header_size = header_buf
        .stream_position()
        .map_err(|e| Error::DataWrite("Appended::header_size", e))?;
    let header_padding = padding::write_zeros(&mut header_buf, BLOCK_SIZE)
        .map_err(|e| Error::DataWrite("Appended::header_padding", e))?;
    let header_end_padded = header_offset
        .checked_add(header_size)
        .and_then(|s| s.checked_add(header_padding))
        .ok_or(Error::IntOverflow("Appended::header_end_padded"))?;

    if let Some(s) = image_size {
        if header_end_padded > s {
            return Err(Error::TooSmallForHeader(s));
        }
    }

    writer
        .write_all(&header_buf.into_inner())
        .map_err(|e| Error::DataWrite("Appended::header", e))?;

    // The footer lives in its own separate block at the end of the empty space.
    let footer_end = if let Some(s) = image_size {
        if s - header_end_padded < BLOCK_SIZE {
            return Err(Error::TooSmallForFooter(s));
        }

        s
    } else {
        header_end_padded
            .checked_add(BLOCK_SIZE)
            .ok_or(Error::IntOverflow("Appended::footer_end"))?
    };

    let footer_offset = footer_end - Footer::SIZE as u64;
    writer
        .seek(SeekFrom::Start(footer_offset))
        .map_err(|e| Error::DataWrite("Appended::footer_offset", e))?;

    footer.original_image_size = match header.appended_descriptor()? {
        AppendedDescriptorRef::HashTree(d) => d.image_size,
        AppendedDescriptorRef::Hash(d) => d.image_size,
    };
    footer.vbmeta_offset = header_offset;
    footer.vbmeta_size = header_size;

    footer.to_writer(&mut writer)?;

    Ok(footer_end)
}
