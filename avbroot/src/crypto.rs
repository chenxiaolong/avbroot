// SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    env::{self, VarError},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::Duration,
};

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
        SignedData, SignerIdentifier, SignerInfo, SignerInfos,
    },
};
use passterm::PromptError;
use pkcs8::{
    pkcs5::{pbes2, scrypt},
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, EncryptedPrivateKeyInfo,
    LineEnding, PrivateKeyInfo,
};
use rand::RngCore;
use rsa::{
    pkcs1v15::SigningKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{pem::PemLabel, referenced::OwnedToRef, Any, Decode, DecodePem, EncodePem},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate,
};

use crate::util::DebugString;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("RSA key size ({}) not supported", .0 * 8)]
    UnsupportedKeySize(usize),
    #[error("Invalid digest length ({0} bytes) for {1:?}")]
    InvalidDigestLength(usize, SignatureAlgorithm),
    #[error("Invalid signature length ({0} bytes) for {1:?}")]
    InvalidSignatureLength(usize, SignatureAlgorithm),
    #[error("Failed to run command: {0:?}")]
    CommandSpawn(DebugString, #[source] io::Error),
    #[error("Command failed with status: {1}: {0:?}")]
    CommandExecution(DebugString, ExitStatus),
    #[error("Signature from signing helper does not match public key: {0:?}")]
    SigningHelperBadSignature(PathBuf),
    #[error("Passphrase prompt requires an interactive terminal")]
    NotInteractive(#[source] io::Error),
    #[error("Failed to prompt for passphrase")]
    PassphrasePrompt(#[source] PromptError),
    #[error("Passphrases do not match")]
    ConfirmPassphrase,
    #[error("Failed to read environment variable: {0:?}")]
    InvalidEnvVar(OsString, #[source] VarError),
    #[error("PEM has start tag, but no end tag")]
    PemNoEndTag,
    #[error("Failed to load encrypted RSA private key")]
    LoadKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to load unencrypted RSA private key")]
    LoadKeyUnencrypted(#[source] pkcs8::Error),
    #[error("Failed to save encrypted RSA private key")]
    SaveKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to save unencrypted RSA private key")]
    SaveKeyUnencrypted(#[source] pkcs8::Error),
    #[error("Failed to load RSA public key")]
    LoadPubKey(#[source] pkcs8::spki::Error),
    #[error("Failed to save RSA public key")]
    SavePubKey(#[source] pkcs8::spki::Error),
    #[error("Failed to load X509 certificate")]
    LoadCert(#[source] x509_cert::der::Error),
    #[error("Failed to save X509 certificate")]
    SaveCert(#[source] x509_cert::der::Error),
    #[error("Failed to generate RSA key")]
    RsaGenerate(#[source] Box<rsa::Error>),
    #[error("Failed to RSA sign digest")]
    RsaSign(#[source] Box<rsa::Error>),
    #[error("Failed to RSA verify signature")]
    RsaVerify(#[source] Box<rsa::Error>),
    #[error("Failed to generate X509 certificate")]
    CertGenerate(#[source] x509_cert::builder::Error),
    #[error("Invalid parameters for X509 certificate generation")]
    CertParams(#[source] x509_cert::der::Error),
    #[error("Failed to CMS sign digest")]
    CmsSign(#[source] x509_cert::der::Error),
    #[error("Failed to parse CMS signature")]
    CmsParse(#[source] x509_cert::der::Error),
    #[error("Failed to read file: {0:?}")]
    ReadFile(PathBuf, #[source] io::Error),
    #[error("Failed to write file: {0:?}")]
    WriteFile(PathBuf, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SignatureAlgorithm {
    Sha1WithRsa,
    Sha256WithRsa,
    Sha512WithRsa,
}

impl SignatureAlgorithm {
    /// Length of digest required by the signing algorithm.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1WithRsa => Sha1::output_size(),
            Self::Sha256WithRsa => Sha256::output_size(),
            Self::Sha512WithRsa => Sha512::output_size(),
        }
    }

    /// Compute the digest of the specified data.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1WithRsa => Sha1::digest(data).to_vec(),
            Self::Sha256WithRsa => Sha256::digest(data).to_vec(),
            Self::Sha512WithRsa => Sha512::digest(data).to_vec(),
        }
    }
}

#[derive(Clone)]
pub enum PassphraseSource {
    Prompt(String),
    EnvVar(OsString),
    File(PathBuf),
}

impl PassphraseSource {
    pub fn new(key_file: &Path, pass_file: Option<&Path>, env_var: Option<&OsStr>) -> Self {
        #[allow(clippy::option_if_let_else)]
        if let Some(v) = env_var {
            Self::EnvVar(v.to_owned())
        } else if let Some(p) = pass_file {
            Self::File(p.to_owned())
        } else {
            Self::Prompt(format!("Enter passphrase for {key_file:?}: "))
        }
    }

    fn prompt(prompt: &str) -> Result<String> {
        match passterm::prompt_password_tty(Some(prompt)) {
            Ok(p) => Ok(p),
            Err(e) => {
                #[cfg(unix)]
                if let PromptError::IOError(io_e) = e {
                    if let Some(errno) = io_e.raw_os_error() {
                        if errno == libc::ENXIO || errno == libc::ENOTTY {
                            return Err(Error::NotInteractive(io_e));
                        }
                    }

                    return Err(Error::PassphrasePrompt(PromptError::IOError(io_e)));
                }

                Err(Error::PassphrasePrompt(e))
            }
        }
    }

    pub fn acquire(&self, confirm: bool) -> Result<String> {
        let passphrase = match self {
            Self::Prompt(p) => {
                let first = Self::prompt(p)?;

                if confirm {
                    let second = Self::prompt("Confirm: ")?;

                    if first != second {
                        return Err(Error::ConfirmPassphrase);
                    }
                }

                first
            }
            Self::EnvVar(v) => env::var(v).map_err(|e| Error::InvalidEnvVar(v.clone(), e))?,
            Self::File(p) => fs::read_to_string(p)
                .map_err(|e| Error::ReadFile(p.clone(), e))?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        };

        Ok(passphrase)
    }
}

fn check_key_size(size: usize) -> Result<()> {
    // RustCrypto does not support 8192-bit keys.
    if size > 4096 / 8 {
        return Err(Error::UnsupportedKeySize(size));
    }

    Ok(())
}

/// Copied from rsa-0.9.6 since the function is not exported.
fn pkcs1v15_sign_pad(prefix: &[u8], hashed: &[u8], k: usize) -> rsa::Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(rsa::Error::MessageTooLong);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}

#[derive(Clone)]
pub enum RsaSigningKey {
    Internal(RsaPrivateKey),
    External {
        program: PathBuf,
        public_key_file: PathBuf,
        public_key: RsaPublicKey,
        passphrase_source: PassphraseSource,
    },
}

impl RsaSigningKey {
    /// Size of key in bytes.
    pub fn size(&self) -> usize {
        match self {
            Self::Internal(key) => key.size(),
            Self::External { public_key, .. } => public_key.size(),
        }
    }

    /// Get the public key portion of the signing key.
    pub fn to_public_key(&self) -> RsaPublicKey {
        match self {
            Self::Internal(key) => key.to_public_key(),
            Self::External { public_key, .. } => public_key.clone(),
        }
    }

    /// Sign the digest with the specified signature algorithm.
    pub fn sign(&self, algo: SignatureAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != algo.digest_len() {
            return Err(Error::InvalidDigestLength(digest.len(), algo));
        }

        check_key_size(self.size())?;

        let scheme = match algo {
            // We don't support signing with insecure algorithms.
            SignatureAlgorithm::Sha1WithRsa => return Err(Error::UnsupportedAlgorithm(algo)),
            SignatureAlgorithm::Sha256WithRsa => Pkcs1v15Sign::new::<Sha256>(),
            SignatureAlgorithm::Sha512WithRsa => Pkcs1v15Sign::new::<Sha512>(),
        };

        match self {
            Self::Internal(key) => key
                .sign(scheme, digest)
                .map_err(|e| Error::RsaSign(Box::new(e))),
            Self::External {
                program,
                public_key,
                public_key_file,
                passphrase_source,
            } => {
                let key_bits = public_key.size() * 8;
                let algo_str = match algo {
                    SignatureAlgorithm::Sha1WithRsa => unreachable!(),
                    SignatureAlgorithm::Sha256WithRsa => format!("SHA256_RSA{key_bits}"),
                    SignatureAlgorithm::Sha512WithRsa => format!("SHA512_RSA{key_bits}"),
                };

                let mut command = Command::new(program);
                command.arg(algo_str);
                command.arg(public_key_file);

                match passphrase_source {
                    PassphraseSource::Prompt(_) => {}
                    PassphraseSource::EnvVar(v) => {
                        command.arg("env");
                        command.arg(v);
                    }
                    PassphraseSource::File(p) => {
                        command.arg("file");
                        command.arg(p);
                    }
                }

                command.stdin(Stdio::piped());
                command.stdout(Stdio::piped());
                command.stderr(Stdio::inherit());

                let mut child = command
                    .spawn()
                    .map_err(|e| Error::CommandSpawn(DebugString::new(&command), e))?;

                // We don't bother with spawning a thread. The pipe capacity on
                // all major OSs is significantly larger than the digest, so we
                // don't risk deadlocking even if the process doesn't read from
                // stdin.
                //
                // Pipe capacities:
                // * Linux: 64 KiB
                // * macOS: 4 KiB, 16 KiB (usually), or 64 KiB
                // * Windows: 4 KiB

                let padded_digest = pkcs1v15_sign_pad(&scheme.prefix, digest, public_key.size())
                    .map_err(|e| Error::RsaSign(Box::new(e)))?;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(&padded_digest)
                    .map_err(|e| Error::WriteFile("<signing helper stdin>".into(), e))?;

                let child = child
                    .wait_with_output()
                    .map_err(|e| Error::CommandSpawn(DebugString::new(&command), e))?;

                if !child.status.success() {
                    return Err(Error::CommandExecution(
                        DebugString::new(&command),
                        child.status,
                    ));
                } else if child.stdout.len() != self.size() {
                    return Err(Error::InvalidSignatureLength(child.stdout.len(), algo));
                }

                // Check that the helper signed with the proper key.
                if let Err(e) = self.to_public_key().verify_sig(algo, digest, &child.stdout) {
                    return match e {
                        Error::RsaVerify(_) => {
                            Err(Error::SigningHelperBadSignature(public_key_file.clone()))
                        }
                        e => Err(e),
                    };
                }

                Ok(child.stdout)
            }
        }
    }
}

pub trait RsaPublicKeyExt {
    fn verify_sig(&self, algo: SignatureAlgorithm, digest: &[u8], signature: &[u8]) -> Result<()>;
}

impl RsaPublicKeyExt for RsaPublicKey {
    /// Verify the signature against the specified key.
    fn verify_sig(&self, algo: SignatureAlgorithm, digest: &[u8], signature: &[u8]) -> Result<()> {
        // Check this explicitly so we can provide a better error message.
        if digest.len() != algo.digest_len() {
            return Err(Error::InvalidDigestLength(digest.len(), algo));
        }

        check_key_size(self.size())?;

        let scheme = match algo {
            SignatureAlgorithm::Sha1WithRsa => Pkcs1v15Sign::new::<Sha1>(),
            SignatureAlgorithm::Sha256WithRsa => Pkcs1v15Sign::new::<Sha256>(),
            SignatureAlgorithm::Sha512WithRsa => Pkcs1v15Sign::new::<Sha512>(),
        };

        self.verify(scheme, digest, signature)
            .map_err(|e| Error::RsaVerify(Box::new(e)))
    }
}

/// Generate an 4096-bit RSA key pair.
pub fn generate_rsa_key_pair() -> Result<RsaPrivateKey> {
    let mut rng = rand::thread_rng();

    // avbroot supports 4096-bit keys only.
    let key = RsaPrivateKey::new(&mut rng, 4096).map_err(|e| Error::RsaGenerate(Box::new(e)))?;

    Ok(key)
}

/// Generate a self-signed certificate.
pub fn generate_cert(
    key: &RsaPrivateKey,
    serial: u64,
    validity: Duration,
    subject: &str,
) -> Result<Certificate> {
    let public_key_der = key
        .to_public_key()
        .to_public_key_der()
        .map_err(Error::SavePubKey)?;
    let signing_key = SigningKey::<Sha256>::new(key.clone());

    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(serial),
        Validity::from_now(validity).map_err(Error::CertParams)?,
        subject.parse().map_err(Error::CertParams)?,
        SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
            .map_err(Error::CertParams)?,
        &signing_key,
    )
    .map_err(Error::CertGenerate)?;

    let mut rng = rand::thread_rng();
    let cert = builder
        .build_with_rng(&mut rng)
        .map_err(Error::CertGenerate)?;

    Ok(cert)
}

/// x509_cert/pem follow rfc7468 strictly instead of implementing a lenient
/// parser. The PEM decoder rejects lines in the base64 section that are longer
/// than 64 characters, excluding whitespace. We'll reformat the data to deal
/// with this because there are certificates that do not follow the spec, like
/// the signing cert for the Pixel 7 Pro official OTAs.
fn reformat_pem(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = vec![];
    let mut base64 = vec![];
    let mut inside_base64 = false;

    for mut line in data.split(|&c| c == b'\n') {
        while !line.is_empty() && line[line.len() - 1].is_ascii_whitespace() {
            line = &line[..line.len() - 1];
        }

        if line.is_empty() {
            continue;
        } else if line.starts_with(b"-----BEGIN CERTIFICATE-----") {
            inside_base64 = true;

            result.extend_from_slice(line);
            result.push(b'\n');
        } else if line.starts_with(b"-----END CERTIFICATE-----") {
            inside_base64 = false;

            for chunk in base64.chunks(64) {
                result.extend_from_slice(chunk);
                result.push(b'\n');
            }

            base64.clear();

            result.extend_from_slice(line);
            result.push(b'\n');
        } else if inside_base64 {
            base64.extend_from_slice(line);
            continue;
        }
    }

    if inside_base64 {
        return Err(Error::PemNoEndTag);
    }

    Ok(result)
}

/// Read PEM-encoded certificate from a reader.
pub fn read_pem_cert(path: &Path, mut reader: impl Read) -> Result<Certificate> {
    let mut data = vec![];
    reader
        .read_to_end(&mut data)
        .map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    let data = reformat_pem(&data)?;
    let certificate = Certificate::from_pem(data).map_err(Error::LoadCert)?;

    Ok(certificate)
}

/// Write PEM-encoded certificate to a writer.
pub fn write_pem_cert(path: &Path, mut writer: impl Write, cert: &Certificate) -> Result<()> {
    let data = cert.to_pem(LineEnding::LF).map_err(Error::SaveCert)?;

    writer
        .write_all(data.as_bytes())
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    Ok(())
}

/// Read PEM-encoded certificate from a file.
pub fn read_pem_cert_file(path: &Path) -> Result<Certificate> {
    let reader = File::open(path).map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    read_pem_cert(path, reader)
}

/// Write PEM-encoded certificate to a file.
pub fn write_pem_cert_file(path: &Path, cert: &Certificate) -> Result<()> {
    let writer = File::create(path).map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    write_pem_cert(path, writer, cert)
}

/// Read PEM-encoded PKCS8 public key from a reader.
pub fn read_pem_public_key(path: &Path, mut reader: impl Read) -> Result<RsaPublicKey> {
    let mut data = String::new();
    reader
        .read_to_string(&mut data)
        .map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    let key = RsaPublicKey::from_public_key_pem(&data).map_err(Error::LoadPubKey)?;

    Ok(key)
}

/// Write PEM-encoded PKCS8 public key to a writer.
pub fn write_pem_public_key(path: &Path, mut writer: impl Write, key: &RsaPublicKey) -> Result<()> {
    let data = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(Error::SavePubKey)?;

    writer
        .write_all(data.as_bytes())
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    Ok(())
}

/// Read PEM-encoded PKCS8 public key from a file.
pub fn read_pem_public_key_file(path: &Path) -> Result<RsaPublicKey> {
    let reader = File::open(path).map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    read_pem_public_key(path, reader)
}

/// Write PEM-encoded PKCS8 public key to a file.
pub fn write_pem_public_key_file(path: &Path, key: &RsaPublicKey) -> Result<()> {
    let writer = File::create(path).map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    write_pem_public_key(path, writer, key)
}

/// Read PEM-encoded PKCS8 private key from a reader.
pub fn read_pem_key(
    path: &Path,
    mut reader: impl Read,
    source: &PassphraseSource,
) -> Result<RsaPrivateKey> {
    let mut data = String::new();
    reader
        .read_to_string(&mut data)
        .map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    if data.contains("ENCRYPTED") {
        let passphrase = source.acquire(false)?;

        RsaPrivateKey::from_pkcs8_encrypted_pem(&data, passphrase).map_err(Error::LoadKeyEncrypted)
    } else {
        RsaPrivateKey::from_pkcs8_pem(&data).map_err(Error::LoadKeyUnencrypted)
    }
}

/// Write PEM-encoded PKCS8 private key to a writer.
pub fn write_pem_key(
    path: &Path,
    mut writer: impl Write,
    key: &RsaPrivateKey,
    source: &PassphraseSource,
) -> Result<()> {
    let passphrase = source.acquire(true)?;

    let data = if passphrase.is_empty() {
        key.to_pkcs8_pem(LineEnding::LF)
            .map_err(Error::SaveKeyUnencrypted)?
    } else {
        let mut rng = rand::thread_rng();

        // Normally, we'd just use key.to_pkcs8_encrypted_pem(). However, it
        // uses scrypt with n = 32768. This is high enough that openssl can no
        // longer read the file and craps out with `memory limit exceeded`.
        // Although we can read those files just fine, let's match openssl's
        // default parameters for better compatibility.
        //
        // Per `man openssl-pkcs8`: -scrypt  Uses the scrypt algorithm for
        // private key encryption using default parameters: currently N=16384,
        // r=8 and p=1 and AES in CBC mode with a 256 bit key.
        //
        // https://github.com/RustCrypto/formats/issues/1205

        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        // 14 = log_2(16384), 32 bytes = 256 bits
        let scrypt_params = scrypt::Params::new(14, 8, 1, 32).unwrap();
        let pbes2_params = pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv).unwrap();

        let plain_text_der = key.to_pkcs8_der().map_err(Error::SaveKeyEncrypted)?;
        let private_key_info =
            PrivateKeyInfo::try_from(plain_text_der.as_bytes()).map_err(Error::SaveKeyEncrypted)?;

        let secret_doc = private_key_info
            .encrypt_with_params(pbes2_params, passphrase)
            .map_err(Error::SaveKeyEncrypted)?;

        secret_doc
            .to_pem(EncryptedPrivateKeyInfo::PEM_LABEL, LineEnding::LF)
            .map_err(pkcs8::Error::Asn1)
            .map_err(Error::SaveKeyEncrypted)?
    };

    writer
        .write_all(data.as_bytes())
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    Ok(())
}

/// Read PEM-encoded PKCS8 private key from a file.
pub fn read_pem_key_file(path: &Path, source: &PassphraseSource) -> Result<RsaPrivateKey> {
    let reader = File::open(path).map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    read_pem_key(path, reader, source)
}

/// Save PEM-encoded PKCS8 private key to a file.
pub fn write_pem_key_file(
    path: &Path,
    key: &RsaPrivateKey,
    source: &PassphraseSource,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    options.create(true);
    options.truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let writer = options
        .open(path)
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    write_pem_key(path, writer, key, source)
}

/// Get the RSA public key from a certificate.
pub fn get_public_key(cert: &Certificate) -> Result<RsaPublicKey> {
    let public_key =
        RsaPublicKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref())
            .map_err(Error::LoadPubKey)?;

    Ok(public_key)
}

/// Check if a certificate matches a private key.
pub fn cert_matches_key(cert: &Certificate, key: &RsaSigningKey) -> Result<bool> {
    let public_key = get_public_key(cert)?;

    Ok(key.to_public_key() == public_key)
}

/// Parse a CMS [`SignedData`] structure from raw DER-encoded data.
pub fn parse_cms(data: &[u8]) -> Result<SignedData> {
    let ci = ContentInfo::from_der(data).map_err(Error::CmsParse)?;
    let sd = ci
        .content
        .decode_as::<SignedData>()
        .map_err(Error::CmsParse)?;

    Ok(sd)
}

/// Get an iterator to all standard X509 certificates contained within a
/// [`SignedData`] structure.
pub fn iter_cms_certs(sd: &SignedData) -> impl Iterator<Item = &Certificate> {
    sd.certificates.iter().flat_map(|certs| {
        certs.0.iter().filter_map(|cc| {
            if let CertificateChoices::Certificate(c) = cc {
                Some(c)
            } else {
                None
            }
        })
    })
}

/// Create a CMS signature from an external digest. This implementation does not
/// use signed attributes because AOSP recovery's otautil/verifier.cpp is not
/// actually CMS compliant. It simply uses the CMS [`SignedData`] structure as
/// a transport mechanism for a raw signature. Thus, we need to ensure that the
/// signature covers nothing but the raw data.
pub fn cms_sign_external(
    key: &RsaSigningKey,
    cert: &Certificate,
    digest: &[u8],
) -> Result<ContentInfo> {
    let signature = key.sign(SignatureAlgorithm::Sha256WithRsa, digest)?;

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::try_from(vec![digest_algorithm.clone()])
            .map_err(Error::CmsSign)?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        },
        certificates: Some(
            CertificateSet::try_from(vec![CertificateChoices::Certificate(cert.clone())])
                .map_err(Error::CmsSign)?,
        ),
        crls: None,
        signer_infos: SignerInfos::try_from(vec![SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: cert.tbs_certificate.issuer.clone(),
                serial_number: cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: digest_algorithm,
            signed_attrs: None,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                parameters: None,
            },
            signature: SignatureValue::new(signature).map_err(Error::CmsSign)?,
            unsigned_attrs: None,
        }])
        .map_err(Error::CmsSign)?,
    };

    let signed_data = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).map_err(Error::CmsSign)?,
    };

    Ok(signed_data)
}
