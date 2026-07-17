// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    borrow::Cow,
    env::{self, VarError},
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::Duration,
};

use clap::ValueEnum;
use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
        SignedData, SignerIdentifier, SignerInfo, SignerInfos,
    },
};
use der::{
    Any, Decode, DecodePem, EncodePem, SecretDocument, pem::PemLabel, referenced::OwnedToRef,
};
use ml_dsa::{
    EncodedSignature, Generate, Keypair, MlDsa65, MlDsa87, Signer, Verifier, VerifyingKey,
};
use passterm::PromptError;
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
    EncryptedPrivateKeyInfoRef, LineEnding, PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
    spki::{self, AssociatedAlgorithmIdentifier},
};
use rand::{
    Rng, SeedableRng,
    rngs::{StdRng, SysRng},
};
use rsa::{
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, pkcs1, pkcs1v15, signature::RandomizedSigner,
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x509_cert::{
    Certificate, TbsCertificate,
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    ext::ToExtension,
    ext::{
        Extension,
        pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier},
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
};

use crate::util::DebugString;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("ML-DSA does not support signing/verifying digests")]
    UnsupportedMlDsaDigest,
    #[error("Invalid signature algorithm {0:?} for key type: {1:?}")]
    InvalidAlgorithmForKey(SignatureAlgorithm, SigningKeyType),
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
    #[error("Generating certificate from external key not supported")]
    CertGenerateExternalKey,
    #[error("Failed to load encrypted private key")]
    LoadKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to load unencrypted private key")]
    LoadKeyUnencrypted(#[source] pkcs8::Error),
    #[error("Failed to save encrypted private key")]
    SaveKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to save unencrypted private key")]
    SaveKeyUnencrypted(#[source] pkcs8::Error),
    #[error("Failed to load public key")]
    LoadPubKey(#[source] spki::Error),
    #[error("Failed to save public key")]
    SavePubKey(#[source] spki::Error),
    #[error("Failed to load X509 certificate")]
    LoadCert(#[source] der::Error),
    #[error("Failed to save X509 certificate")]
    SaveCert(#[source] der::Error),
    #[error("Failed to initialize RNG")]
    RngInit(#[source] rand::rngs::SysError),
    #[error("Failed to generate RSA key")]
    RsaGenerate(#[source] Box<rsa::Error>),
    #[error("Failed to perform RSA signing")]
    RsaSign(#[source] Box<rsa::Error>),
    #[error("Failed to perform RSA verification")]
    RsaVerify(#[source] Box<rsa::Error>),
    #[error("Failed to perform ML-DSA signing")]
    MlDsaSign(#[source] ml_dsa::Error),
    #[error("Failed to perform ML-DSA verification")]
    MlDsaVerify(#[source] ml_dsa::Error),
    #[error("Failed to generate X509 certificate")]
    CertGenerate(#[source] x509_cert::builder::Error),
    #[error("Invalid parameters for X509 certificate generation")]
    CertParams(#[source] der::Error),
    #[error("Failed to CMS sign digest")]
    CmsSign(#[source] der::Error),
    #[error("Failed to parse CMS signature")]
    CmsParse(#[source] der::Error),
    #[error("Failed to read file: {0:?}")]
    ReadFile(PathBuf, #[source] io::Error),
    #[error("Failed to write file: {0:?}")]
    WriteFile(PathBuf, #[source] io::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SignatureAlgorithm {
    Sha1WithRsa,
    Sha256WithRsa,
    Sha512WithRsa,
    MlDsa65,
    MlDsa87,
}

impl SignatureAlgorithm {
    /// Length of digest required by the signing algorithm.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1WithRsa => Sha1::output_size(),
            Self::Sha256WithRsa => Sha256::output_size(),
            Self::Sha512WithRsa => Sha512::output_size(),
            Self::MlDsa65 | Self::MlDsa87 => 0,
        }
    }

    /// Compute the digest of the specified data.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1WithRsa => Sha1::digest(data).to_vec(),
            Self::Sha256WithRsa => Sha256::digest(data).to_vec(),
            Self::Sha512WithRsa => Sha512::digest(data).to_vec(),
            Self::MlDsa65 | Self::MlDsa87 => vec![],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
                    if let Some(errno) = io_e.raw_os_error()
                        && (errno == libc::ENXIO || errno == libc::ENOTTY)
                    {
                        return Err(Error::NotInteractive(io_e));
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyType {
    /// Size in bytes.
    Rsa(usize),
    MlDsa65,
    MlDsa87,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningContent<'a> {
    Data(&'a [u8]),
    Digest(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum SigningMethod {
    #[default]
    Deterministic,
    NonDeterministic,
}

impl fmt::Display for SigningMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_possible_value().ok_or(fmt::Error)?.get_name())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SigningPublicKey {
    Rsa(RsaPublicKey),
    MlDsa65(VerifyingKey<MlDsa65>),
    MlDsa87(VerifyingKey<MlDsa87>),
}

impl SigningPublicKey {
    pub fn key_type(&self) -> SigningKeyType {
        match self {
            Self::Rsa(key) => SigningKeyType::Rsa(key.size()),
            Self::MlDsa65(_) => SigningKeyType::MlDsa65,
            Self::MlDsa87(_) => SigningKeyType::MlDsa87,
        }
    }

    /// Verify the signature of the content.
    ///
    /// * [`SigningContent::Data`] is supported for both RSA and ML-DSA.
    /// * [`SigningContent::Digest`] is only supported for RSA.
    pub fn verify(
        &self,
        algo: SignatureAlgorithm,
        content: SigningContent,
        signature: &[u8],
    ) -> Result<()> {
        let key_type = self.key_type();

        match self {
            Self::Rsa(key) => {
                let scheme = match algo {
                    SignatureAlgorithm::Sha1WithRsa => Pkcs1v15Sign::new::<Sha1>(),
                    SignatureAlgorithm::Sha256WithRsa => Pkcs1v15Sign::new::<Sha256>(),
                    SignatureAlgorithm::Sha512WithRsa => Pkcs1v15Sign::new::<Sha512>(),
                    _ => return Err(Error::InvalidAlgorithmForKey(algo, key_type)),
                };

                let digest = match content {
                    SigningContent::Data(data) => Cow::Owned(algo.hash(data)),
                    SigningContent::Digest(digest) => Cow::Borrowed(digest),
                };

                // Check this explicitly to return a better error message.
                if digest.len() != algo.digest_len() {
                    return Err(Error::InvalidDigestLength(digest.len(), algo));
                }

                key.verify(scheme, &digest, signature)
                    .map_err(|e| Error::RsaSign(Box::new(e)))
            }
            Self::MlDsa65(key) => {
                if algo != SignatureAlgorithm::MlDsa65 {
                    return Err(Error::InvalidAlgorithmForKey(algo, key_type));
                }

                let SigningContent::Data(data) = content else {
                    return Err(Error::UnsupportedMlDsaDigest);
                };

                let ml_dsa_signature = EncodedSignature::<MlDsa65>::try_from(signature)
                    .ok()
                    .and_then(|enc| ml_dsa::Signature::decode(&enc))
                    .ok_or_else(|| Error::InvalidSignatureLength(signature.len(), algo))?;

                key.verify(data, &ml_dsa_signature)
                    .map_err(Error::MlDsaVerify)
            }
            Self::MlDsa87(key) => {
                if algo != SignatureAlgorithm::MlDsa87 {
                    return Err(Error::InvalidAlgorithmForKey(algo, key_type));
                }

                let SigningContent::Data(data) = content else {
                    return Err(Error::UnsupportedMlDsaDigest);
                };

                let ml_dsa_signature = EncodedSignature::<MlDsa87>::try_from(signature)
                    .ok()
                    .and_then(|enc| ml_dsa::Signature::decode(&enc))
                    .ok_or_else(|| Error::InvalidSignatureLength(signature.len(), algo))?;

                key.verify(data, &ml_dsa_signature)
                    .map_err(Error::MlDsaVerify)
            }
        }
    }
}

impl EncodePublicKey for SigningPublicKey {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        match self {
            Self::Rsa(key) => key.to_public_key_der(),
            Self::MlDsa65(key) => key.to_public_key_der(),
            Self::MlDsa87(key) => key.to_public_key_der(),
        }
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for SigningPublicKey {
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        match spki.algorithm {
            a if a == pkcs1::ALGORITHM_ID => RsaPublicKey::try_from(spki).map(Self::Rsa),
            a if a == MlDsa65::ALGORITHM_IDENTIFIER => {
                VerifyingKey::try_from(spki).map(Self::MlDsa65)
            }
            a if a == MlDsa87::ALGORITHM_IDENTIFIER => {
                VerifyingKey::try_from(spki).map(Self::MlDsa87)
            }
            a => Err(spki::Error::OidUnknown { oid: a.oid }),
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum SigningPrivateKey {
    Rsa(RsaPrivateKey),
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<MlDsa87>),
    External {
        program: PathBuf,
        public_key_file: PathBuf,
        public_key: SigningPublicKey,
        passphrase_source: PassphraseSource,
    },
}

impl SigningPrivateKey {
    pub fn generate(key_type: SigningKeyType) -> Result<Self> {
        let mut rng = csprng()?;

        match key_type {
            SigningKeyType::Rsa(bytes) => {
                let key = RsaPrivateKey::new(&mut rng, bytes * 8)
                    .map_err(|e| Error::RsaGenerate(Box::new(e)))?;

                Ok(Self::Rsa(key))
            }
            SigningKeyType::MlDsa65 => {
                let key = ml_dsa::SigningKey::generate_from_rng(&mut rng);

                Ok(Self::MlDsa65(key))
            }
            SigningKeyType::MlDsa87 => {
                let key = ml_dsa::SigningKey::generate_from_rng(&mut rng);

                Ok(Self::MlDsa87(key))
            }
        }
    }

    pub fn key_type(&self) -> SigningKeyType {
        self.to_public_key().key_type()
    }

    pub fn to_public_key(&self) -> SigningPublicKey {
        match self {
            Self::Rsa(key) => SigningPublicKey::Rsa(key.to_public_key()),
            Self::MlDsa65(key) => SigningPublicKey::MlDsa65(key.verifying_key()),
            Self::MlDsa87(key) => SigningPublicKey::MlDsa87(key.verifying_key()),
            Self::External { public_key, .. } => public_key.clone(),
        }
    }

    /// Sign the data using an external program. For compatibility with AOSP's
    /// avbtool:
    ///
    /// * For RSA, a PKCS#1 v1.5 padded digest is passed to the program, which
    ///   is expected to perform a raw RSA signing operation.
    /// * For ML-DSA, the actual data is passed to the program.
    ///
    /// In either case, the resulting signature will be verified against the
    /// public key before returning.
    fn sign_external(&self, algo: SignatureAlgorithm, content: SigningContent) -> Result<Vec<u8>> {
        let Self::External {
            program,
            public_key,
            public_key_file,
            passphrase_source,
        } = self
        else {
            panic!("Not an external key");
        };

        let key_type = self.key_type();
        let algo_str = match (algo, key_type) {
            (SignatureAlgorithm::Sha1WithRsa, SigningKeyType::Rsa(_)) => {
                return Err(Error::UnsupportedAlgorithm(algo));
            }
            (SignatureAlgorithm::Sha256WithRsa, SigningKeyType::Rsa(bytes)) => {
                format!("SHA256_RSA{}", bytes * 8)
            }
            (SignatureAlgorithm::Sha512WithRsa, SigningKeyType::Rsa(bytes)) => {
                format!("SHA512_RSA{}", bytes * 8)
            }
            (SignatureAlgorithm::MlDsa65, SigningKeyType::MlDsa65) => "MLDSA65".to_owned(),
            (SignatureAlgorithm::MlDsa87, SigningKeyType::MlDsa87) => "MLDSA87".to_owned(),
            (_, key_type) => return Err(Error::InvalidAlgorithmForKey(algo, key_type)),
        };

        let to_sign = match key_type {
            SigningKeyType::Rsa(bytes) => {
                let scheme = match algo {
                    SignatureAlgorithm::Sha256WithRsa => Pkcs1v15Sign::new::<Sha256>(),
                    SignatureAlgorithm::Sha512WithRsa => Pkcs1v15Sign::new::<Sha512>(),
                    _ => unreachable!(),
                };

                let digest = match content {
                    SigningContent::Data(data) => Cow::Owned(algo.hash(data)),
                    SigningContent::Digest(digest) => Cow::Borrowed(digest),
                };

                if digest.len() != algo.digest_len() {
                    return Err(Error::InvalidDigestLength(digest.len(), algo));
                }

                pkcs1v15_sign_pad(&scheme.prefix, &digest, bytes)
                    .map(Cow::Owned)
                    .map_err(|e| Error::RsaSign(Box::new(e)))?
            }
            SigningKeyType::MlDsa65 | SigningKeyType::MlDsa87 => {
                let SigningContent::Data(data) = content else {
                    return Err(Error::UnsupportedMlDsaDigest);
                };

                Cow::Borrowed(data)
            }
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

        let stdin_result = child
            .stdin
            .take()
            .unwrap()
            .write_all(&to_sign)
            .map_err(|e| Error::WriteFile("<signing helper stdin>".into(), e));

        let result = child
            .wait_with_output()
            .map_err(|e| Error::CommandSpawn(DebugString::new(&command), e))?;

        stdin_result?;

        if !result.status.success() {
            return Err(Error::CommandExecution(
                DebugString::new(&command),
                result.status,
            ));
        }

        // Check that the helper signed with the proper key.
        if let Err(e) = public_key.verify(algo, content, &result.stdout) {
            return match e {
                Error::RsaVerify(_) => {
                    Err(Error::SigningHelperBadSignature(public_key_file.clone()))
                }
                e => Err(e),
            };
        }

        Ok(result.stdout)
    }

    /// Sign the specified content.
    ///
    /// * [`SigningContent::Data`] is supported for both RSA and ML-DSA.
    /// * [`SigningContent::Digest`] is only supported for RSA.
    pub fn sign(
        &self,
        method: SigningMethod,
        algo: SignatureAlgorithm,
        content: SigningContent,
    ) -> Result<Vec<u8>> {
        let key_type = self.key_type();

        match self {
            Self::Rsa(key) => {
                let scheme = match algo {
                    // We don't support signing with insecure algorithms.
                    SignatureAlgorithm::Sha1WithRsa => {
                        return Err(Error::UnsupportedAlgorithm(algo));
                    }
                    SignatureAlgorithm::Sha256WithRsa => Pkcs1v15Sign::new::<Sha256>(),
                    SignatureAlgorithm::Sha512WithRsa => Pkcs1v15Sign::new::<Sha512>(),
                    _ => return Err(Error::InvalidAlgorithmForKey(algo, key_type)),
                };

                let digest = match content {
                    SigningContent::Data(data) => Cow::Owned(algo.hash(data)),
                    SigningContent::Digest(digest) => Cow::Borrowed(digest),
                };

                if digest.len() != algo.digest_len() {
                    return Err(Error::InvalidDigestLength(digest.len(), algo));
                }

                // PKCS#1 v1.5 signatures are always deterministic.
                key.sign(scheme, &digest)
                    .map_err(|e| Error::RsaSign(Box::new(e)))
            }
            Self::MlDsa65(key) => {
                if algo != SignatureAlgorithm::MlDsa65 {
                    return Err(Error::InvalidAlgorithmForKey(algo, key_type));
                }

                let SigningContent::Data(data) = content else {
                    return Err(Error::UnsupportedMlDsaDigest);
                };

                let signature = match method {
                    SigningMethod::Deterministic => key.try_sign(data).map_err(Error::MlDsaSign)?,
                    SigningMethod::NonDeterministic => {
                        let mut rng = csprng()?;

                        key.expanded_key()
                            .try_sign_with_rng(&mut rng, data)
                            .map_err(Error::MlDsaSign)?
                    }
                };

                Ok(signature.encode().into())
            }
            Self::MlDsa87(key) => {
                if algo != SignatureAlgorithm::MlDsa87 {
                    return Err(Error::InvalidAlgorithmForKey(algo, key_type));
                }

                let SigningContent::Data(data) = content else {
                    return Err(Error::UnsupportedMlDsaDigest);
                };

                let signature = match method {
                    SigningMethod::Deterministic => key.try_sign(data).map_err(Error::MlDsaSign)?,
                    SigningMethod::NonDeterministic => {
                        let mut rng = csprng()?;

                        key.expanded_key()
                            .try_sign_with_rng(&mut rng, data)
                            .map_err(Error::MlDsaSign)?
                    }
                };

                Ok(signature.encode().into())
            }
            // sign_external() will check that the algorithm is compatible with
            // the key. The signing method is ignored.
            Self::External { .. } => self.sign_external(algo, content),
        }
    }
}

impl EncodePrivateKey for SigningPrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        match self {
            Self::Rsa(key) => key.to_pkcs8_der(),
            Self::MlDsa65(key) => key.to_pkcs8_der(),
            Self::MlDsa87(key) => key.to_pkcs8_der(),
            // There's not really a good error we can return here.
            Self::External { .. } => Err(pkcs8::Error::KeyMalformed(pkcs8::KeyError::Invalid)),
        }
    }
}

impl TryFrom<PrivateKeyInfoRef<'_>> for SigningPrivateKey {
    type Error = pkcs8::Error;

    fn try_from(private_key_info: PrivateKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        match private_key_info.algorithm {
            a if a == pkcs1::ALGORITHM_ID => {
                RsaPrivateKey::try_from(private_key_info).map(Self::Rsa)
            }
            a if a == MlDsa65::ALGORITHM_IDENTIFIER => {
                ml_dsa::SigningKey::try_from(private_key_info).map(Self::MlDsa65)
            }
            a if a == MlDsa87::ALGORITHM_IDENTIFIER => {
                ml_dsa::SigningKey::try_from(private_key_info).map(Self::MlDsa87)
            }
            a => Err(pkcs8::Error::PublicKey(spki::Error::OidUnknown {
                oid: a.oid,
            })),
        }
    }
}

/// Create a cryptographically secure random number generator.
fn csprng() -> Result<StdRng> {
    StdRng::try_from_rng(&mut SysRng).map_err(Error::RngInit)
}

/// Produce certs that match what AOSP's `development/tools/make_key` create.
struct AndroidRootProfile {
    subject: Name,
}

impl BuilderProfile for AndroidRootProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>, x509_cert::builder::Error> {
        let mut extensions = vec![];

        let ski = SubjectKeyIdentifier::try_from(spk)?;

        extensions.push(ski.to_extension(tbs.subject(), &extensions)?);

        extensions.push(
            AuthorityKeyIdentifier {
                key_identifier: Some(ski.0),
                ..Default::default()
            }
            .to_extension(tbs.subject(), &extensions)?,
        );

        extensions.push(
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );

        Ok(extensions)
    }
}

/// Generate a self-signed certificate.
pub fn generate_cert(
    key: &SigningPrivateKey,
    validity: Duration,
    subject: &str,
) -> Result<Certificate> {
    let mut rng = csprng()?;

    // Must be positive.
    let mut subject_bytes = [0u8; 20];
    while subject_bytes[0] == 0 || subject_bytes[0] > 0x7f {
        rng.fill_bytes(&mut subject_bytes);
    }

    let subject: Name = subject.parse().map_err(Error::CertParams)?;
    let profile = AndroidRootProfile { subject };

    let public_key_der = key
        .to_public_key()
        .to_public_key_der()
        .map_err(Error::SavePubKey)?;

    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::new(&subject_bytes).unwrap(),
        Validity::from_now(validity).map_err(Error::CertParams)?,
        SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
            .map_err(Error::CertParams)?,
    )
    .map_err(Error::CertGenerate)?;

    match key {
        SigningPrivateKey::Rsa(rsa_key) => {
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(rsa_key.clone());

            builder
                .build_with_rng(&signing_key, &mut rng)
                .map_err(Error::CertGenerate)
        }
        SigningPrivateKey::MlDsa65(ml_dsa_key) => builder
            .build_with_rng(ml_dsa_key.expanded_key(), &mut rng)
            .map_err(Error::CertGenerate),
        SigningPrivateKey::MlDsa87(ml_dsa_key) => builder
            .build_with_rng(ml_dsa_key.expanded_key(), &mut rng)
            .map_err(Error::CertGenerate),
        SigningPrivateKey::External { .. } => Err(Error::CertGenerateExternalKey),
    }
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

/// Read PEM-encoded SPKI public key from a reader.
pub fn read_pem_public_key(path: &Path, mut reader: impl Read) -> Result<SigningPublicKey> {
    let mut data = String::new();
    reader
        .read_to_string(&mut data)
        .map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    SigningPublicKey::from_public_key_pem(&data).map_err(Error::LoadPubKey)
}

/// Write PEM-encoded SPKI public key to a writer.
pub fn write_pem_public_key(
    path: &Path,
    mut writer: impl Write,
    key: &SigningPublicKey,
) -> Result<()> {
    let data = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(Error::SavePubKey)?;

    writer
        .write_all(data.as_bytes())
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    Ok(())
}

/// Read PEM-encoded SPKI public key from a file.
pub fn read_pem_public_key_file(path: &Path) -> Result<SigningPublicKey> {
    let reader = File::open(path).map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    read_pem_public_key(path, reader)
}

/// Write PEM-encoded SPKI public key to a file.
pub fn write_pem_public_key_file(path: &Path, key: &SigningPublicKey) -> Result<()> {
    let writer = File::create(path).map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    write_pem_public_key(path, writer, key)
}

/// Read PEM-encoded PKCS8 private key from a reader.
pub fn read_pem_private_key(
    path: &Path,
    mut reader: impl Read,
    source: &PassphraseSource,
) -> Result<SigningPrivateKey> {
    let mut data = String::new();
    reader
        .read_to_string(&mut data)
        .map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    let (label, doc) = SecretDocument::from_pem(&data)
        .map_err(|e| Error::LoadKeyEncrypted(pkcs8::Error::Asn1(e)))?;

    if label == EncryptedPrivateKeyInfoRef::PEM_LABEL {
        let passphrase = source.acquire(false)?;

        SigningPrivateKey::from_pkcs8_encrypted_der(doc.as_bytes(), passphrase)
            .map_err(Error::LoadKeyEncrypted)
    } else {
        SigningPrivateKey::from_pkcs8_der(doc.as_bytes()).map_err(Error::LoadKeyUnencrypted)
    }
}

/// Write PEM-encoded PKCS8 private key to a writer.
pub fn write_pem_private_key(
    path: &Path,
    mut writer: impl Write,
    key: &SigningPrivateKey,
    source: &PassphraseSource,
) -> Result<()> {
    let passphrase = source.acquire(true)?;

    let data = if passphrase.is_empty() {
        key.to_pkcs8_pem(LineEnding::LF)
            .map_err(Error::SaveKeyUnencrypted)?
    } else {
        key.to_pkcs8_encrypted_pem(&passphrase, LineEnding::LF)
            .map_err(Error::SaveKeyEncrypted)?
    };

    writer
        .write_all(data.as_bytes())
        .map_err(|e| Error::WriteFile(path.to_owned(), e))?;

    Ok(())
}

/// Read PEM-encoded PKCS8 private key from a file.
pub fn read_pem_private_key_file(
    path: &Path,
    source: &PassphraseSource,
) -> Result<SigningPrivateKey> {
    let reader = File::open(path).map_err(|e| Error::ReadFile(path.to_owned(), e))?;

    read_pem_private_key(path, reader, source)
}

/// Save PEM-encoded PKCS8 private key to a file.
pub fn write_pem_private_key_file(
    path: &Path,
    key: &SigningPrivateKey,
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

    write_pem_private_key(path, writer, key, source)
}

/// Get the public key from a certificate.
pub fn get_public_key(cert: &Certificate) -> Result<SigningPublicKey> {
    let public_key = SigningPublicKey::try_from(
        cert.tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref(),
    )
    .map_err(Error::LoadPubKey)?;

    Ok(public_key)
}

/// Check if a certificate matches a private key.
pub fn cert_matches_key(cert: &Certificate, key: &SigningPrivateKey) -> Result<bool> {
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
///
/// Currently, only RSA keys are supported.
pub fn cms_sign_external(
    key: &SigningPrivateKey,
    cert: &Certificate,
    method: SigningMethod,
    digest: &[u8],
) -> Result<ContentInfo> {
    let signature = key.sign(
        method,
        SignatureAlgorithm::Sha256WithRsa,
        SigningContent::Digest(digest),
    )?;

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
                issuer: cert.tbs_certificate().issuer().clone(),
                serial_number: cert.tbs_certificate().serial_number().clone(),
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
