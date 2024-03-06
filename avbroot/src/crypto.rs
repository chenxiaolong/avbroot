/*
 * SPDX-FileCopyrightText: 2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    env::{self, VarError},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
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
use pkcs8::{
    pkcs5::{pbes2, scrypt},
    DecodePrivateKey, EncodePrivateKey, EncodePublicKey, EncryptedPrivateKeyInfo, LineEnding,
    PrivateKeyInfo,
};
use rand::RngCore;
use rsa::{pkcs1v15::SigningKey, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{pem::PemLabel, referenced::OwnedToRef, Any, Decode, DecodePem, EncodePem},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Passphrases do not match")]
    ConfirmPassphrase,
    #[error("Failed to read environment variable: {0:?}")]
    InvalidEnvVar(OsString, #[source] VarError),
    #[error("PEM has start tag, but no end tag")]
    PemNoEndTag,
    #[error("Failed to load encrypted private key")]
    LoadKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to load unencrypted private key")]
    LoadKeyUnencrypted(#[source] pkcs8::Error),
    #[error("Failed to save encrypted private key")]
    SaveKeyEncrypted(#[source] pkcs8::Error),
    #[error("Failed to save unencrypted private key")]
    SaveKeyUnencrypted(#[source] pkcs8::Error),
    #[error("X509 error")]
    X509(#[from] x509_cert::builder::Error),
    #[error("SPKI error")]
    Spki(#[from] pkcs8::spki::Error),
    #[error("DER error")]
    Der(#[from] x509_cert::der::Error),
    #[error("RSA error")]
    Rsa(#[from] rsa::Error),
    #[error("I/O error")]
    Io(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub enum PassphraseSource {
    Prompt(String),
    EnvVar(OsString),
    File(PathBuf),
}

impl PassphraseSource {
    pub fn new(key_file: &Path, pass_file: Option<&Path>, env_var: Option<&OsStr>) -> Self {
        if let Some(v) = env_var {
            Self::EnvVar(v.to_owned())
        } else if let Some(p) = pass_file {
            Self::File(p.to_owned())
        } else {
            Self::Prompt(format!("Enter passphrase for {key_file:?}: "))
        }
    }

    pub fn acquire(&self, confirm: bool) -> Result<String> {
        let passphrase = match self {
            Self::Prompt(p) => {
                let first = rpassword::prompt_password(p)?;

                if confirm {
                    let second = rpassword::prompt_password("Confirm: ")?;

                    if first != second {
                        return Err(Error::ConfirmPassphrase);
                    }
                }

                first
            }
            Self::EnvVar(v) => env::var(v).map_err(|e| Error::InvalidEnvVar(v.clone(), e))?,
            Self::File(p) => fs::read_to_string(p)?
                .trim_end_matches(&['\r', '\n'])
                .to_owned(),
        };

        Ok(passphrase)
    }
}

/// Generate an 4096-bit RSA key pair.
pub fn generate_rsa_key_pair() -> Result<RsaPrivateKey> {
    let mut rng = rand::thread_rng();

    // avbroot supports 4096-bit keys only.
    let key = RsaPrivateKey::new(&mut rng, 4096)?;

    Ok(key)
}

/// Generate a self-signed certificate.
pub fn generate_cert(
    key: &RsaPrivateKey,
    serial: u64,
    validity: Duration,
    subject: &str,
) -> Result<Certificate> {
    let public_key_der = key.to_public_key().to_public_key_der()?;
    let signing_key = SigningKey::<Sha256>::new(key.clone());

    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(serial),
        Validity::from_now(validity)?,
        subject.parse()?,
        SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())?,
        &signing_key,
    )?;

    let mut rng = rand::thread_rng();
    let cert = builder.build_with_rng(&mut rng)?;

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
pub fn read_pem_cert(mut reader: impl Read) -> Result<Certificate> {
    let mut data = vec![];
    reader.read_to_end(&mut data)?;

    let data = reformat_pem(&data)?;
    let certificate = Certificate::from_pem(data)?;

    Ok(certificate)
}

/// Write PEM-encoded certificate to a writer.
pub fn write_pem_cert(mut writer: impl Write, cert: &Certificate) -> Result<()> {
    let data = cert.to_pem(LineEnding::LF)?;

    writer.write_all(data.as_bytes())?;

    Ok(())
}

/// Read PEM-encoded certificate from a file.
pub fn read_pem_cert_file(path: &Path) -> Result<Certificate> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    read_pem_cert(reader)
}

/// Write PEM-encoded certificate to a file.
pub fn write_pem_cert_file(path: &Path, cert: &Certificate) -> Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    write_pem_cert(writer, cert)
}

/// Write PEM-encoded PKCS8 public key to a writer.
pub fn write_pem_public_key(mut writer: impl Write, key: &RsaPublicKey) -> Result<()> {
    let data = key.to_public_key_pem(LineEnding::LF)?;

    writer.write_all(data.as_bytes())?;

    Ok(())
}

/// Write PEM-encoded PKCS8 public key to a file.
pub fn write_pem_public_key_file(path: &Path, key: &RsaPublicKey) -> Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    write_pem_public_key(writer, key)
}

/// Read PEM-encoded PKCS8 private key from a reader.
pub fn read_pem_key(mut reader: impl Read, source: &PassphraseSource) -> Result<RsaPrivateKey> {
    let mut data = String::new();
    reader.read_to_string(&mut data)?;

    if data.contains("ENCRYPTED") {
        let passphrase = source.acquire(false)?;

        RsaPrivateKey::from_pkcs8_encrypted_pem(&data, passphrase).map_err(Error::LoadKeyEncrypted)
    } else {
        RsaPrivateKey::from_pkcs8_pem(&data).map_err(Error::LoadKeyUnencrypted)
    }
}

/// Write PEM-encoded PKCS8 private key to a writer.
pub fn write_pem_key(
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

        secret_doc.to_pem(EncryptedPrivateKeyInfo::PEM_LABEL, LineEnding::LF)?
    };

    writer.write_all(data.as_bytes())?;

    Ok(())
}

/// Read PEM-encoded PKCS8 private key from a file.
pub fn read_pem_key_file(path: &Path, source: &PassphraseSource) -> Result<RsaPrivateKey> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    read_pem_key(reader, source)
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

    let file = options.open(path)?;
    let writer = BufWriter::new(file);

    write_pem_key(writer, key, source)
}

/// Get the RSA public key from a certificate.
pub fn get_public_key(cert: &Certificate) -> Result<RsaPublicKey> {
    let public_key =
        RsaPublicKey::try_from(cert.tbs_certificate.subject_public_key_info.owned_to_ref())?;

    Ok(public_key)
}

/// Check if a certificate matches a private key.
pub fn cert_matches_key(cert: &Certificate, key: &RsaPrivateKey) -> Result<bool> {
    let public_key = get_public_key(cert)?;

    Ok(key.to_public_key() == public_key)
}

/// Parse a CMS [`SignedData`] structure from raw DER-encoded data.
pub fn parse_cms(data: &[u8]) -> Result<SignedData> {
    let ci = ContentInfo::from_der(data)?;
    let sd = ci.content.decode_as::<SignedData>()?;

    Ok(sd)
}

/// Get a list of all standard X509 certificates contained within a
/// [`SignedData`] structure.
pub fn get_cms_certs(sd: &SignedData) -> Vec<Certificate> {
    sd.certificates.as_ref().map_or_else(Vec::new, |certs| {
        certs
            .0
            .iter()
            .filter_map(|cc| {
                if let CertificateChoices::Certificate(c) = cc {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect()
    })
}

/// Create a CMS signature from an external digest. This implementation does not
/// use signed attributes because AOSP recovery's otautil/verifier.cpp is not
/// actually CMS compliant. It simply uses the CMS [`SignedData`] structure as
/// a transport mechanism for a raw signature. Thus, we need to ensure that the
/// signature covers nothing but the raw data.
pub fn cms_sign_external(
    key: &RsaPrivateKey,
    cert: &Certificate,
    digest: &[u8],
) -> Result<ContentInfo> {
    let scheme = Pkcs1v15Sign::new::<Sha256>();
    let signature = key.sign(scheme, digest)?;

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::try_from(vec![digest_algorithm.clone()])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet::try_from(vec![
            CertificateChoices::Certificate(cert.clone()),
        ])?),
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
            signature: SignatureValue::new(signature)?,
            unsigned_attrs: None,
        }])?,
    };

    let signed_data = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data)?,
    };

    Ok(signed_data)
}
