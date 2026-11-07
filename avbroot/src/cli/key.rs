// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use tracing::warn;
use winnow_args::{Args, Subcommand, ValueEnum};

use crate::{
    crypto::{self, PassphraseSource, SigningKeyType, SigningPrivateKey},
    format::avb,
};

fn get_passphrase_source(group: &PassphraseGroup, key_path: &Path) -> PassphraseSource {
    PassphraseSource::new(
        key_path,
        group.pass_file.as_deref(),
        group.pass_env_var.as_deref(),
    )
}

pub fn key_main(cli: &KeyCli) -> Result<()> {
    match &cli.command {
        KeyCommand::GenerateKey(c) => {
            let source = get_passphrase_source(&c.passphrase, &c.output);
            let generate_key_type = c.key_type.unwrap_or_else(|| {
                let default = GenerateKeyType::Rsa4096;
                warn!(
                    "Defaulting to {}; -t/--key-type will be required in avbroot 4.0",
                    default.name(),
                );
                default
            });
            let key_type = match generate_key_type {
                GenerateKeyType::Rsa2048 => SigningKeyType::Rsa(2048 / 8),
                GenerateKeyType::Rsa4096 => SigningKeyType::Rsa(4096 / 8),
                GenerateKeyType::Rsa8192 => SigningKeyType::Rsa(8192 / 8),
                GenerateKeyType::MlDsa65 => SigningKeyType::MlDsa65,
                GenerateKeyType::MlDsa87 => SigningKeyType::MlDsa87,
            };

            let private_key =
                SigningPrivateKey::generate(key_type).context("Failed to generate keypair")?;

            crypto::write_pem_private_key_file(&c.output, &private_key, &source)
                .with_context(|| format!("Failed to write private key: {:?}", c.output))?;
        }
        KeyCommand::GenerateCert(c) => {
            let source = get_passphrase_source(&c.passphrase, &c.key);
            let private_key = crypto::read_pem_private_key_file(&c.key, &source)
                .with_context(|| format!("Failed to load key: {:?}", c.key))?;

            let validity = Duration::from_secs(c.validity * 24 * 60 * 60);
            let cert = crypto::generate_cert(&private_key, validity, &c.subject)
                .context("Failed to generate certificate")?;

            crypto::write_pem_cert_file(&c.output, &cert)
                .with_context(|| format!("Failed to write certificate: {:?}", c.output))?;
        }
        KeyCommand::ExtractAvb(c) | KeyCommand::EncodeAvb(c) => {
            let public_key = if let Some(p) = &c.input.key {
                let passphrase = get_passphrase_source(&c.passphrase, p);
                let private_key = crypto::read_pem_private_key_file(p, &passphrase)
                    .with_context(|| format!("Failed to load key: {p:?}"))?;

                private_key.to_public_key()
            } else if let Some(p) = &c.input.public_key {
                crypto::read_pem_public_key_file(p)
                    .with_context(|| format!("Failed to load public key: {p:?}"))?
            } else if let Some(p) = &c.input.cert {
                let certificate = crypto::read_pem_cert_file(p)
                    .with_context(|| format!("Failed to load certificate: {p:?}"))?;

                crypto::get_public_key(&certificate)
                    .with_context(|| format!("Failed to extract public key: {p:?}"))?
            } else {
                unreachable!()
            };

            let encoded = avb::encode_public_key(&public_key)
                .context("Failed to encode public key in AVB format")?;

            fs::write(&c.output, encoded)
                .with_context(|| format!("Failed to write public key: {:?}", c.output))?;
        }
        KeyCommand::DecodeAvb(c) => {
            let encoded = fs::read(&c.key)
                .with_context(|| format!("Failed to load AVB public key: {:?}", c.key))?;

            let public_key = avb::decode_public_key(&encoded)
                .context("Failed to decode public key as AVB format")?;

            crypto::write_pem_public_key_file(&c.output, &public_key)
                .with_context(|| format!("Failed to write public key: {:?}", c.output))?;
        }
    }

    Ok(())
}

#[derive(Debug, Args)]
#[arg(group("key", required))]
struct PublicKeyInputGroup {
    /// Path to private key.
    #[arg(short, long, value_name = "FILE", group = "key")]
    key: Option<PathBuf>,

    /// Path to public key.
    #[arg(short, long, value_name = "FILE", group = "key")]
    public_key: Option<PathBuf>,

    /// Path to certificate.
    #[arg(short, long, value_name = "FILE", group = "key")]
    cert: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[arg(group("pass"))]
struct PassphraseGroup {
    /// Environment variable containing private key passphrase.
    #[arg(long, value_name = "ENV_VAR", group = "pass")]
    pass_env_var: Option<OsString>,

    /// File containing private key passphrase.
    #[arg(long, value_name = "FILE", group = "pass")]
    pass_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[arg(rename_all = "lowercase")]
pub enum GenerateKeyType {
    Rsa2048,
    Rsa4096,
    Rsa8192,
    MlDsa65,
    MlDsa87,
}

/// Generate a signing keypair.
///
/// The output is saved in the standard PKCS8 format.
#[derive(Debug, Args)]
struct GenerateKeyCli {
    /// Path to output private key.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    /// The type of key to create.
    ///
    /// WARNING: This will be a required field starting in avbroot 4.0.
    #[arg(short = 't', long, value_name = "TYPE")]
    key_type: Option<GenerateKeyType>,

    #[arg(flatten)]
    passphrase: PassphraseGroup,
}

/// Generate a certificate.
#[derive(Debug, Args)]
struct GenerateCertCli {
    /// Path to input private key.
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,

    #[arg(flatten)]
    passphrase: PassphraseGroup,

    /// Path to output certificate.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    /// Certificate subject with comma-separated components.
    #[arg(short, long, default = "CN=avbroot")]
    subject: String,

    /// Certificate validity in days.
    #[arg(short, long, default = "10000")]
    validity: u64,
}

/// Convert a key or certificate to an AVB-encoded public key.
///
/// The public key is stored in both the private key and the certificate. Either
/// one can be used interchangeably.
#[derive(Debug, Args)]
struct EncodeAvbCli {
    /// Path to output AVB public key.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    #[arg(flatten)]
    input: PublicKeyInputGroup,

    #[arg(flatten)]
    passphrase: PassphraseGroup,
}

/// Convert an AVB-encoded public key to a PKCS8-encoded public key.
#[derive(Debug, Args)]
struct DecodeAvbCli {
    /// Path to output PKCS8-encoded public key.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    /// Path to AVB-encoded public key.
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    GenerateKey(GenerateKeyCli),
    GenerateCert(GenerateCertCli),
    /// (Deprecated: Use `avbroot key encode-avb` instead.)
    #[arg(hide)]
    ExtractAvb(EncodeAvbCli),
    EncodeAvb(EncodeAvbCli),
    DecodeAvb(DecodeAvbCli),
}

/// Generate and convert keys.
#[derive(Debug, Args)]
pub struct KeyCli {
    #[arg(subcommand)]
    command: KeyCommand,
}
