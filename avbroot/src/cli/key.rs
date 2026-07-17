// SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::warn;

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
                    default.to_possible_value().unwrap().get_name(),
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
#[group(required = true, multiple = false)]
struct PublicKeyInputGroup {
    /// Path to private key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: Option<PathBuf>,

    /// Path to public key.
    #[arg(short, long, value_name = "FILE", value_parser, conflicts_with_all = ["pass_env_var", "pass_file"])]
    public_key: Option<PathBuf>,

    /// Path to certificate.
    #[arg(short, long, value_name = "FILE", value_parser, conflicts_with_all = ["pass_env_var", "pass_file"])]
    cert: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PassphraseGroup {
    /// Environment variable containing private key passphrase.
    #[arg(long, value_name = "ENV_VAR", value_parser, group = "pass")]
    pass_env_var: Option<OsString>,

    /// File containing private key passphrase.
    #[arg(long, value_name = "FILE", value_parser, group = "pass")]
    pass_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "lower")]
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
#[derive(Debug, Parser)]
struct GenerateKeyCli {
    /// Path to output private key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// The type of key to create.
    ///
    /// WARNING: This will be a required field starting in avbroot 4.0.
    #[arg(short = 't', long, value_name = "TYPE")]
    key_type: Option<GenerateKeyType>,

    #[command(flatten)]
    passphrase: PassphraseGroup,
}

/// Generate a certificate.
#[derive(Debug, Parser)]
struct GenerateCertCli {
    /// Path to input private key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,

    #[command(flatten)]
    passphrase: PassphraseGroup,

    /// Path to output certificate.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Certificate subject with comma-separated components.
    #[arg(short, long, default_value = "CN=avbroot")]
    subject: String,

    /// Certificate validity in days.
    #[arg(short, long, default_value = "10000")]
    validity: u64,
}

/// Convert a key or certificate to an AVB-encoded public key.
///
/// The public key is stored in both the private key and the certificate. Either
/// one can be used interchangeably.
#[derive(Debug, Parser)]
struct EncodeAvbCli {
    /// Path to output AVB public key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    #[command(flatten)]
    input: PublicKeyInputGroup,

    #[command(flatten)]
    passphrase: PassphraseGroup,
}

/// Convert an AVB-encoded public key to a PKCS8-encoded public key.
#[derive(Debug, Parser)]
struct DecodeAvbCli {
    /// Path to output PKCS8-encoded public key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    output: PathBuf,

    /// Path to AVB-encoded public key.
    #[arg(short, long, value_name = "FILE", value_parser)]
    key: PathBuf,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    GenerateKey(GenerateKeyCli),
    GenerateCert(GenerateCertCli),
    /// (Deprecated: Use `avbroot key encode-avb` instead.)
    #[command(hide = true)]
    ExtractAvb(EncodeAvbCli),
    EncodeAvb(EncodeAvbCli),
    DecodeAvb(DecodeAvbCli),
}

/// Generate and convert keys.
#[derive(Debug, Parser)]
pub struct KeyCli {
    #[command(subcommand)]
    command: KeyCommand,
}
