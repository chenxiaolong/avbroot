// SPDX-FileCopyrightText: 2022-2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read, Seek},
    num::ParseIntError,
    ops::Range,
    path::{Path, PathBuf},
    slice,
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use liblzma::{
    stream::{Check, Stream},
    write::XzEncoder,
};
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use regex::bytes::Regex;
use ring::digest::Context;
use rsa::RsaPublicKey;
use thiserror::Error;
use tracing::{debug, debug_span, trace, warn, Span};
use x509_cert::Certificate;
use zip::{result::ZipError, ZipArchive};

use crate::{
    crypto::{self, RsaSigningKey},
    format::{
        avb::{self, AppendedDescriptorMut, Footer, Header},
        bootimage::{self, BootImage, BootImageExt, RamdiskMeta},
        compression::{self, CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{self, CpioEntry, CpioEntryData},
    },
    patch::otacert::{self, OtaCertBuildFlags},
    stream::{self, FromReader, HashingWriter, ReadSeek, SectionReader, ToWriter, WriteSeek},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("No compatible boot image found for {0}")]
    NoTargets(&'static str),
    #[error("Boot image has no vbmeta footer")]
    NoFooter,
    #[error("No hash descriptor found in vbmeta header")]
    NoHashDescriptor,
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Failed to parse Magisk version from line: {0:?}")]
    ParseMagiskVersion(String, #[source] ParseIntError),
    #[error("Failed to determine Magisk version from: {0:?}")]
    FindMagiskVersion(PathBuf),
    #[error("AVB error")]
    Avb(#[from] avb::Error),
    #[error("Boot image error")]
    BootImage(#[from] bootimage::Error),
    #[error("Compression error")]
    Compression(#[from] compression::Error),
    #[error("Crypto error")]
    Crypto(#[from] crypto::Error),
    #[error("CPIO error")]
    Cpio(#[from] cpio::Error),
    #[error("OTA certificate error")]
    OtaCert(#[from] otacert::Error),
    #[error("XZ stream error")]
    XzStream(#[from] liblzma::stream::Error),
    #[error("Zip error")]
    Zip(#[source] ZipError),
    #[error("Zip error for entry name: {0:?}")]
    ZipEntryName(String, #[source] ZipError),
    #[error("Zip error for entry index #{0}")]
    ZipEntryIndex(usize, #[source] ZipError),
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("File I/O error")]
    File(PathBuf, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn load_ramdisk(
    data: &[u8],
    cancel_signal: &AtomicBool,
) -> Result<(Vec<CpioEntry>, CompressedFormat)> {
    let raw_reader = Cursor::new(data);
    let mut reader = CompressedReader::new(raw_reader, false)?;
    let entries = cpio::load(&mut reader, false, cancel_signal)?;

    trace!(
        "Loaded {:?} ramdisk with {} entries",
        reader.format(),
        entries.len(),
    );

    Ok((entries, reader.format()))
}

fn save_ramdisk(
    entries: &[CpioEntry],
    format: CompressedFormat,
    cancel_signal: &AtomicBool,
) -> Result<Vec<u8>> {
    let raw_writer = Cursor::new(vec![]);
    let mut writer = CompressedWriter::new(raw_writer, format)?;
    cpio::save(&mut writer, entries, false, cancel_signal)?;

    trace!("Wrote {format:?} ramdisk with {} entries", entries.len());

    let raw_writer = writer.finish()?;
    Ok(raw_writer.into_inner())
}

pub struct BootImageInfo {
    pub header: Header,
    pub footer: Footer,
    pub image_size: u64,
    pub boot_image: BootImage,
}

pub trait BootImagePatch {
    fn patcher_name(&self) -> &'static str;

    /// Inspect a set of possible candidate boot images and return a list of
    /// image names that can be patched. Both the boot image and the AVB info
    /// can be inspected, but during patching, only the boot image is available.
    fn find_targets<'a>(
        &self,
        boot_images: &HashMap<&'a str, BootImageInfo>,
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<&'a str>>;

    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &AtomicBool) -> Result<()>;
}

/// Root a boot image with Magisk.
pub struct MagiskRootPatcher {
    apk_path: PathBuf,
    version: u32,
    preinit_device: Option<String>,
    random_seed: u64,
}

impl MagiskRootPatcher {
    // - Versions <25102 are not supported because they're missing commit
    //   1f8c063dc64806c4f7320ed66c785ff7bc116383, which would leave devices
    //   that use Android 13 GKIs unable to boot into recovery
    // - Versions 25207 through 25210 are not supported because they used the
    //   RULESDEVICE config option, which stored the writable block device as an
    //   rdev major/minor pair, which was not consistent across reboots and was
    //   replaced by PREINITDEVICE
    const VERS_SUPPORTED: &'static [Range<u32>] = &[25102..25207, 25211..28200];
    const VER_PREINIT_DEVICE: Range<u32> =
        25211..Self::VERS_SUPPORTED[Self::VERS_SUPPORTED.len() - 1].end;
    const VER_RANDOM_SEED: Range<u32> = 25211..26103;
    const VER_PATCH_VBMETA: Range<u32> = Self::VERS_SUPPORTED[0].start..26202;
    const VER_XZ_BACKUP: Range<u32> =
        26403..Self::VERS_SUPPORTED[Self::VERS_SUPPORTED.len() - 1].end;

    const ZIP_INIT_LD: &'static str = "lib/arm64-v8a/libinit-ld.so";
    const ZIP_LIBMAGISK: &'static str = "lib/arm64-v8a/libmagisk.so";
    const ZIP_LIBMAGISK32: &'static str = "lib/armeabi-v7a/libmagisk32.so";
    const ZIP_LIBMAGISK64: &'static str = "lib/arm64-v8a/libmagisk64.so";
    const ZIP_MAGISKINIT: &'static str = "lib/arm64-v8a/libmagiskinit.so";
    const ZIP_STUB: &'static str = "assets/stub.apk";
    const ZIP_UTIL_FUNCTIONS: &'static str = "assets/util_functions.sh";

    pub fn new(
        path: &Path,
        preinit_device: Option<&str>,
        random_seed: Option<u64>,
        ignore_compatibility: bool,
    ) -> Result<Self> {
        let version = Self::get_version(path)?;

        debug!("Found Magisk version: {version}");

        if !Self::VERS_SUPPORTED.iter().any(|v| v.contains(&version)) {
            let msg = format!(
                "Unsupported Magisk version {} (supported: {:?})",
                version,
                Self::VERS_SUPPORTED,
            );

            if ignore_compatibility {
                warn!("{msg}");
            } else {
                return Err(Error::Validation(msg));
            }
        }

        if preinit_device.is_none() && Self::VER_PREINIT_DEVICE.contains(&version) {
            let msg = format!(
                "Magisk version {} ({:?}) requires a preinit device to be specified",
                version,
                Self::VER_PREINIT_DEVICE,
            );

            if ignore_compatibility {
                warn!("{msg}");
            } else {
                return Err(Error::Validation(msg));
            }
        }

        Ok(Self {
            apk_path: path.to_owned(),
            version,
            preinit_device: preinit_device.map(|d| d.to_owned()),
            // Use a hardcoded random seed by default to ensure byte-for-byte
            // reproducibility.
            random_seed: random_seed.unwrap_or(0xfedcba9876543210),
        })
    }

    fn get_version(path: &Path) -> Result<u32> {
        let reader = File::open(path).map_err(|e| Error::File(path.to_owned(), e))?;
        let reader = BufReader::new(reader);
        let mut zip = ZipArchive::new(reader).map_err(Error::Zip)?;
        let entry = zip
            .by_name(Self::ZIP_UTIL_FUNCTIONS)
            .map_err(|e| Error::ZipEntryName(Self::ZIP_UTIL_FUNCTIONS.to_owned(), e))?;
        let mut entry = BufReader::new(entry);
        let mut line = String::new();

        loop {
            line.clear();
            let n = entry.read_line(&mut line)?;
            if n == 0 {
                return Err(Error::FindMagiskVersion(path.to_owned()));
            }

            if let Some(suffix) = line.trim_end().strip_prefix("MAGISK_VER_CODE=") {
                trace!("Magisk version code line: {line:?}");

                let version = suffix
                    .parse()
                    .map_err(|e| Error::ParseMagiskVersion(suffix.to_owned(), e))?;
                return Ok(version);
            }
        }
    }

    fn xz_compress(reader: impl Read, cancel_signal: &AtomicBool) -> Result<Vec<u8>> {
        let stream = Stream::new_easy_encoder(9, Check::Crc32)?;
        let raw_writer = Cursor::new(Vec::new());
        let mut writer = XzEncoder::new_stream(raw_writer, stream);

        stream::copy(reader, &mut writer, cancel_signal)?;

        let raw_writer = writer.finish()?;

        Ok(raw_writer.into_inner())
    }

    /// Compare old and new ramdisk entry lists, creating the Magisk `.backup/`
    /// directory structure. `.backup/.rmlist` will contain a sorted list of
    /// NULL-terminated strings, listing which files were newly added or
    /// changed. The old entries for changed files will be added to the new
    /// entries as `.backup/<path>`.
    ///
    /// Both lists and entries within the lists may be mutated.
    fn apply_magisk_backup(
        old_entries: &mut [CpioEntry],
        new_entries: &mut Vec<CpioEntry>,
        xz_compress: bool,
        cancel_signal: &AtomicBool,
    ) -> Result<()> {
        cpio::sort(old_entries);
        cpio::sort(new_entries);

        let mut rm_list = vec![];
        let mut to_back_up = vec![];

        let mut old_iter = old_entries.iter().peekable();
        let mut new_iter = new_entries.iter().peekable();

        loop {
            match (old_iter.peek(), new_iter.peek()) {
                (Some(&old), Some(&new)) => match old.path.cmp(&new.path) {
                    Ordering::Less => {
                        to_back_up.push(old);
                        old_iter.next();
                    }
                    Ordering::Equal => {
                        if old.data != new.data {
                            to_back_up.push(old);
                        }
                        old_iter.next();
                        new_iter.next();
                    }
                    Ordering::Greater => {
                        rm_list.extend(&new.path);
                        rm_list.push(b'\0');
                        new_iter.next();
                    }
                },
                (Some(old), None) => {
                    to_back_up.push(old);
                    old_iter.next();
                }
                (None, Some(new)) => {
                    rm_list.extend(&new.path);
                    rm_list.push(b'\0');
                    new_iter.next();
                }
                (None, None) => break,
            }
        }

        new_entries.push(CpioEntry::new_directory(b".backup", 0));

        debug!(
            "Removed entries: {:?}",
            rm_list
                .split(|b| *b == 0)
                .filter(|e| !e.is_empty())
                .map(|p| p.as_bstr().to_string())
                .collect::<Vec<_>>(),
        );
        debug!(
            "Added/changed entries: {:?}",
            to_back_up
                .iter()
                .map(|e| e.path.as_bstr().to_string())
                .collect::<Vec<_>>(),
        );

        for old_entry in to_back_up {
            let mut new_path = b".backup/".to_vec();
            new_path.extend(&old_entry.path);

            let mut new_data = None;

            if xz_compress {
                if let CpioEntryData::Data(data) = &old_entry.data {
                    new_path.extend(b".xz");

                    let reader = Cursor::new(data);
                    let buf = Self::xz_compress(reader, cancel_signal)?;
                    new_data = Some(CpioEntryData::Data(buf));
                }
            }

            new_entries.push(CpioEntry {
                path: new_path,
                data: new_data.unwrap_or_else(|| old_entry.data.clone()),
                inode: old_entry.inode,
                file_type: old_entry.file_type,
                file_mode: old_entry.file_mode,
                uid: old_entry.uid,
                gid: old_entry.gid,
                nlink: old_entry.nlink,
                mtime: old_entry.mtime,
                dev_maj: old_entry.dev_maj,
                dev_min: old_entry.dev_min,
                rdev_maj: old_entry.rdev_maj,
                rdev_min: old_entry.rdev_min,
                crc32: old_entry.crc32,
            });
        }

        new_entries.push(CpioEntry::new_file(
            b".backup/.rmlist",
            0,
            CpioEntryData::Data(rm_list),
        ));

        Ok(())
    }
}

impl BootImagePatch for MagiskRootPatcher {
    fn patcher_name(&self) -> &'static str {
        "MagiskRootPatcher"
    }

    fn find_targets<'a>(
        &self,
        boot_images: &HashMap<&'a str, BootImageInfo>,
        _cancel_signal: &AtomicBool,
    ) -> Result<Vec<&'a str>> {
        let mut targets = vec![];

        if boot_images.contains_key("init_boot") {
            targets.push("init_boot");
        } else if boot_images.contains_key("boot") {
            targets.push("boot");
        };

        Ok(targets)
    }

    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &AtomicBool) -> Result<()> {
        let zip_reader =
            File::open(&self.apk_path).map_err(|e| Error::File(self.apk_path.clone(), e))?;
        let mut zip = ZipArchive::new(BufReader::new(zip_reader)).map_err(Error::Zip)?;

        // Load the first ramdisk. If it doesn't exist, we have to generate one
        // from scratch.
        let ramdisk = match boot_image {
            BootImage::V0Through2(b) => Some(&b.ramdisk),
            BootImage::V3Through4(b) => Some(&b.ramdisk),
            BootImage::VendorV3Through4(b) => b.ramdisks.first(),
        };
        let (mut entries, ramdisk_format) = match ramdisk {
            Some(r) if !r.is_empty() => load_ramdisk(r, cancel_signal)?,
            _ => (vec![], CompressedFormat::Lz4Legacy),
        };

        let mut old_entries = entries.clone();

        // Create the Magisk directory structure.
        for (path, perms) in [
            (b"overlay.d".as_slice(), 0o750),
            (b"overlay.d/sbin".as_slice(), 0o750),
        ] {
            entries.push(CpioEntry::new_directory(path, perms));
        }

        // Delete the original init.
        entries.retain(|e| e.path != b"init");

        // Add magiskinit.
        {
            let mut zip_entry = zip
                .by_name(Self::ZIP_MAGISKINIT)
                .map_err(|e| Error::ZipEntryName(Self::ZIP_MAGISKINIT.to_owned(), e))?;
            let mut data = vec![];
            zip_entry.read_to_end(&mut data)?;

            entries.push(CpioEntry::new_file(
                b"init",
                0o750,
                CpioEntryData::Data(data),
            ));
        }

        let mut xz_files = HashMap::<&str, &[u8]>::new();
        if zip.file_names().any(|n| n == Self::ZIP_LIBMAGISK) {
            // Newer Magisk versions only include a single binary for the target
            // ABI in the ramdisk. fb5ee86615ed3df830e8538f8b39b1b133caea34.
            debug!("Single libmagisk");
            xz_files.insert(Self::ZIP_LIBMAGISK, b"overlay.d/sbin/magisk.xz");
        } else {
            // Older Magisk versions include the 64-bit binary and, optionally,
            // the 32-bit binary if the device supports it. We unconditionally
            // include the magisk32 because the boot image itself doesn't have
            // sufficient information to determine if a device is 64-bit only.
            debug!("Split libmagisk32/libmagisk64");
            xz_files.insert(Self::ZIP_LIBMAGISK32, b"overlay.d/sbin/magisk32.xz");
            xz_files.insert(Self::ZIP_LIBMAGISK64, b"overlay.d/sbin/magisk64.xz");
        }

        // Add stub apk, which only exists after Magisk commit
        // ad0e6511e11ebec65aa9b5b916e1397342850319.
        if zip.file_names().any(|n| n == Self::ZIP_STUB) {
            debug!("Magisk stub found");
            xz_files.insert(Self::ZIP_STUB, b"overlay.d/sbin/stub.xz");
        }

        // Add init-ld, which only exists after Magisk commit
        // 33aebb59763b6ec27209563035303700e998633d
        if zip.file_names().any(|n| n == Self::ZIP_INIT_LD) {
            debug!("Magisk init-ld found");
            xz_files.insert(Self::ZIP_INIT_LD, b"overlay.d/sbin/init-ld.xz");
        }

        for (source, target) in xz_files {
            let reader = zip
                .by_name(source)
                .map_err(|e| Error::ZipEntryName(source.to_owned(), e))?;
            let buf = Self::xz_compress(reader, cancel_signal)?;

            entries.push(CpioEntry::new_file(target, 0o644, CpioEntryData::Data(buf)));
        }

        // Create Magisk .backup directory structure.
        Self::apply_magisk_backup(
            &mut old_entries,
            &mut entries,
            Self::VER_XZ_BACKUP.contains(&self.version),
            cancel_signal,
        )?;

        // Create Magisk config.
        let mut magisk_config = String::new();
        magisk_config.push_str("KEEPVERITY=true\n");
        magisk_config.push_str("KEEPFORCEENCRYPT=true\n");

        if Self::VER_PATCH_VBMETA.contains(&self.version) {
            magisk_config.push_str("PATCHVBMETAFLAG=false\n");
        }

        magisk_config.push_str("RECOVERYMODE=false\n");

        if Self::VER_PREINIT_DEVICE.contains(&self.version) {
            magisk_config.push_str(&format!(
                "PREINITDEVICE={}\n",
                self.preinit_device.as_ref().unwrap(),
            ));
        }

        // Magisk normally saves the original SHA1 digest in its config file. It
        // uses this to find the original image in /data/magisk_backup_<sha1> to
        // restore the stock boot image for uninstallation purposes. This is a
        // feature we cannot ever use, so just use a dummy value.
        magisk_config.push_str("SHA1=0000000000000000000000000000000000000000\n");

        if Self::VER_RANDOM_SEED.contains(&self.version) {
            magisk_config.push_str(&format!("RANDOMSEED={:#x}\n", self.random_seed));
        }

        trace!("Magisk config: {magisk_config:?}");

        entries.push(CpioEntry::new_file(
            b".backup/.magisk",
            0,
            CpioEntryData::Data(magisk_config.into_bytes()),
        ));

        // Repack ramdisk.
        cpio::sort(&mut entries);
        cpio::assign_inodes(&mut entries, false)?;
        let new_ramdisk = save_ramdisk(&entries, ramdisk_format, cancel_signal)?;

        match boot_image {
            BootImage::V0Through2(b) => b.ramdisk = new_ramdisk,
            BootImage::V3Through4(b) => b.ramdisk = new_ramdisk,
            BootImage::VendorV3Through4(b) => {
                if b.ramdisks.is_empty() {
                    b.ramdisks.push(new_ramdisk);

                    if let Some(v4) = &mut b.v4_extra {
                        v4.ramdisk_metas.push(RamdiskMeta {
                            ramdisk_type: bootimage::VENDOR_RAMDISK_TYPE_NONE,
                            ramdisk_name: String::new(),
                            board_id: Default::default(),
                        });
                    }
                } else {
                    b.ramdisks[0] = new_ramdisk;
                }
            }
        }

        Ok(())
    }
}

/// Replace the OTA certificates in the vendor_boot/recovery image with the
/// custom OTA signing certificate.
pub struct OtaCertPatcher {
    cert: Certificate,
}

impl OtaCertPatcher {
    const OTACERTS_PATH: &'static [u8] = b"system/etc/security/otacerts.zip";

    pub fn new(cert: Certificate) -> Self {
        Self { cert }
    }

    pub fn get_certificates(
        boot_image: &BootImage,
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<Certificate>> {
        let mut ramdisks = vec![];

        match boot_image {
            BootImage::V0Through2(b) => ramdisks.push(&b.ramdisk),
            BootImage::V3Through4(b) => ramdisks.push(&b.ramdisk),
            BootImage::VendorV3Through4(b) => ramdisks.extend(b.ramdisks.iter()),
        }

        let mut certificates = vec![];

        for ramdisk in ramdisks {
            if ramdisk.is_empty() {
                continue;
            }

            let (entries, _) = load_ramdisk(ramdisk, cancel_signal)?;
            let Some(entry) = entries.iter().find(|e| e.path == Self::OTACERTS_PATH) else {
                continue;
            };
            let CpioEntryData::Data(data) = &entry.data else {
                continue;
            };

            let mut zip = ZipArchive::new(Cursor::new(&data)).map_err(Error::Zip)?;

            for index in 0..zip.len() {
                let zip_entry = zip
                    .by_index(index)
                    .map_err(|e| Error::ZipEntryIndex(index, e))?;
                if !zip_entry.name().ends_with(".x509.pem") {
                    debug!("Skipping invalid entry path: {}", zip_entry.name());
                    continue;
                }

                let certificate = crypto::read_pem_cert(zip_entry)?;
                certificates.push(certificate);
            }
        }

        Ok(certificates)
    }

    fn patch_ramdisk(
        ramdisk: &mut Vec<u8>,
        zip: &[u8],
        cancel_signal: &AtomicBool,
    ) -> Result<bool> {
        let (mut entries, ramdisk_format) = load_ramdisk(ramdisk, cancel_signal)?;
        let Some(entry) = entries.iter_mut().find(|e| e.path == Self::OTACERTS_PATH) else {
            return Ok(false);
        };

        // Create a new otacerts archive. The old certs are ignored since
        // flashing a stock OTA will render the device unbootable.
        entry.data = CpioEntryData::Data(zip.to_vec());

        // Repack ramdisk.
        *ramdisk = save_ramdisk(&entries, ramdisk_format, cancel_signal)?;

        Ok(true)
    }
}

impl BootImagePatch for OtaCertPatcher {
    fn patcher_name(&self) -> &'static str {
        "OtaCertPatcher"
    }

    fn find_targets<'a>(
        &self,
        boot_images: &HashMap<&'a str, BootImageInfo>,
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<&'a str>> {
        let mut targets = vec![];

        'outer: for (name, info) in boot_images {
            let ramdisks = match &info.boot_image {
                BootImage::V0Through2(b) => slice::from_ref(&b.ramdisk),
                BootImage::V3Through4(b) => slice::from_ref(&b.ramdisk),
                BootImage::VendorV3Through4(b) => &b.ramdisks,
            };

            for ramdisk in ramdisks {
                if ramdisk.is_empty() {
                    continue;
                }

                let (entries, _) = load_ramdisk(ramdisk, cancel_signal)?;
                if entries.iter().any(|e| e.path == Self::OTACERTS_PATH) {
                    targets.push(*name);
                    continue 'outer;
                }
            }
        }

        Ok(targets)
    }

    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &AtomicBool) -> Result<()> {
        let ramdisks = match boot_image {
            BootImage::V0Through2(b) => slice::from_mut(&mut b.ramdisk),
            BootImage::V3Through4(b) => slice::from_mut(&mut b.ramdisk),
            BootImage::VendorV3Through4(b) => &mut b.ramdisks,
        };

        let new_zip = otacert::create_zip(&self.cert, OtaCertBuildFlags::empty())?;
        trace!("Generated new {} byte otacerts.zip", new_zip.len());

        for ramdisk in ramdisks {
            if ramdisk.is_empty() {
                continue;
            }

            if Self::patch_ramdisk(ramdisk, &new_zip, cancel_signal)? {
                return Ok(());
            }
        }

        // Fail hard if otacerts does not exist. We don't want to lock the user
        // out of future updates if the OTA certificate mechanism has changed.
        Err(Error::Validation(format!(
            "No ramdisk contains {:?}",
            Self::OTACERTS_PATH.as_bstr(),
        )))
    }
}

/// Add the AVB public key to DSU's list of trusted keys for verifying GSIs.
pub struct DsuPubKeyPatcher {
    key: RsaPublicKey,
}

impl DsuPubKeyPatcher {
    const FIRST_STAGE_PATH: &'static [u8] = b"first_stage_ramdisk";
    const DSU_KEYS_PATH: &'static [u8] = b"first_stage_ramdisk/avb";
    const AVBROOT_KEY_PATH: &'static [u8] = b"first_stage_ramdisk/avb/avbroot.avbpubkey";

    pub fn new(key: RsaPublicKey) -> Self {
        Self { key }
    }

    fn patch_ramdisk(&self, ramdisk: &mut Vec<u8>, cancel_signal: &AtomicBool) -> Result<bool> {
        let (mut entries, ramdisk_format) = load_ramdisk(ramdisk, cancel_signal)?;
        if !entries.iter_mut().any(|e| e.path == Self::FIRST_STAGE_PATH) {
            return Ok(false);
        }

        if !entries.iter().any(|e| e.path == Self::DSU_KEYS_PATH) {
            entries.push(CpioEntry::new_directory(Self::DSU_KEYS_PATH, 0o755));
        }

        let data = CpioEntryData::Data(avb::encode_public_key(&self.key)?);

        if let Some(e) = entries
            .iter_mut()
            .find(|e| e.path == Self::AVBROOT_KEY_PATH)
        {
            e.data = data;
        } else {
            entries.push(CpioEntry::new_file(Self::AVBROOT_KEY_PATH, 0o644, data));
        };

        *ramdisk = save_ramdisk(&entries, ramdisk_format, cancel_signal)?;

        Ok(true)
    }
}

impl BootImagePatch for DsuPubKeyPatcher {
    fn patcher_name(&self) -> &'static str {
        "DsuPubKeyPatcher"
    }

    fn find_targets<'a>(
        &self,
        boot_images: &HashMap<&'a str, BootImageInfo>,
        cancel_signal: &AtomicBool,
    ) -> Result<Vec<&'a str>> {
        let mut dsu_keys_targets = vec![];
        let mut first_stage_targets = vec![];

        'outer: for (name, info) in boot_images {
            let ramdisks = match &info.boot_image {
                BootImage::V0Through2(b) => slice::from_ref(&b.ramdisk),
                BootImage::V3Through4(b) => slice::from_ref(&b.ramdisk),
                BootImage::VendorV3Through4(b) => &b.ramdisks,
            };

            for ramdisk in ramdisks {
                if ramdisk.is_empty() {
                    continue;
                }

                let (entries, _) = load_ramdisk(ramdisk, cancel_signal)?;
                let mut found = false;

                for entry in entries {
                    if entry.path == Self::DSU_KEYS_PATH {
                        dsu_keys_targets.push(*name);
                        found = true;
                    } else if entry.path == Self::FIRST_STAGE_PATH {
                        first_stage_targets.push(*name);
                        found = true;
                    }
                }

                if found {
                    continue 'outer;
                }
            }
        }

        if !dsu_keys_targets.is_empty() {
            // Most builds trust as least one DSU key. For these builds, add the
            // user's key to the same directory.
            if dsu_keys_targets.len() > 1 {
                return Err(Error::Validation(format!(
                    "DSU keys found in more than one boot image: {dsu_keys_targets:?}",
                )));
            }

            Ok(dsu_keys_targets)
        } else {
            // For builds that don't trust any DSU keys, pick the first boot
            // image that contains a first stage ramdisk directory.
            if !first_stage_targets.is_empty() {
                first_stage_targets.sort_unstable();
                first_stage_targets.resize(1, "");
            }

            Ok(first_stage_targets)
        }
    }

    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &AtomicBool) -> Result<()> {
        let ramdisks = match boot_image {
            BootImage::V0Through2(b) => slice::from_mut(&mut b.ramdisk),
            BootImage::V3Through4(b) => slice::from_mut(&mut b.ramdisk),
            BootImage::VendorV3Through4(b) => &mut b.ramdisks,
        };

        for ramdisk in ramdisks {
            if ramdisk.is_empty() {
                continue;
            }

            if self.patch_ramdisk(ramdisk, cancel_signal)? {
                return Ok(());
            }
        }

        Err(Error::Validation(format!(
            "No ramdisk contains {:?}",
            Self::FIRST_STAGE_PATH.as_bstr(),
        )))
    }
}

/// Replace the boot image with a prepatched boot image if it is compatible.
///
/// An image is compatible if all the non-size-related header fields are
/// identical and the set of included sections (eg. kernel, dtb) are the same.
/// The only exception is the number of ramdisk sections, which is allowed to be
/// higher than the original image.
pub struct PrepatchedImagePatcher {
    prepatched: PathBuf,
    fatal_level: u8,
}

impl PrepatchedImagePatcher {
    const MIN_LEVEL: u8 = 0;
    const MAX_LEVEL: u8 = 2;

    // We compile without Unicode support so we have to use [0-9] instead of \d.
    const VERSION_REGEX: &'static str =
        r"Linux version ([0-9]+\.[0-9]+).[0-9]+-(android[0-9]+)-([0-9]+)-";

    pub fn new(prepatched: &Path, fatal_level: u8) -> Self {
        Self {
            prepatched: prepatched.to_owned(),
            fatal_level,
        }
    }

    fn load_prepatched_image(&self) -> Result<BootImage> {
        let raw_reader =
            File::open(&self.prepatched).map_err(|e| Error::File(self.prepatched.clone(), e))?;
        let boot_image = BootImage::from_reader(BufReader::new(raw_reader))?;

        Ok(boot_image)
    }

    fn get_kmi_version(kernel: &[u8]) -> Result<Option<String>> {
        let mut decompressed = vec![];
        {
            let raw_reader = Cursor::new(kernel);
            let mut reader = CompressedReader::new(raw_reader, true)?;
            reader.read_to_end(&mut decompressed)?;
        }

        let regex = Regex::new(Self::VERSION_REGEX).unwrap();
        let Some(captures) = regex.captures(&decompressed) else {
            return Ok(None);
        };

        let kmi_version = captures
            .iter()
            // Capture #0 is the entire match.
            .skip(1)
            .flatten()
            .map(|c| c.as_bytes())
            // Our regex only matches ASCII bytes.
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-");

        Ok(Some(kmi_version))
    }
}

impl BootImagePatch for PrepatchedImagePatcher {
    fn patcher_name(&self) -> &'static str {
        "PrepatchedImagePatcher"
    }

    fn find_targets<'a>(
        &self,
        boot_images: &HashMap<&'a str, BootImageInfo>,
        _cancel_signal: &AtomicBool,
    ) -> Result<Vec<&'a str>> {
        let prepatched_image = self.load_prepatched_image()?;

        let has_kernel = match prepatched_image {
            BootImage::V0Through2(b) => !b.kernel.is_empty(),
            BootImage::V3Through4(b) => !b.kernel.is_empty(),
            BootImage::VendorV3Through4(_) => false,
        };

        let mut targets = vec![];

        if !has_kernel && boot_images.contains_key("init_boot") {
            targets.push("init_boot");
        } else if boot_images.contains_key("boot") {
            targets.push("boot");
        };

        Ok(targets)
    }

    fn patch(&self, boot_image: &mut BootImage, _cancel_signal: &AtomicBool) -> Result<()> {
        let prepatched_image = self.load_prepatched_image()?;

        // Level 0: Warnings that don't affect booting
        // Level 1: Warnings that may affect booting
        // Level 2: Warnings that are very likely to affect booting
        let mut issues = [vec![], vec![], vec![]];

        macro_rules! check {
            ($level:literal, $old:expr, $new:expr $(,)?) => {
                let old_val = $old;
                let new_val = $new;

                if old_val != new_val {
                    issues[$level].push(format!(
                        "Field differs: {} ({:?}) -> {} ({:?})",
                        stringify!($old),
                        old_val,
                        stringify!($new),
                        new_val,
                    ));
                }
            };
        }

        let old_kernel;
        let new_kernel;

        match (&boot_image, &prepatched_image) {
            (BootImage::V0Through2(old), BootImage::V0Through2(new)) => {
                check!(2, old.header_version(), new.header_version());
                check!(2, old.kernel_addr, new.kernel_addr);
                check!(2, old.ramdisk_addr, new.ramdisk_addr);
                check!(2, old.second_addr, new.second_addr);
                check!(2, old.tags_addr, new.tags_addr);
                check!(2, old.page_size, new.page_size);
                check!(0, old.os_version, new.os_version);
                check!(0, &old.name, &new.name);
                check!(1, &old.cmdline, &new.cmdline);
                check!(0, &old.id, &new.id);
                check!(1, &old.extra_cmdline, &new.extra_cmdline);
                check!(2, old.kernel.is_empty(), new.kernel.is_empty());
                check!(2, old.second.is_empty(), new.second.is_empty());

                if let (Some(old_v1), Some(new_v1)) = (&old.v1_extra, &new.v1_extra) {
                    check!(2, old_v1.recovery_dtbo_offset, new_v1.recovery_dtbo_offset);
                    check!(
                        2,
                        old_v1.recovery_dtbo.is_empty(),
                        new_v1.recovery_dtbo.is_empty(),
                    );
                }

                if let (Some(old_v2), Some(new_v2)) = (&old.v2_extra, &new.v2_extra) {
                    check!(2, old_v2.dtb_addr, new_v2.dtb_addr);
                    check!(2, old_v2.dtb.is_empty(), new_v2.dtb.is_empty());
                }

                // We allow adding a ramdisk.
                if !old.ramdisk.is_empty() || new.ramdisk.is_empty() {
                    check!(2, old.ramdisk.is_empty(), new.ramdisk.is_empty());
                }

                old_kernel = if old.kernel.is_empty() {
                    None
                } else {
                    Some(&old.kernel)
                };
                new_kernel = if new.kernel.is_empty() {
                    None
                } else {
                    Some(&new.kernel)
                };
            }
            (BootImage::V3Through4(old), BootImage::V3Through4(new)) => {
                check!(2, old.header_version(), new.header_version());
                check!(0, old.os_version, new.os_version);
                check!(0, old.reserved, new.reserved);
                check!(1, &old.cmdline, &new.cmdline);
                check!(2, old.kernel.is_empty(), new.kernel.is_empty());

                // We allow adding a ramdisk.
                if !old.ramdisk.is_empty() || new.ramdisk.is_empty() {
                    check!(2, old.ramdisk.is_empty(), new.ramdisk.is_empty());
                }

                old_kernel = if old.kernel.is_empty() {
                    None
                } else {
                    Some(&old.kernel)
                };
                new_kernel = if new.kernel.is_empty() {
                    None
                } else {
                    Some(&new.kernel)
                };
            }
            (BootImage::VendorV3Through4(old), BootImage::VendorV3Through4(new)) => {
                check!(2, old.page_size, new.page_size);
                check!(2, old.kernel_addr, new.kernel_addr);
                check!(2, old.ramdisk_addr, new.ramdisk_addr);
                check!(1, &old.cmdline, &new.cmdline);
                check!(2, old.tags_addr, new.tags_addr);
                check!(0, &old.name, &new.name);
                check!(2, old.dtb.is_empty(), new.dtb.is_empty());
                check!(2, old.dtb_addr, new.dtb_addr);
                check!(2, old.ramdisks.len(), new.ramdisks.len());

                if let (Some(old_v4), Some(new_v4)) = (&old.v4_extra, &new.v4_extra) {
                    check!(2, &old_v4.ramdisk_metas, &new_v4.ramdisk_metas);
                    check!(2, &old_v4.bootconfig, &new_v4.bootconfig);
                }

                old_kernel = None;
                new_kernel = None;
            }
            _ => {
                return Err(Error::Validation(
                    "Boot image and prepatched image are different boot image types".to_owned(),
                ));
            }
        }

        if let (Some(old), Some(new)) = (old_kernel, new_kernel) {
            let old_kmi_version = Self::get_kmi_version(old)?;
            let new_kmi_version = Self::get_kmi_version(new)?;

            check!(2, old_kmi_version, new_kmi_version);
        }

        let mut warnings = vec![];
        let mut errors = vec![];

        for level in Self::MIN_LEVEL..self.fatal_level {
            warnings.extend(&issues[level as usize]);
        }
        for level in self.fatal_level..=Self::MAX_LEVEL {
            errors.extend(&issues[level as usize]);
        }

        if !warnings.is_empty() {
            let mut msg =
                "The prepatched boot image may not be compatible with the original:".to_owned();
            for warning in warnings {
                msg.push_str("\n- ");
                msg.push_str(warning);
            }

            warn!("{msg}");
        }

        if !errors.is_empty() {
            let mut msg =
                "The prepatched boot image is not compatible with the original:".to_owned();
            for error in errors {
                msg.push_str("\n- ");
                msg.push_str(error);
            }

            return Err(Error::Validation(msg));
        }

        *boot_image = prepatched_image;

        Ok(())
    }
}

pub fn load_boot_images<'a>(
    names: &[&'a str],
    open_input: impl Fn(&str) -> io::Result<Box<dyn ReadSeek>> + Sync,
) -> Result<HashMap<&'a str, BootImageInfo>> {
    let parent_span = Span::current();

    names
        .par_iter()
        .map(|name| {
            let _span = debug_span!(parent: &parent_span, "image", name).entered();
            let mut reader = open_input(name)?;

            let (header, footer, image_size) = avb::load_image(&mut reader)?;
            let Some(footer) = footer else {
                return Err(Error::NoFooter);
            };

            let section_reader = SectionReader::new(reader, 0, footer.original_image_size)?;
            let boot_image = BootImage::from_reader(section_reader)?;

            let info = BootImageInfo {
                header,
                footer,
                image_size,
                boot_image,
            };

            trace!("Loaded {image_size} byte boot image: {name}");

            Ok((*name, info))
        })
        .collect()
}

/// Apply applicable patches to the list of specified boot images. For each
/// image, the applicable patchers run in the same order as in `patchers`. All
/// operations run in parallel where possible. Only the patcher execution for a
/// given image is guaranteed to be sequential. The input and output files will
/// be opened from multiple threads, but at most once each.
pub fn patch_boot_images<'a>(
    names: &[&'a str],
    open_input: impl Fn(&str) -> io::Result<Box<dyn ReadSeek>> + Sync,
    open_output: impl Fn(&str) -> io::Result<Box<dyn WriteSeek>> + Sync,
    key: &RsaSigningKey,
    patchers: &[Box<dyn BootImagePatch + Sync>],
    cancel_signal: &AtomicBool,
) -> Result<HashSet<&'a str>> {
    let parent_span = Span::current();

    if patchers.is_empty() {
        debug!("Skip loading boot images; nothing to patch");
        return Ok(HashSet::new());
    }

    // Preparse all images. Some patchers need to inspect every candidate.
    let mut images = load_boot_images(names, open_input)?;

    // Find the targets that each patcher wants to patch.
    let all_targets = patchers
        .par_iter()
        .map(|p| {
            let _span =
                debug_span!(parent: &parent_span, "patcher", name = p.patcher_name()).entered();
            p.find_targets(&images, cancel_signal).and_then(|targets| {
                if targets.is_empty() {
                    Err(Error::NoTargets(p.patcher_name()))
                } else {
                    debug!("Found patcher targets: {targets:?}");
                    Ok(targets)
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;

    debug!("All patcher targets: {all_targets:?}");

    // Regroup data so we can parallelize by target.
    let mut groups = HashMap::<&str, (BootImageInfo, Vec<&Box<dyn BootImagePatch + Sync>>)>::new();
    for (patcher, targets) in patchers.iter().zip(all_targets.into_iter()) {
        for target in targets {
            groups
                .entry(target)
                .or_insert_with(|| (images.remove(target).unwrap(), vec![]))
                .1
                .push(patcher);
        }
    }

    // Deallocate all untouched images.
    drop(images);

    // Apply all patches.
    groups
        .par_iter_mut()
        .try_for_each(|(_, (info, patchers))| -> Result<()> {
            patchers.iter().try_for_each(|p| {
                let _span =
                    debug_span!(parent: &parent_span, "patcher", name = p.patcher_name()).entered();
                p.patch(&mut info.boot_image, cancel_signal)
            })
        })?;

    // Resign and write new images.
    groups
        .par_iter_mut()
        .map(|(name, (info, _))| {
            let _span = debug_span!(parent: &parent_span, "image", name).entered();

            let AppendedDescriptorMut::Hash(descriptor) = info.header.appended_descriptor_mut()?
            else {
                return Err(Error::NoHashDescriptor);
            };

            let writer = open_output(name)?;

            // Write new boot image. We reuse the existing salt for the digest.
            let mut context = Context::new(&ring::digest::SHA256);
            context.update(&descriptor.salt);
            let mut hashing_writer = HashingWriter::new(writer, context);
            info.boot_image.to_writer(&mut hashing_writer)?;
            let (mut writer, context) = hashing_writer.finish();

            descriptor.image_size = writer.stream_position()?;
            "sha256".clone_into(&mut descriptor.hash_algorithm);
            descriptor.root_digest = context.finish().as_ref().to_vec();

            if !info.header.public_key.is_empty() {
                debug!("Signing boot image");
                info.header.set_algo_for_key(key)?;
                info.header.sign(key)?;
            }

            avb::write_appended_image(
                writer,
                &info.header,
                &mut info.footer,
                Some(info.image_size),
            )?;

            Ok(())
        })
        .collect::<Result<()>>()?;

    Ok(groups.keys().copied().collect())
}
