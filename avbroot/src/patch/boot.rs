// SPDX-FileCopyrightText: 2022-2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt::Write,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read},
    num::ParseIntError,
    ops::{Range, RangeFrom},
    path::{Path, PathBuf},
    slice, str,
    sync::atomic::AtomicBool,
};

use bstr::ByteSlice;
use lzma_rust2::{CheckType, XZOptions, XZWriter};
use rawzip::{RECOMMENDED_BUFFER_SIZE, ZipArchive};
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use regex::bytes::Regex;
use ring::digest::Context;
use rsa::RsaPublicKey;
use thiserror::Error;
use tracing::{Span, debug, debug_span, trace, warn};
use x509_cert::Certificate;

use crate::{
    crypto::{self, RsaSigningKey},
    format::{
        avb::{self, AppendedDescriptorMut, Footer, Header},
        bootimage::{self, BootImage, BootImageExt, RamdiskMeta},
        compression::{self, CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{self, CpioEntry, CpioEntryData},
        zip::{self, ZipEntriesSafeExt, ZipFileHeaderRecordExt, ZipSliceEntriesSafeExt},
    },
    patch::otacert::{self, OtaCertBuildFlags},
    stream::{self, FromReader, HashingWriter, ReadSeek, SectionReader, ToWriter, WriteSeek},
    util,
};

#[derive(Debug, Error)]
pub enum Error {
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
    #[error("Failed to load potentially compressed ramdisk")]
    RamdiskLoadCompression(#[source] compression::Error),
    #[error("Failed to save potentially compressed ramdisk")]
    RamdiskSaveCompression(#[source] compression::Error),
    #[error("Failed to finalize compressed ramdisk")]
    RamdiskSaveCompressionFinalize(#[source] io::Error),
    #[error("Failed to load ramdisk cpio entries")]
    RamdiskLoadCpio(#[source] cpio::Error),
    #[error("Failed to save ramdisk cpio entries")]
    RamdiskSaveCpio(#[source] cpio::Error),
    #[error("Failed to load potentially compressed kernel")]
    KernelLoadCompression(#[source] compression::Error),
    #[error("Failed to read kernel image")]
    KernelRead(#[source] io::Error),
    #[error("Failed to load boot image")]
    BootImageLoad(#[source] bootimage::Error),
    #[error("Failed to save boot image")]
    BootImageSave(#[source] bootimage::Error),
    #[error("Failed to seek boot image")]
    BootImageSeek(#[source] io::Error),
    #[error("Failed to encode public key in AVB binary format")]
    AvbEncodeKey(#[source] avb::Error),
    #[error("Failed to load AVB header from boot image")]
    AvbLoad(#[source] avb::Error),
    #[error("Failed to update AVB header for boot image")]
    AvbUpdate(#[source] avb::Error),
    #[error("Failed to load OTA certificate")]
    OtaCertLoad(#[source] crypto::Error),
    #[error("Failed to generate replacement otacerts zip")]
    OtaCertZip(#[source] otacert::Error),
    #[error("Failed to initialize XZ encoder")]
    XzInit(#[source] io::Error),
    #[error("Failed to XZ compress entry: {:?}", .0.as_bstr())]
    XzCompress(Vec<u8>, #[source] io::Error),
    #[error("Failed to open zip file: {0:?}")]
    ZipOpen(PathBuf, #[source] rawzip::Error),
    #[error("Failed to list zip entries")]
    ZipEntryList(#[source] rawzip::Error),
    #[error("Missing zip entry: {0:?}")]
    ZipEntryMissing(Cow<'static, str>),
    #[error("Failed to open zip entry: {0:?}")]
    ZipEntryOpen(Cow<'static, str>, #[source] rawzip::Error),
    #[error("Failed to read zip entry: {0:?}")]
    ZipEntryRead(Cow<'static, str>, #[source] io::Error),
    #[error("Failed to open file: {0:?}")]
    FileOpen(PathBuf, #[source] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum TargetsError {
    #[error("No compatible boot image found for {0}")]
    NoTargets(&'static str),
    #[error("Targets validation error: {0}")]
    TargetValidation(String),
    #[error("Failed to open boot image: {0}")]
    Open(String, #[source] io::Error),
    #[error("Failed to load boot image: {0}")]
    Load(String, #[source] Error),
    #[error("Failed to save boot image: {0}")]
    Save(String, #[source] Error),
    #[error("Failed to patch boot image: {0}")]
    Patch(String, #[source] Error),
}

type TargetsResult<T> = std::result::Result<T, TargetsError>;

fn load_ramdisk(
    data: &[u8],
    cancel_signal: &AtomicBool,
) -> Result<(Vec<CpioEntry>, CompressedFormat)> {
    let raw_reader = Cursor::new(data);
    let mut reader =
        CompressedReader::new(raw_reader, false).map_err(Error::RamdiskLoadCompression)?;
    let entries = cpio::load(&mut reader, false, cancel_signal).map_err(Error::RamdiskLoadCpio)?;

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
    let mut writer =
        CompressedWriter::new(raw_writer, format).map_err(Error::RamdiskSaveCompression)?;
    cpio::save(&mut writer, entries, false, cancel_signal).map_err(Error::RamdiskSaveCpio)?;

    trace!("Wrote {format:?} ramdisk with {} entries", entries.len());

    let raw_writer = writer
        .finish()
        .map_err(Error::RamdiskSaveCompressionFinalize)?;
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
    ) -> TargetsResult<Vec<&'a str>>;

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
    // - Versions newer than the latest supported version are assumed to support
    //   the same features as the latest version
    const VERS_SUPPORTED: &'static [Range<u32>] = &[25102..25207, 25211..30400];
    const VER_PREINIT_DEVICE: RangeFrom<u32> = 25211..;
    const VER_RANDOM_SEED: Range<u32> = 25211..26103;
    const VER_PATCH_VBMETA: Range<u32> = Self::VERS_SUPPORTED[0].start..26202;
    const VER_XZ_BACKUP: RangeFrom<u32> = 26403..;
    const VER_VENDOR_BOOT: RangeFrom<u32> = 30300..;

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

    fn get_version(apk_path: &Path) -> Result<u32> {
        let file = File::open(apk_path).map_err(|e| Error::FileOpen(apk_path.to_owned(), e))?;
        let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
        let archive = ZipArchive::from_file(file, &mut buffer)
            .map_err(|e| Error::ZipOpen(apk_path.to_owned(), e))?;
        let mut entries = archive.entries_safe(&mut buffer);

        while let Some((cd_entry, entry)) = entries.next_entry().map_err(Error::ZipEntryList)? {
            let path = cd_entry.file_path_utf8().map_err(Error::ZipEntryList)?;

            if path != Self::ZIP_UTIL_FUNCTIONS {
                continue;
            }

            let mut reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map(BufReader::new)
                .map_err(|e| Error::ZipEntryOpen(Self::ZIP_UTIL_FUNCTIONS.into(), e))?;
            let mut line = String::new();

            loop {
                line.clear();
                let n = reader
                    .read_line(&mut line)
                    .map_err(|e| Error::ZipEntryRead(Self::ZIP_UTIL_FUNCTIONS.into(), e))?;
                if n == 0 {
                    return Err(Error::FindMagiskVersion(apk_path.to_owned()));
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

        Err(Error::ZipEntryMissing(Self::ZIP_UTIL_FUNCTIONS.into()))
    }

    fn xz_compress(name: &[u8], reader: impl Read, cancel_signal: &AtomicBool) -> Result<Vec<u8>> {
        let mut options = XZOptions::with_preset(9);
        options.set_check_sum_type(CheckType::None);

        let raw_writer = Cursor::new(Vec::new());
        let mut writer = XZWriter::new(raw_writer, options).map_err(Error::XzInit)?;

        let raw_writer = stream::copy(reader, &mut writer, cancel_signal)
            .and_then(|_| writer.finish())
            .map_err(|e| Error::XzCompress(name.to_owned(), e))?;

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

            let new_data = if xz_compress && let CpioEntryData::Data(data) = &old_entry.data {
                new_path.extend(b".xz");

                let reader = Cursor::new(data);
                let buf = Self::xz_compress(&new_path, reader, cancel_signal)?;
                Some(CpioEntryData::Data(buf))
            } else {
                None
            };

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
    ) -> TargetsResult<Vec<&'a str>> {
        let mut targets = vec![];

        if boot_images.contains_key("init_boot") {
            targets.push("init_boot");
        } else if boot_images.contains_key("boot") {
            targets.push("boot");
        }

        Ok(targets)
    }

    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &AtomicBool) -> Result<()> {
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

        let file =
            File::open(&self.apk_path).map_err(|e| Error::FileOpen(self.apk_path.clone(), e))?;
        let mut buffer = vec![0u8; RECOMMENDED_BUFFER_SIZE];
        let archive = ZipArchive::from_file(file, &mut buffer)
            .map_err(|e| Error::ZipOpen(self.apk_path.clone(), e))?;

        let mut zip_entries = archive.entries_safe(&mut buffer);
        let mut found_magiskinit = false;
        let mut found_libmagisk = false;

        while let Some((cd_entry, entry)) = zip_entries.next_entry().map_err(Error::ZipEntryList)? {
            let path = cd_entry.file_path_utf8().map_err(Error::ZipEntryList)?;

            // magiskinit is the only entry that is not xz-compressed.
            if path == Self::ZIP_MAGISKINIT {
                let mut reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                    .map_err(|e| Error::ZipEntryOpen(Self::ZIP_MAGISKINIT.into(), e))?;
                let mut data = vec![];

                reader
                    .read_to_end(&mut data)
                    .map_err(|e| Error::ZipEntryRead(Self::ZIP_MAGISKINIT.into(), e))?;

                entries.push(CpioEntry::new_file(
                    b"init",
                    0o750,
                    CpioEntryData::Data(data),
                ));

                found_magiskinit = true;
                continue;
            }

            // Keep a 'static version of the zip path.
            let (path, cpio_path): (_, &[u8]) = match path {
                // Newer Magisk versions only include a single binary for the
                // target ABI in the ramdisk. This was introduced in commit
                // fb5ee86615ed3df830e8538f8b39b1b133caea34.
                p if p == Self::ZIP_LIBMAGISK => {
                    debug!("Single libmagisk");
                    found_libmagisk = true;
                    (Self::ZIP_LIBMAGISK, b"overlay.d/sbin/magisk.xz")
                }
                // Older Magisk versions include the 64-bit binary and,
                // optionally, the 32-bit binary if the device supports it. We
                // unconditionally include the magisk32 because the boot image
                // itself doesn't have sufficient information to determine if a
                // device is 64-bit only.
                p if p == Self::ZIP_LIBMAGISK32 => {
                    debug!("Split libmagisk32");
                    found_libmagisk = true;
                    (Self::ZIP_LIBMAGISK32, b"overlay.d/sbin/magisk32.xz")
                }
                p if p == Self::ZIP_LIBMAGISK64 => {
                    debug!("Split libmagisk64");
                    found_libmagisk = true;
                    (Self::ZIP_LIBMAGISK64, b"overlay.d/sbin/magisk64.xz")
                }
                // The stub apk was introduced in commit
                // ad0e6511e11ebec65aa9b5b916e1397342850319.
                p if p == Self::ZIP_STUB => {
                    debug!("Magisk stub found");
                    (Self::ZIP_STUB, b"overlay.d/sbin/stub.xz")
                }
                // init-ld was introduced in commit
                // 33aebb59763b6ec27209563035303700e998633d.
                p if p == Self::ZIP_INIT_LD => {
                    debug!("Magisk init-ld found");
                    (Self::ZIP_INIT_LD, b"overlay.d/sbin/init-ld.xz")
                }
                _ => continue,
            };

            let reader = zip::verifying_reader(&entry, cd_entry.compression_method())
                .map_err(|e| Error::ZipEntryOpen(path.into(), e))?;

            let buf = Self::xz_compress(path.as_bytes(), reader, cancel_signal)?;

            entries.push(CpioEntry::new_file(
                cpio_path,
                0o644,
                CpioEntryData::Data(buf),
            ));
        }

        if !found_magiskinit {
            return Err(Error::ZipEntryMissing(Self::ZIP_MAGISKINIT.into()));
        } else if !found_libmagisk {
            return Err(Error::ZipEntryMissing(Self::ZIP_LIBMAGISK.into()));
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

        // We never install Magisk into the init_boot.cpio within the
        // vendor_boot ramdisk. This config option was introduced in commit
        // 742913ebcb10cf819a54699497359535047874f7.
        if Self::VER_VENDOR_BOOT.contains(&self.version) {
            magisk_config.push_str("VENDORBOOT=false\n");
        }

        if Self::VER_PREINIT_DEVICE.contains(&self.version)
            && let Some(device) = &self.preinit_device
        {
            writeln!(&mut magisk_config, "PREINITDEVICE={device}").unwrap();
        }

        // Magisk normally saves the original SHA1 digest in its config file. It
        // uses this to find the original image in /data/magisk_backup_<sha1> to
        // restore the stock boot image for uninstallation purposes. This is a
        // feature we cannot ever use, so just use a dummy value.
        magisk_config.push_str("SHA1=0000000000000000000000000000000000000000\n");

        if Self::VER_RANDOM_SEED.contains(&self.version) {
            writeln!(&mut magisk_config, "RANDOMSEED={:#x}", self.random_seed).unwrap();
        }

        trace!("Magisk config: {magisk_config:?}");

        entries.push(CpioEntry::new_file(
            b".backup/.magisk",
            0,
            CpioEntryData::Data(magisk_config.into_bytes()),
        ));

        // Repack ramdisk.
        cpio::sort(&mut entries);
        cpio::assign_inodes(&mut entries, false).map_err(Error::RamdiskSaveCpio)?;
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
    const OTACERTS_PATH: &'static str = "system/etc/security/otacerts.zip";

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
            let Some(entry) = entries
                .iter()
                .find(|e| e.path == Self::OTACERTS_PATH.as_bytes())
            else {
                continue;
            };
            let CpioEntryData::Data(data) = &entry.data else {
                continue;
            };

            let archive = ZipArchive::from_slice(data)
                .map_err(|e| Error::ZipOpen(Self::OTACERTS_PATH.into(), e))?;
            let mut entries = archive.entries_safe();

            while let Some((cd_entry, entry)) = entries.next_entry().map_err(Error::ZipEntryList)? {
                let path = cd_entry.file_path_utf8().map_err(Error::ZipEntryList)?;

                if !path.ends_with(".x509.pem") {
                    debug!("Skipping invalid entry path: {path:?}");
                    continue;
                }

                let reader = zip::verifying_slice_reader(&entry, cd_entry.compression_method())
                    .map_err(|e| Error::ZipEntryOpen(path.to_owned().into(), e))?;

                let certificate =
                    crypto::read_pem_cert(Path::new(path), reader).map_err(Error::OtaCertLoad)?;
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
        let Some(entry) = entries
            .iter_mut()
            .find(|e| e.path == Self::OTACERTS_PATH.as_bytes())
        else {
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
    ) -> TargetsResult<Vec<&'a str>> {
        let mut targets = vec![];

        'outer: for (&name, info) in boot_images {
            let ramdisks = match &info.boot_image {
                BootImage::V0Through2(b) => slice::from_ref(&b.ramdisk),
                BootImage::V3Through4(b) => slice::from_ref(&b.ramdisk),
                BootImage::VendorV3Through4(b) => &b.ramdisks,
            };

            for ramdisk in ramdisks {
                if ramdisk.is_empty() {
                    continue;
                }

                let (entries, _) = load_ramdisk(ramdisk, cancel_signal)
                    .map_err(|e| TargetsError::Load(name.to_owned(), e))?;
                if entries
                    .iter()
                    .any(|e| e.path == Self::OTACERTS_PATH.as_bytes())
                {
                    targets.push(name);
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

        let new_zip = otacert::create_zip(&self.cert, OtaCertBuildFlags::empty())
            .map_err(Error::OtaCertZip)?;
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
            Self::OTACERTS_PATH,
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

        let binary_key = avb::encode_public_key(&self.key).map_err(Error::AvbEncodeKey)?;
        let data = CpioEntryData::Data(binary_key);

        if let Some(e) = entries
            .iter_mut()
            .find(|e| e.path == Self::AVBROOT_KEY_PATH)
        {
            e.data = data;
        } else {
            entries.push(CpioEntry::new_file(Self::AVBROOT_KEY_PATH, 0o644, data));
        }

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
    ) -> TargetsResult<Vec<&'a str>> {
        let mut dsu_keys_targets = vec![];
        let mut first_stage_targets = vec![];

        'outer: for (&name, info) in boot_images {
            let ramdisks = match &info.boot_image {
                BootImage::V0Through2(b) => slice::from_ref(&b.ramdisk),
                BootImage::V3Through4(b) => slice::from_ref(&b.ramdisk),
                BootImage::VendorV3Through4(b) => &b.ramdisks,
            };

            for ramdisk in ramdisks {
                if ramdisk.is_empty() {
                    continue;
                }

                let (entries, _) = load_ramdisk(ramdisk, cancel_signal)
                    .map_err(|e| TargetsError::Load(name.to_owned(), e))?;
                let mut found = false;

                for entry in entries {
                    if entry.path == Self::DSU_KEYS_PATH {
                        dsu_keys_targets.push(name);
                        found = true;
                    } else if entry.path == Self::FIRST_STAGE_PATH {
                        first_stage_targets.push(name);
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
                return Err(TargetsError::TargetValidation(format!(
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
        let reader = File::open(&self.prepatched)
            .map(BufReader::new)
            .map_err(|e| Error::FileOpen(self.prepatched.clone(), e))?;

        BootImage::from_reader(reader).map_err(Error::BootImageLoad)
    }

    fn get_kmi_version(kernel: &[u8]) -> Result<Option<String>> {
        let mut decompressed = vec![];
        {
            let raw_reader = Cursor::new(kernel);
            let mut reader =
                CompressedReader::new(raw_reader, true).map_err(Error::KernelLoadCompression)?;
            reader
                .read_to_end(&mut decompressed)
                .map_err(Error::KernelRead)?;
        }

        let regex = Regex::new(Self::VERSION_REGEX).unwrap();
        let Some(captures) = regex.captures(&decompressed) else {
            return Ok(None);
        };

        let kmi_version = util::join(
            captures
                .iter()
                // Capture #0 is the entire match.
                .skip(1)
                .flatten()
                .map(|c| c.as_bytes())
                // Our regex only matches ASCII bytes.
                .map(|c| std::str::from_utf8(c).unwrap()),
            "-",
        );

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
    ) -> TargetsResult<Vec<&'a str>> {
        let prepatched_image = self
            .load_prepatched_image()
            .map_err(|e| TargetsError::Load("prepatched".to_owned(), e))?;

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
        }

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

fn load_boot_image(reader: &mut dyn ReadSeek) -> Result<BootImageInfo> {
    let (header, footer, image_size) = avb::load_image(&mut *reader).map_err(Error::AvbLoad)?;
    let Some(footer) = footer else {
        return Err(Error::NoFooter);
    };

    let section_reader =
        SectionReader::new(reader, 0, footer.original_image_size).map_err(Error::BootImageSeek)?;
    let boot_image = BootImage::from_reader(section_reader).map_err(Error::BootImageLoad)?;

    let info = BootImageInfo {
        header,
        footer,
        image_size,
        boot_image,
    };

    trace!("Loaded {image_size} byte boot image");

    Ok(info)
}

fn save_boot_image(
    writer: &mut dyn WriteSeek,
    info: &mut BootImageInfo,
    key: &RsaSigningKey,
) -> Result<()> {
    let AppendedDescriptorMut::Hash(descriptor) = info
        .header
        .appended_descriptor_mut()
        .map_err(Error::AvbUpdate)?
    else {
        return Err(Error::NoHashDescriptor);
    };

    // Write new boot image. We reuse the existing salt for the digest.
    let mut context = Context::new(&ring::digest::SHA256);
    context.update(&descriptor.salt);
    let mut hashing_writer = HashingWriter::new(writer, context);
    info.boot_image
        .to_writer(&mut hashing_writer)
        .map_err(Error::BootImageSave)?;
    let (writer, context) = hashing_writer.finish();

    descriptor.image_size = writer.stream_position().map_err(Error::BootImageSeek)?;
    "sha256".clone_into(&mut descriptor.hash_algorithm);
    descriptor.root_digest = context.finish().as_ref().to_vec();

    if !info.header.public_key.is_empty() {
        debug!("Signing boot image");
        info.header
            .set_algo_for_key(key)
            .map_err(Error::AvbUpdate)?;
        info.header.sign(key).map_err(Error::AvbUpdate)?;
    }

    avb::write_appended_image(
        writer,
        &info.header,
        &mut info.footer,
        Some(info.image_size),
    )
    .map_err(Error::AvbUpdate)?;

    Ok(())
}

pub trait BootImageOpener {
    fn open_original(&self, name: &str) -> io::Result<Box<dyn ReadSeek + Sync>>;

    fn open_replacement(&self, name: &str) -> io::Result<Box<dyn WriteSeek + Sync>> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} boot image not found"),
        ))
    }
}

pub fn load_boot_images<'a>(
    names: &[&'a str],
    opener: &(dyn BootImageOpener + Sync),
) -> TargetsResult<HashMap<&'a str, BootImageInfo>> {
    let parent_span = Span::current();

    names
        .par_iter()
        .map(|&name| {
            let _span = debug_span!(parent: &parent_span, "image", name).entered();
            let mut reader = opener
                .open_original(name)
                .map_err(|e| TargetsError::Open(name.to_owned(), e))?;

            let info =
                load_boot_image(&mut reader).map_err(|e| TargetsError::Load(name.to_owned(), e))?;

            Ok((name, info))
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
    opener: &(dyn BootImageOpener + Sync),
    key: &RsaSigningKey,
    patchers: &[Box<dyn BootImagePatch + Sync>],
    cancel_signal: &AtomicBool,
) -> TargetsResult<HashSet<&'a str>> {
    let parent_span = Span::current();

    if patchers.is_empty() {
        debug!("Skip loading boot images; nothing to patch");
        return Ok(HashSet::new());
    }

    // Preparse all images. Some patchers need to inspect every candidate.
    let mut images = load_boot_images(names, opener)?;

    // Find the targets that each patcher wants to patch.
    let all_targets = patchers
        .par_iter()
        .map(|p| {
            let _span =
                debug_span!(parent: &parent_span, "patcher", name = p.patcher_name()).entered();
            p.find_targets(&images, cancel_signal).and_then(|targets| {
                if targets.is_empty() {
                    Err(TargetsError::NoTargets(p.patcher_name()))
                } else {
                    debug!("Found patcher targets: {targets:?}");
                    Ok(targets)
                }
            })
        })
        .collect::<TargetsResult<Vec<_>>>()?;

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
        .try_for_each(|(&name, (info, patchers))| -> TargetsResult<()> {
            patchers.iter().try_for_each(|p| {
                let _span =
                    debug_span!(parent: &parent_span, "patcher", name = p.patcher_name()).entered();
                p.patch(&mut info.boot_image, cancel_signal)
                    .map_err(|e| TargetsError::Patch(name.to_owned(), e))
            })
        })?;

    // Resign and write new images.
    groups.par_iter_mut().try_for_each(|(&name, (info, _))| {
        let _span = debug_span!(parent: &parent_span, "image", name).entered();
        let mut writer = opener
            .open_replacement(name)
            .map_err(|e| TargetsError::Open(name.to_owned(), e))?;

        save_boot_image(&mut writer, info, key).map_err(|e| TargetsError::Save(name.to_owned(), e))
    })?;

    Ok(groups.keys().copied().collect())
}
