/*
 * SPDX-FileCopyrightText: 2022-2023 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    cmp::Ordering,
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, Cursor, Read, Seek, Write},
    num::ParseIntError,
    ops::Range,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
};

use regex::bytes::Regex;
use ring::digest::Context;
use rsa::RsaPrivateKey;
use thiserror::Error;
use x509_cert::Certificate;
use xz2::{
    stream::{Check, Stream},
    write::XzEncoder,
};
use zip::{result::ZipError, write::FileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    crypto,
    format::{
        avb::{self, AlgorithmType, Descriptor},
        bootimage::{self, BootImage, BootImageExt, RamdiskMeta},
        compression::{self, CompressedFormat, CompressedReader, CompressedWriter},
        cpio::{self, CpioEntryNew},
    },
    stream::{self, FromReader, HashingWriter, SectionReader, ToWriter},
    util::EscapedString,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Boot image has no vbmeta footer")]
    NoFooter,
    #[error("No hash descriptor found in vbmeta footer")]
    NoHashDescriptor,
    #[error("Found multiple hash descriptors in vbmeta footer")]
    MultipleHashDescriptors,
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
    #[error("XZ stream error")]
    XzStream(#[from] xz2::stream::Error),
    #[error("Zip error")]
    Zip(#[from] ZipError),
    #[error("I/O error")]
    IoError(#[from] io::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn load_ramdisk(data: &[u8]) -> Result<(Vec<CpioEntryNew>, CompressedFormat)> {
    let raw_reader = Cursor::new(data);
    let mut reader = CompressedReader::new(raw_reader, false)?;
    let entries = cpio::load(&mut reader, false)?;

    Ok((entries, reader.format()))
}

fn save_ramdisk(entries: &[CpioEntryNew], format: CompressedFormat) -> Result<Vec<u8>> {
    let raw_writer = Cursor::new(vec![]);
    let mut writer = CompressedWriter::new(raw_writer, format)?;
    cpio::save(&mut writer, entries, false)?;

    let raw_writer = writer.finish()?;
    Ok(raw_writer.into_inner())
}

pub trait BootImagePatcher {
    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &Arc<AtomicBool>) -> Result<()>;
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
    const VERS_SUPPORTED: &[Range<u32>] = &[25102..25207, 25211..26200];
    const VER_PREINIT_DEVICE: Range<u32> =
        25211..Self::VERS_SUPPORTED[Self::VERS_SUPPORTED.len() - 1].end;
    const VER_RANDOM_SEED: Range<u32> = 25211..26103;

    pub fn new(
        path: &Path,
        preinit_device: Option<&str>,
        random_seed: Option<u64>,
        ignore_compatibility: bool,
        warning_fn: impl Fn(&str) + Send + 'static,
    ) -> Result<Self> {
        let version = Self::get_version(path)?;

        if !Self::VERS_SUPPORTED.iter().any(|v| v.contains(&version)) {
            let msg = format!(
                "Unsupported Magisk version {} (supported: {:?})",
                version,
                Self::VERS_SUPPORTED,
            );

            if ignore_compatibility {
                warning_fn(&msg);
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
                warning_fn(&msg);
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
        let reader = File::open(path)?;
        let reader = BufReader::new(reader);
        let mut zip = ZipArchive::new(reader)?;
        let entry = zip.by_name("assets/util_functions.sh")?;
        let mut entry = BufReader::new(entry);
        let mut line = String::new();

        loop {
            line.clear();
            let n = entry.read_line(&mut line)?;
            if n == 0 {
                return Err(Error::FindMagiskVersion(path.to_owned()));
            }

            if let Some(suffix) = line.trim_end().strip_prefix("MAGISK_VER_CODE=") {
                let version = suffix
                    .parse()
                    .map_err(|e| Error::ParseMagiskVersion(suffix.to_owned(), e))?;
                return Ok(version);
            }
        }
    }

    /// Compare old and new ramdisk entry lists, creating the Magisk `.backup/`
    /// directory structure. `.backup/.rmlist` will contain a sorted list of
    /// NULL-terminated strings, listing which files were newly added or
    /// changed. The old entries for changed files will be added to the new
    /// entries as `.backup/<path>`.
    ///
    /// Both lists and entries within the lists may be mutated.
    fn apply_magisk_backup(old_entries: &mut [CpioEntryNew], new_entries: &mut Vec<CpioEntryNew>) {
        cpio::sort(old_entries);
        cpio::sort(new_entries);

        let mut rm_list = vec![];
        let mut to_back_up = vec![];

        let mut old_iter = old_entries.iter().peekable();
        let mut new_iter = new_entries.iter().peekable();

        loop {
            match (old_iter.peek(), new_iter.peek()) {
                (Some(&old), Some(&new)) => match old.name.cmp(&new.name) {
                    Ordering::Less => {
                        to_back_up.push(old);
                        old_iter.next();
                    }
                    Ordering::Equal => {
                        if old.content != new.content {
                            to_back_up.push(old);
                        }
                        old_iter.next();
                        new_iter.next();
                    }
                    Ordering::Greater => {
                        rm_list.extend(&new.name);
                        rm_list.push(b'\0');
                        new_iter.next();
                    }
                },
                (Some(old), None) => {
                    to_back_up.push(old);
                    old_iter.next();
                }
                (None, Some(new)) => {
                    rm_list.extend(&new.name);
                    rm_list.push(b'\0');
                    new_iter.next();
                }
                (None, None) => break,
            }
        }

        // Intentially using 000 permissions to match Magisk.
        new_entries.push(CpioEntryNew::new_directory(b".backup"));

        for old_entry in to_back_up {
            let mut new_entry = old_entry.clone();
            new_entry.name = b".backup/".to_vec();
            new_entry.name.extend(&old_entry.name);
            new_entries.push(new_entry);
        }

        {
            // Intentially using 000 permissions to match Magisk.
            let mut entry = CpioEntryNew::new_file(b".backup/.rmlist");
            entry.content = rm_list;
            new_entries.push(entry);
        }
    }
}

impl BootImagePatcher for MagiskRootPatcher {
    fn patch(&self, boot_image: &mut BootImage, cancel_signal: &Arc<AtomicBool>) -> Result<()> {
        let zip_reader = File::open(&self.apk_path)?;
        let mut zip = ZipArchive::new(BufReader::new(zip_reader))?;

        // Load the first ramdisk. If it doesn't exist, we have to generate one
        // from scratch.
        let ramdisk = match boot_image {
            BootImage::V0Through2(b) => Some(&b.ramdisk),
            BootImage::V3Through4(b) => Some(&b.ramdisk),
            BootImage::VendorV3Through4(b) => b.ramdisks.first(),
        };
        let (mut entries, ramdisk_format) = match ramdisk {
            Some(r) if !r.is_empty() => load_ramdisk(r)?,
            _ => (vec![], CompressedFormat::Lz4Legacy),
        };

        let mut old_entries = entries.clone();

        // Create the Magisk directory structure.
        for (path, perms) in [
            (b"overlay.d".as_slice(), 0o750),
            (b"overlay.d/sbin".as_slice(), 0o750),
        ] {
            let mut entry = CpioEntryNew::new_directory(path);
            entry.mode |= perms;
            entries.push(entry);
        }

        // Delete the original init.
        entries.retain(|e| e.name != b"init");

        // Add magiskinit.
        {
            let mut zip_entry = zip.by_name("lib/arm64-v8a/libmagiskinit.so")?;
            let mut data = vec![];
            zip_entry.read_to_end(&mut data)?;

            let mut entry = CpioEntryNew::new_file(b"init");
            entry.mode |= 0o750;
            entry.content = data;
            entries.push(entry);
        }

        // Add xz-compressed magisk32 and magisk64.
        let mut xz_files = HashMap::<&str, &[u8]>::new();
        xz_files.insert(
            "lib/armeabi-v7a/libmagisk32.so",
            b"overlay.d/sbin/magisk32.xz",
        );
        xz_files.insert(
            "lib/arm64-v8a/libmagisk64.so",
            b"overlay.d/sbin/magisk64.xz",
        );

        // Add stub apk, which only exists after Magisk commit
        // ad0e6511e11ebec65aa9b5b916e1397342850319.
        if zip.file_names().any(|n| n == "assets/stub.apk") {
            xz_files.insert("assets/stub.apk", b"overlay.d/sbin/stub.xz");
        }

        for (source, target) in xz_files {
            let reader = zip.by_name(source)?;
            let raw_writer = Cursor::new(vec![]);
            let stream = Stream::new_easy_encoder(9, Check::Crc32)?;
            let mut writer = XzEncoder::new_stream(raw_writer, stream);

            stream::copy(reader, &mut writer, cancel_signal)?;

            let raw_writer = writer.finish()?;
            let mut entry = CpioEntryNew::new_file(target);
            entry.mode |= 0o644;
            entry.content = raw_writer.into_inner();
            entries.push(entry);
        }

        // Create Magisk .backup directory structure.
        Self::apply_magisk_backup(&mut old_entries, &mut entries);

        // Create Magisk config.
        let mut magisk_config = String::new();
        magisk_config.push_str("KEEPVERITY=true\n");
        magisk_config.push_str("KEEPFORCEENCRYPT=true\n");
        magisk_config.push_str("PATCHVBMETAFLAG=false\n");
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

        {
            // Intentially using 000 permissions to match Magisk.
            let mut entry = CpioEntryNew::new_file(b".backup/.magisk");
            entry.content = magisk_config.into_bytes();
            entries.push(entry);
        }

        // Repack ramdisk.
        cpio::sort(&mut entries);
        cpio::reassign_inodes(&mut entries);
        let new_ramdisk = save_ramdisk(&entries, ramdisk_format)?;

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
    const OTACERTS_PATH: &[u8] = b"system/etc/security/otacerts.zip";

    pub fn new(cert: Certificate) -> Self {
        Self { cert }
    }

    fn patch_ramdisk(&self, data: &mut Vec<u8>) -> Result<bool> {
        let (mut entries, ramdisk_format) = load_ramdisk(data)?;
        let Some(entry) = entries.iter_mut().find(|e| e.name == Self::OTACERTS_PATH) else {
            return Ok(false);
        };

        // Create a new otacerts archive. The old certs are ignored since
        // flashing a stock OTA will render the device unbootable.
        {
            let raw_writer = Cursor::new(vec![]);
            let mut writer = ZipWriter::new(raw_writer);
            let options = FileOptions::default().compression_method(CompressionMethod::Stored);
            writer.start_file("ota.x509.pem", options)?;

            crypto::write_pem_cert(&mut writer, &self.cert)?;

            let raw_writer = writer.finish()?;
            entry.content = raw_writer.into_inner();
        }

        // Repack ramdisk.
        *data = save_ramdisk(&entries, ramdisk_format)?;

        Ok(true)
    }
}

impl BootImagePatcher for OtaCertPatcher {
    fn patch(&self, boot_image: &mut BootImage, _cancel_signal: &Arc<AtomicBool>) -> Result<()> {
        let patched_any = match boot_image {
            BootImage::V0Through2(b) => self.patch_ramdisk(&mut b.ramdisk)?,
            BootImage::V3Through4(b) => self.patch_ramdisk(&mut b.ramdisk)?,
            BootImage::VendorV3Through4(b) => {
                let mut patched = false;

                for ramdisk in &mut b.ramdisks {
                    if self.patch_ramdisk(ramdisk)? {
                        patched = true;
                        break;
                    }
                }

                patched
            }
        };

        // Fail hard if otacerts does not exist. We don't want to lock the user
        // out of future updates if the OTA certificate mechanism has changed.
        if !patched_any {
            return Err(Error::Validation(format!(
                "No ramdisk contains {}",
                EscapedString::new(Self::OTACERTS_PATH),
            )));
        }

        Ok(())
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
    warning_fn: Box<dyn Fn(&str) + Send>,
}

impl PrepatchedImagePatcher {
    const MIN_LEVEL: u8 = 0;
    const MAX_LEVEL: u8 = 2;

    // We compile without Unicode support so we have to use [0-9] instead of \d.
    const VERSION_REGEX: &str = r"Linux version ([0-9]+\.[0-9]+).[0-9]+-(android[0-9]+)-([0-9]+)-";

    pub fn new(
        prepatched: &Path,
        fatal_level: u8,
        warning_fn: impl Fn(&str) + Send + 'static,
    ) -> Self {
        Self {
            prepatched: prepatched.to_owned(),
            fatal_level,
            warning_fn: Box::new(warning_fn),
        }
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

impl BootImagePatcher for PrepatchedImagePatcher {
    fn patch(&self, boot_image: &mut BootImage, _cancel_signal: &Arc<AtomicBool>) -> Result<()> {
        let prepatched_image = {
            let raw_reader = File::open(&self.prepatched)?;
            BootImage::from_reader(BufReader::new(raw_reader))?
        };

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

            (self.warning_fn)(&msg);
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

/// Run each patcher against the boot image with the vbmeta footer stripped off
/// and then re-sign the image.
pub fn patch_boot(
    mut reader: impl Read + Seek,
    writer: impl Write + Seek,
    key: &RsaPrivateKey,
    patchers: &[Box<dyn BootImagePatcher + Send>],
    cancel_signal: &Arc<AtomicBool>,
) -> Result<()> {
    let (mut header, footer, image_size) = avb::load_image(&mut reader)?;
    let Some(footer) = footer else {
        return Err(Error::NoFooter);
    };

    let section_reader = SectionReader::new(reader, 0, footer.original_image_size)?;
    let mut boot_image = BootImage::from_reader(section_reader)?;

    for patcher in patchers {
        patcher.patch(&mut boot_image, cancel_signal)?;
    }

    let mut descriptor_iter = header.descriptors.iter_mut().filter_map(|d| {
        if let Descriptor::Hash(h) = d {
            Some(h)
        } else {
            None
        }
    });

    let Some(descriptor) = descriptor_iter.next() else {
        return Err(Error::NoHashDescriptor);
    };

    // Write new boot image. We reuse the existing salt for the digest.
    let mut context = Context::new(&ring::digest::SHA256);
    context.update(&descriptor.salt);
    let mut hashing_writer = HashingWriter::new(writer, context);
    boot_image.to_writer(&mut hashing_writer)?;
    let (mut writer, context) = hashing_writer.finish();

    header.algorithm_type = AlgorithmType::Sha256Rsa4096;

    descriptor.image_size = writer.stream_position()?;
    descriptor.hash_algorithm = "sha256".to_owned();
    descriptor.root_digest = context.finish().as_ref().to_vec();

    if descriptor_iter.next().is_some() {
        return Err(Error::MultipleHashDescriptors);
    }

    if !header.public_key.is_empty() {
        header.sign(key)?;
    }

    avb::write_appended_image(writer, &header, &footer, image_size)?;

    Ok(())
}
