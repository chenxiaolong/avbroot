import hashlib
import io
import lzma
import shutil
import zipfile

import avbtool

from . import openssl
from . import util
from . import vbmeta
from .formats import bootimage
from .formats import compression
from .formats import cpio


def _load_ramdisk(ramdisk):
    with (
        io.BytesIO(ramdisk) as f_raw,
        compression.CompressedFile(f_raw, 'rb') as f,
    ):
        return cpio.load(f.fp), f.format


def _save_ramdisk(entries, format):
    with io.BytesIO() as f_raw:
        with compression.CompressedFile(f_raw, 'wb', format=format) as f:
            cpio.save(f.fp, entries)

        return f_raw.getvalue()


class BootImagePatch:
    def __call__(self, image_file):
        # Load the boot image
        with open(image_file, 'r+b') as f:
            boot_image = bootimage.load_autodetect(f)

            self.patch(image_file, boot_image)

            f.seek(0)
            f.truncate(0)

            boot_image.generate(f)

    def patch(self, image_file, boot_image):
        raise NotImplementedError()


class MagiskRootPatch(BootImagePatch):
    '''
    Root the boot image with Magisk.
    '''

    def __init__(self, magisk_apk):
        self.magisk_apk = magisk_apk

    def patch(self, image_file, boot_image):
        with zipfile.ZipFile(self.magisk_apk, 'r') as zip:
            self._patch(image_file, boot_image, zip)

    def _patch(self, image_file, boot_image, zip):
        if len(boot_image.ramdisks) > 1:
            raise Exception('Boot image is not expected to have '
                            f'{len(boot_image.ramdisks)} ramdisks')

        # Magisk saves the original SHA1 digest in its config file
        with open(image_file, 'rb') as f:
            hasher = util.hash_file(f, hashlib.sha1())

        # Load the existing ramdisk if it exists. If it doesn't, we have to
        # generate one from scratch
        if boot_image.ramdisks:
            entries, ramdisk_format = _load_ramdisk(boot_image.ramdisks[0])
        else:
            entries, ramdisk_format = [], compression.Format.LZ4_LEGACY

        old_entries = entries.copy()

        # Create magisk directory structure
        for path, perms in (
            (b'overlay.d', 0o750),
            (b'overlay.d/sbin', 0o750),
        ):
            entries.append(cpio.CpioEntryNew.new_directory(path, perms=perms))

        # Delete the original init
        if boot_image.ramdisks:
            entries = [e for e in entries if e.name != b'init']

        # Add magiskinit
        with zip.open('lib/arm64-v8a/libmagiskinit.so', 'r') as f:
            entries.append(cpio.CpioEntryNew.new_file(
                b'init', perms=0o750, data=f.read()))

        # Add xz-compressed magisk32 and magisk64
        xz_files = {
            'lib/armeabi-v7a/libmagisk32.so': b'magisk32.xz',
            'lib/arm64-v8a/libmagisk64.so': b'magisk64.xz',
        }

        # Add stub apk, which only exists after the Magisk commit:
        # ad0e6511e11ebec65aa9b5b916e1397342850319
        if 'assets/stub.apk' in zip.namelist():
            xz_files['assets/stub.apk'] = b'stub.xz'

        for source, target in xz_files.items():
            with (
                zip.open(source, 'r') as f_in,
                io.BytesIO() as f_out_raw,
            ):
                with lzma.open(f_out_raw, 'wb', preset=9,
                               check=lzma.CHECK_CRC32) as f_out:
                    shutil.copyfileobj(f_in, f_out)

                entries.append(cpio.CpioEntryNew.new_file(
                    b'overlay.d/sbin/' + target, perms=0o644,
                    data=f_out_raw.getvalue()))

        # Create magisk .backup directory structure
        self._apply_magisk_backup(old_entries, entries)

        # Create magisk config
        magisk_config = \
            b'KEEPVERITY=true\n' \
            b'KEEPFORCEENCRYPT=true\n' \
            b'PATCHVBMETAFLAG=false\n' \
            b'RECOVERYMODE=false\n' \
            b'SHA1=%s\n' % hasher.hexdigest().encode('ascii')
        entries.append(cpio.CpioEntryNew.new_file(
            b'.backup/.magisk', perms=0o000, data=magisk_config))

        # Repack ramdisk
        new_ramdisk = _save_ramdisk(entries, ramdisk_format)
        if boot_image.ramdisks:
            boot_image.ramdisks[0] = new_ramdisk
        else:
            boot_image.ramdisks.append(new_ramdisk)

    @staticmethod
    def _apply_magisk_backup(old_entries, new_entries):
        '''
        Compare old and new ramdisk entry lists, creating the Magisk `.backup/`
        directory structure. `.backup/.rmlist` will contain a sorted list of
        NULL-terminated strings, listing which files were newly added or
        changed. The old entries for changed files will be added to the new
        entries as `.backup/<path>`.

        Both lists and entries within the lists may be mutated.
        '''

        old_by_name = {e.name: e for e in old_entries}
        new_by_name = {e.name: e for e in new_entries}

        added = new_by_name.keys() - old_by_name.keys()
        deleted = old_by_name.keys() - new_by_name.keys()
        changed = set(n for n in old_by_name.keys() & new_by_name.keys()
                      if old_by_name[n].content != new_by_name[n].content)

        new_entries.append(cpio.CpioEntryNew.new_directory(
            b'.backup', perms=0o000))

        for name in deleted | changed:
            entry = old_by_name[name]
            entry.name = b'.backup/' + entry.name
            new_entries.append(entry)

        rmlist_data = b''.join(n + b'\0' for n in sorted(added))
        new_entries.append(cpio.CpioEntryNew.new_file(
            b'.backup/.rmlist', perms=0o000, data=rmlist_data))


class OtaCertPatch(BootImagePatch):
    '''
    Replace the OTA certificates in the vendor_boot image with the custom OTA
    signing certificate.
    '''

    OTACERTS_PATH = b'system/etc/security/otacerts.zip'

    def __init__(self, cert_ota):
        self.cert_ota = cert_ota

    def patch(self, image_file, boot_image):
        found_otacerts = False

        # Check each ramdisk
        for i, ramdisk in enumerate(boot_image.ramdisks):
            entries, ramdisk_format = _load_ramdisk(ramdisk)

            # Fail hard if otacerts does not exist. We don't want to lock the
            # user out of future updates if the OTA certificate mechanism has
            # changed.
            otacerts = next((e for e in entries if e.name ==
                             self.OTACERTS_PATH), None)
            if otacerts:
                found_otacerts = True
            else:
                continue

            # Create new otacerts archive. The old certs are ignored since
            # flashing a stock OTA will render the device unbootable.
            with io.BytesIO() as f_zip:
                with zipfile.ZipFile(f_zip, 'w') as z:
                    # Use zeroed-out metadata to ensure the archive is bit for
                    # bit reproducible across runs.
                    info = zipfile.ZipInfo('ota.x509.pem')
                    with (
                        z.open(info, 'w') as f_out,
                        open(self.cert_ota, 'rb') as f_in,
                    ):
                        shutil.copyfileobj(f_in, f_out)

                otacerts.content = f_zip.getvalue()

            # Repack ramdisk
            boot_image.ramdisks[i] = _save_ramdisk(entries, ramdisk_format)

        if not found_otacerts:
            raise Exception(f'{self.OTACERTS_PATH} not found in ramdisk')


def patch_boot(avb, input_path, output_path, key, passphrase,
               only_if_previously_signed, patch_funcs):
    '''
    Call each function in patch_funcs against a boot image with vbmeta stripped
    out and then resign the image using the provided private key.
    '''

    image = avbtool.ImageHandler(input_path, read_only=True)
    footer, header, descriptors, image_size = avb._parse_image(image)

    have_key_old = not not header.public_key_size
    if not have_key_old and only_if_previously_signed:
        key = None

    have_key_new = not not key

    if have_key_old != have_key_new:
        raise Exception('Key presence does not match: %s (old) != %s (new)' %
                        (have_key_old, have_key_new))

    hash = None
    new_descriptors = []

    for d in descriptors:
        if isinstance(d, avbtool.AvbHashDescriptor):
            if hash is not None:
                raise Exception('Expected only one hash descriptor')
            hash = d
        else:
            new_descriptors.append(d)

    if hash is None:
        raise Exception('No hash descriptor found')

    algorithm_name = avbtool.lookup_algorithm_by_type(header.algorithm_type)[0]

    # Pixel 7's init_boot image is originally signed by a 2048-bit RSA key, but
    # avbroot expects RSA 4096 keys
    if algorithm_name == 'SHA256_RSA2048':
        algorithm_name = 'SHA256_RSA4096'

    with util.open_output_file(output_path) as f:
        shutil.copyfile(input_path, f.name)

        # Strip the vbmeta footer from the boot image
        avb.erase_footer(f.name, False)

        # Invoke the patching functions
        for patch_func in patch_funcs:
            patch_func(f.name)

        # Sign the new boot image
        with (
            vbmeta.smuggle_descriptors(),
            openssl.inject_passphrase(passphrase),
        ):
            avb.add_hash_footer(
                image_filename=f.name,
                partition_size=image_size,
                dynamic_partition_size=False,
                partition_name=hash.partition_name,
                hash_algorithm=hash.hash_algorithm,
                salt=hash.salt.hex(),
                chain_partitions=None,
                algorithm_name=algorithm_name,
                key_path=key,
                public_key_metadata_path=None,
                rollback_index=header.rollback_index,
                flags=header.flags,
                rollback_index_location=header.rollback_index_location,
                props=None,
                props_from_file=None,
                kernel_cmdlines=new_descriptors,
                setup_rootfs_from_kernel=None,
                include_descriptors_from_image=None,
                calc_max_image_size=False,
                signing_helper=None,
                signing_helper_with_files=None,
                release_string=header.release_string,
                append_to_release_string=None,
                output_vbmeta_image=None,
                do_not_append_vbmeta_image=False,
                print_required_libavb_version=False,
                use_persistent_digest=False,
                do_not_use_ab=False,
            )
