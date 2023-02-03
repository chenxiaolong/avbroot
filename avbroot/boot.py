import os
import shutil
import subprocess
import struct
import tempfile
import zipfile

import avbtool

from . import util
from . import vbmeta


class BootImagePatch:
    def __init__(self, magisk_apk, to_extract):
        self.magisk_apk = magisk_apk
        self.to_extract = to_extract

    def __call__(self, image_file):
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(self.magisk_apk, 'r') as zip:
                for source, extract_info in self.to_extract.items():
                    try:
                        info = zip.getinfo(source)
                    except KeyError:
                        if extract_info.get('optional', False):
                            continue
                        raise

                    info.filename = extract_info['dest']
                    zip.extract(info, path=temp_dir)

            self.patch(image_file, temp_dir)

    def patch(self, image_file, temp_dir):
        raise NotImplementedError()


class MagiskRootPatch(BootImagePatch):
    '''
    Root the boot image using Magisk's patch script.
    '''

    EXTRACT_MAP = {
        'assets/boot_patch.sh': {'dest': 'boot_patch.sh'},
        'assets/stub.apk': {
            'dest': 'stub.apk',
            # Only exists after the Magisk commit:
            # ad0e6511e11ebec65aa9b5b916e1397342850319
            'optional': True,
        },
        'assets/util_functions.sh': {'dest': 'util_functions.sh'},
        'lib/arm64-v8a/libmagisk64.so': {'dest': 'magisk64'},
        'lib/arm64-v8a/libmagiskinit.so': {'dest': 'magiskinit'},
        'lib/armeabi-v7a/libmagisk32.so': {'dest': 'magisk32'},
        # The x86 binary is used because the x86_64 binary breaks if the PID
        # exceeds 65535. This is due to the pthread_mutex implementation in the
        # version of bionic libc compiled into magiskboot, which uses the
        # thread ID as a 16-bit integer. On systems with a large PID limit,
        # like Fedora 37, which sets `kernel.pid_max = 4194304`, the x86_64
        # binary is almost never able to run successfully. In the future, if
        # there's a need to work around this, we can unshare() a new PID
        # namespace to get small PIDs.
        'lib/x86/libmagiskboot.so': {'dest': 'magiskboot'},
    }

    def __init__(self, magisk_apk):
        super().__init__(magisk_apk, self.EXTRACT_MAP)

    def patch(self, image_file, temp_dir):
        subprocess.check_call(
            ['sh', './boot_patch.sh', image_file],
            cwd=temp_dir,
            env={
                'BOOTMODE': 'true',
                'KEEPVERITY': 'true',
                'KEEPFORCEENCRYPT': 'true',
            },
        )

        shutil.copyfile(os.path.join(temp_dir, 'new-boot.img'), image_file)


class OtaCertPatch(BootImagePatch):
    '''
    Replace the OTA certificates in the vendor_boot image with the custom OTA
    signing certificate.
    '''

    EXTRACT_MAP = {
        'lib/x86/libmagiskboot.so': {'dest': 'magiskboot'},
    }

    def __init__(self, magisk_apk, cert_ota):
        super().__init__(magisk_apk, self.EXTRACT_MAP)
        self.cert_ota = cert_ota

    def _read_header_version(self, image_file):
        with open(image_file, 'rb') as f:
            magic = f.read(8)

            if magic == b'ANDROID!':
                f.seek(0x28)
            elif magic == b'VNDRBOOT':
                # Version is immediately after magic
                pass
            else:
                raise Exception(b'Invalid magic: {magic}')

            return struct.unpack('I', f.read(4))[0]

    def patch(self, image_file, temp_dir):
        def run(*args):
            subprocess.check_call(['./magiskboot', *args], cwd=temp_dir)

        os.chmod(os.path.join(temp_dir, 'magiskboot'), 0o755)

        # Unpack the boot image
        run('unpack', image_file)

        # magiskboot currently does not automatically decompress v4 vendor boot
        # ramdisks as there may be more than one. This is not the case for
        # Android 13 on the Pixel 6 Pro.
        ramdisk_file = 'ramdisk.cpio'
        header_version = self._read_header_version(image_file)
        if header_version == 4:
            ramdisk_file = 'decompressed.cpio'
            run('decompress', 'ramdisk.cpio', ramdisk_file)

        # Fail hard if otacerts does not exist. We don't want to lock the user
        # out of future updates if the OTA certificate mechanism has changed.
        run(
            'cpio', ramdisk_file,
            'exists system/etc/security/otacerts.zip',
        )

        # Create new otacerts archive. The old certs are ignored since flashing
        # a stock OTA will render the device unbootable.
        with zipfile.ZipFile(os.path.join(temp_dir, 'otacerts.zip'), 'w') as z:
            # Construct our own timestamp so the archive is reproducible
            info = zipfile.ZipInfo('ota.x509.pem')
            with z.open(info, 'w') as f_out:
                with open(self.cert_ota, 'rb') as f_in:
                    shutil.copyfileobj(f_in, f_out)

        # Repack ramdisk
        run(
            'cpio', ramdisk_file,
            'rm system/etc/security/otacerts.zip',
            'add 644 system/etc/security/otacerts.zip otacerts.zip',
        )

        # Recompress ramdisk
        if header_version == 4:
            run('compress=lz4_legacy', ramdisk_file, 'ramdisk.cpio')

        # Repack image
        run('repack', image_file)

        shutil.copyfile(os.path.join(temp_dir, 'new-boot.img'), image_file)


def patch_boot(avb, input_path, output_path, key, only_if_previously_signed,
               patch_funcs):
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
                raise Exception(f'Expected only one hash descriptor')
            hash = d
        else:
            new_descriptors.append(d)

    if hash is None:
        raise Exception(f'No hash descriptor found')

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
        with vbmeta.smuggle_descriptors():
            avb.add_hash_footer(
                image_filename = f.name,
                partition_size = image_size,
                dynamic_partition_size = False,
                partition_name = hash.partition_name,
                hash_algorithm = hash.hash_algorithm,
                salt = hash.salt.hex(),
                chain_partitions = None,
                algorithm_name = algorithm_name,
                key_path = key,
                public_key_metadata_path = None,
                rollback_index = header.rollback_index,
                flags = header.flags,
                rollback_index_location = header.rollback_index_location,
                props = None,
                props_from_file = None,
                kernel_cmdlines = new_descriptors,
                setup_rootfs_from_kernel = None,
                include_descriptors_from_image = None,
                calc_max_image_size = False,
                signing_helper = None,
                signing_helper_with_files = None,
                release_string = header.release_string,
                append_to_release_string = None,
                output_vbmeta_image = None,
                do_not_append_vbmeta_image = False,
                print_required_libavb_version = False,
                use_persistent_digest = False,
                do_not_use_ab = False,
            )
