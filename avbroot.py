#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile


@contextlib.contextmanager
def open_output_file(path):
    '''
    Create a temporary file in the same directory as the specified path and
    atomically replace it if the function succeeds.
    '''

    directory = os.path.dirname(path)

    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
        try:
            yield f
            os.rename(f.name, path)
        except:
            os.unlink(f.name)
            raise


class BootImagePatch:
    def __init__(self, magisk_apk, to_extract):
        self.magisk_apk = magisk_apk
        self.to_extract = to_extract

    def __call__(self, image_file):
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(self.magisk_apk, 'r') as zip:
                for source, target in self.to_extract.items():
                    info = zip.getinfo(source)
                    info.filename = target
                    zip.extract(info, path=temp_dir)

            self.patch(image_file, temp_dir)

    def patch(self, image_file, temp_dir):
        raise NotImplementedError()


class MagiskRootPatch(BootImagePatch):
    EXTRACT_MAP = {
        'assets/boot_patch.sh': 'boot_patch.sh',
        'assets/util_functions.sh': 'util_functions.sh',
        'lib/arm64-v8a/libmagisk64.so': 'magisk64',
        'lib/arm64-v8a/libmagiskinit.so': 'magiskinit',
        'lib/armeabi-v7a/libmagisk32.so': 'magisk32',
        'lib/x86/libmagiskboot.so': 'magiskboot',
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


class FastbootdPatch(BootImagePatch):
    EXTRACT_MAP = {
        'lib/x86/libmagiskboot.so': 'magiskboot',
    }
    BL_PROP_ORIG = b'ro.boot.verifiedbootstate'
    BL_PROP_NEW = b'ro.fake.verifiedbootstate'
    BL_PROP_VALUE = b'orange'

    def __init__(self, magisk_apk):
        super().__init__(magisk_apk, self.EXTRACT_MAP)

    def patch(self, image_file, temp_dir):
        def run(*args):
            subprocess.check_call(['./magiskboot', *args], cwd=temp_dir)

        os.chmod(os.path.join(temp_dir, 'magiskboot'), 0o755)

        # Unpack the boot image
        run('unpack', image_file)

        # magiskboot currently does not automatically decompress v4 vendor boot
        # ramdisks as there may be more than one. This is not the case for
        # Android 13 on the Pixel 6 Pro.
        run('decompress', 'ramdisk.cpio', 'decompressed.cpio')

        # Patch fastbootd to look at a fake bootloader status property
        run(
            'cpio', 'decompressed.cpio',
            'extract system/bin/fastbootd fastbootd',
        )

        with open(os.path.join(temp_dir, 'fastbootd'), 'rb+') as f:
            data = f.read()
            if self.BL_PROP_ORIG not in data:
                raise Exception(f'{self.BL_PROP_ORIG} not found in fastbootd')

            f.seek(0)
            f.write(data.replace(self.BL_PROP_ORIG, self.BL_PROP_NEW))

        # Add fake unlocked bootloader status property
        run('cpio', 'decompressed.cpio', 'extract prop.default prop.default')

        with open(os.path.join(temp_dir, 'prop.default'), 'ab') as f:
            f.write(b'\n')
            f.write(self.BL_PROP_NEW)
            f.write(b'=')
            f.write(self.BL_PROP_VALUE)
            f.write(b'\n')

        # Repack ramdisk
        run(
            'cpio', 'decompressed.cpio',
            'rm prop.default',
            'rm system/bin/fastbootd',
            'add 644 prop.default prop.default',
            'add 755 system/bin/fastbootd fastbootd',
        )

        # Recompress ramdisk
        run('compress=lz4_legacy', 'decompressed.cpio', 'ramdisk.cpio')

        # Repack image
        run('repack', image_file)

        shutil.copyfile(os.path.join(temp_dir, 'new-boot.img'), image_file)


class SmuggledViaKernelCmdlineDescriptor:
    def __init__(self):
        self.kernel_cmdline = None

    def encode(self):
        return self.kernel_cmdline.encode()


@contextlib.contextmanager
def smuggle_descriptors():
    '''
    Smuggle predefined vbmeta descriptors into Avb.make_vbmeta_image via the
    kernel_cmdlines parameter. The make_vbmeta_image function will:

    * loop through kernel_cmdlines
    * create a AvbKernelCmdlineDescriptor instance for each item
    * assign kernel_cmdline to each descriptor instance
    * call encode on each descriptor
    '''

    orig_kernel = avbtool.AvbKernelCmdlineDescriptor

    avbtool.AvbKernelCmdlineDescriptor = SmuggledViaKernelCmdlineDescriptor

    try:
        yield
    finally:
        avbtool.AvbKernelCmdlineDescriptor = orig_kernel


def patch_boot(avb, input_path, output_path, key, patch_funcs):
    '''
    Call each function in patch_funcs against a boot image with vbmeta stripped
    out and then resign the image using the provided private key.
    '''

    image = avbtool.ImageHandler(input_path, read_only=True)
    (footer, header, descriptors, image_size) = avb._parse_image(image)

    have_key_old = not not header.public_key_size
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

    with open_output_file(output_path) as f:
        shutil.copyfile(input_path, f.name)

        # Strip the vbmeta footer from the boot image
        avb.erase_footer(f.name, False)

        # Invoke the patching functions
        for patch_func in patch_funcs:
            patch_func(f.name)

        # Sign the new boot image
        with smuggle_descriptors():
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


def build_descriptor_overrides(avb, paths):
    '''
    Build a set of chain and hash descriptors overrides for the given paths
    based on whether they are signed.
    '''

    # Partition name -> raw public key
    chains = {}
    # Partition name -> hash descriptor
    hashes = {}

    # Construct descriptor overrides
    for path in paths:
        image = avbtool.ImageHandler(path, read_only=True)
        (footer, header, descriptors, image_size) = avb._parse_image(image)

        # Find the partition name in the first hash descriptor
        hash = next(d for d in descriptors
            if isinstance(d, avbtool.AvbHashDescriptor))

        if hash is None:
            raise Exception(f'{path} has no hash descriptor')
        elif hash.partition_name in chains:
            raise Exception(f'Duplicate partition name: {hash.partition_name}')

        if header.public_key_size:
            # vbmeta is signed; use a chain descriptor
            blob = avb._load_vbmeta_blob(image)
            offset = header.SIZE + \
                header.authentication_data_block_size + \
                header.public_key_offset
            chains[hash.partition_name] = \
                blob[offset:offset + header.public_key_size]
        else:
            # vbmeta is unsigned; use a hash descriptor
            hashes[hash.partition_name] = hash

    return (chains, hashes)


def patch_vbmeta_root(avb, boot_path, vendor_boot_path, input_path, output_path,
                      key):
    '''
    Patch the root vbmeta image to reference the newly generated boot and
    vendor_boot images.
    '''

    # Load the original root vbmeta image
    image = avbtool.ImageHandler(input_path, read_only=True)
    (footer, header, descriptors, image_size) = avb._parse_image(image)

    # Build a set of new descriptors in the same order as the original
    # descriptors, except with the boot and vendor_boot descriptors patched to
    # reference the given images
    chains, hashes = build_descriptor_overrides(
        avb, (boot_path, vendor_boot_path))
    new_descriptors = []

    for d in descriptors:
        if isinstance(d, avbtool.AvbChainPartitionDescriptor) and \
                d.partition_name in chains:
            d.public_key = chains.pop(d.partition_name)
        elif isinstance(d, avbtool.AvbHashDescriptor) and \
                d.partition_name in hashes:
            d = hashes.pop(d.partition_name)

        new_descriptors.append(d)

    if chains:
        raise Exception(f'Unused chain overrides: {chains}')
    if hashes:
        raise Exception(f'Unused hash overrides: {hashes}')

    algorithm_name = avbtool.lookup_algorithm_by_type(header.algorithm_type)[0]

    with open_output_file(output_path) as f:
        # Smuggle in the prebuilt descriptors via kernel_cmdlines
        with smuggle_descriptors():
            avb.make_vbmeta_image(
                output = f,
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
                signing_helper = None,
                signing_helper_with_files = None,
                release_string = header.release_string,
                append_to_release_string = False,
                print_required_libavb_version = False,
                padding_size = 0,
            )


def import_source_file(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def parse_args():
    avbtool_default = os.path.join(sys.path[0], 'external', 'avb', 'avbtool.py')

    parser = argparse.ArgumentParser()
    parser.add_argument('--avbtool', default=avbtool_default,
                        help='Path to avbtool')
    parser.add_argument('--magisk', required=True,
                        help='Path to Magisk APK')

    images = ('vbmeta', 'boot', 'vendor_boot')

    for image in images:
        arg_image = image.replace('_', '-')
        parser.add_argument(f'--input-{arg_image}', required=True,
                            help=f'Path to original {image} image')
        parser.add_argument(f'--output-{arg_image}',
                            help=f'Path to new {image} image')
        parser.add_argument(f'--privkey-{arg_image}',
                            help=f'Private key for signing {image} image')

    args = parser.parse_args()

    for image in images:
        arg_input = f'input_{image}'
        arg_output = f'output_{image}'

        if getattr(args, arg_output) is None:
            setattr(args, arg_output, getattr(args, arg_input) + '.patched')

    return args


def main():
    args = parse_args()

    # Dynamically import avbtool without putting the parent directory into the
    # module path
    global avbtool
    avbtool = import_source_file('avbtool', args.avbtool)

    avb = avbtool.Avb()

    patch_boot(
        avb,
        args.input_boot,
        args.output_boot,
        args.privkey_boot,
        (
            MagiskRootPatch(args.magisk),
        ),
    )
    patch_boot(
        avb,
        args.input_vendor_boot,
        args.output_vendor_boot,
        args.privkey_vendor_boot,
        (
            FastbootdPatch(args.magisk),
        ),
    )
    patch_vbmeta_root(
        avb,
        args.output_boot,
        args.output_vendor_boot,
        args.input_vbmeta,
        args.output_vbmeta,
        args.privkey_vbmeta,
    )


if __name__ == '__main__':
    main()
