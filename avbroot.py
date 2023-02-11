#!/usr/bin/env python3

from avbroot import external

import argparse
import os
import shutil
import tempfile
import time
import zipfile

import avbtool

from avbroot import boot
from avbroot import openssl
from avbroot import ota
from avbroot import util
from avbroot import vbmeta


PATH_METADATA = 'META-INF/com/android/metadata'
PATH_METADATA_PB = f'{PATH_METADATA}.pb'
PATH_OTACERT = 'META-INF/com/android/otacert'
PATH_PAYLOAD = 'payload.bin'
PATH_PROPERTIES = 'payload_properties.txt'


def print_status(*args, **kwargs):
    print('\x1b[1m*****', *args, '*****\x1b[0m', **kwargs)


def get_images(manifest):
    boot_image = 'boot'
    otacert_image = None

    for p in manifest.partitions:
        # Devices launching with Android 13 use a GKI init_boot ramdisk
        if p.partition_name == 'init_boot':
            boot_image = p.partition_name
        # OnePlus devices have a recovery image
        elif p.partition_name == 'recovery':
            # If a recovery image exists, it will always contain the OTA certs,
            # even if vendor_boot exists
            otacert_image = p.partition_name
        # Older devices may not have vendor_boot
        elif p.partition_name == 'vendor_boot':
            if otacert_image is None:
                otacert_image = p.partition_name

    images = ['vbmeta', boot_image]

    if otacert_image is not None:
        images.append(otacert_image)
    else:
        otacert_image = boot_image

    return images, boot_image, otacert_image


def patch_ota_payload(f_in, f_out, file_size, magisk, privkey_avb,
                      passphrase_avb, privkey_ota, passphrase_ota, cert_ota):
    with tempfile.TemporaryDirectory() as temp_dir:
        extract_dir = os.path.join(temp_dir, 'extract')
        patch_dir = os.path.join(temp_dir, 'patch')
        payload_dir = os.path.join(temp_dir, 'payload')
        os.mkdir(extract_dir)
        os.mkdir(patch_dir)
        os.mkdir(payload_dir)

        version, manifest, blob_offset = ota.parse_payload(f_in)
        images, boot_image, otacert_image = get_images(manifest)

        print_status('Extracting', ', '.join(images), 'from the payload')
        ota.extract_images(f_in, manifest, blob_offset, extract_dir, images)

        boot_patches = [boot.MagiskRootPatch(magisk)]
        otacert_patches = [boot.OtaCertPatch(cert_ota)]

        if otacert_image == boot_image:
            boot_patches.extend(otacert_patches)
            otacert_patches.clear()

        avb = avbtool.Avb()

        print_status(f'Patching {boot_image} image')
        boot.patch_boot(
            avb,
            os.path.join(extract_dir, f'{boot_image}.img'),
            os.path.join(patch_dir, f'{boot_image}.img'),
            privkey_avb,
            passphrase_avb,
            True,
            boot_patches,
        )

        if otacert_patches:
            print_status(f'Patching {otacert_image} image')
            boot.patch_boot(
                avb,
                os.path.join(extract_dir, f'{otacert_image}.img'),
                os.path.join(patch_dir, f'{otacert_image}.img'),
                privkey_avb,
                passphrase_avb,
                True,
                otacert_patches,
            )

        print_status('Building new root vbmeta image')
        vbmeta.patch_vbmeta_root(
            avb,
            [os.path.join(patch_dir, f'{i}.img')
                for i in images if i != 'vbmeta'],
            os.path.join(extract_dir, 'vbmeta.img'),
            os.path.join(patch_dir, 'vbmeta.img'),
            privkey_avb,
            passphrase_avb,
            manifest.block_size,
        )

        print_status('Updating OTA payload to reference patched images')
        return ota.patch_payload(
            f_in,
            f_out,
            version,
            manifest,
            blob_offset,
            payload_dir,
            {i: os.path.join(patch_dir, f'{i}.img') for i in images},
            file_size,
            privkey_ota,
            passphrase_ota,
        )


def patch_ota_zip(f_zip_in, f_zip_out, magisk, privkey_avb, passphrase_avb,
                  privkey_ota, passphrase_ota, cert_ota):
    with (
        zipfile.ZipFile(f_zip_in, 'r') as z_in,
        zipfile.ZipFile(f_zip_out, 'w') as z_out,
    ):
        infolist = z_in.infolist()
        missing = {
            PATH_METADATA,
            PATH_METADATA_PB,
            PATH_OTACERT,
            PATH_PAYLOAD,
            PATH_PROPERTIES,
        }
        i_payload = -1
        i_properties = -1

        for i, info in enumerate(infolist):
            if info.filename in missing:
                missing.remove(info.filename)

            if info.filename == PATH_PAYLOAD:
                i_payload = i
            elif info.filename == PATH_PROPERTIES:
                i_properties = i

            if not missing and i_payload >= 0 and i_properties >= 0:
                break

        if missing:
            raise Exception(f'Missing files in zip: {missing}')

        # Ensure payload is processed before properties
        if i_payload > i_properties:
            infolist[i_payload], infolist[i_properties] = \
                infolist[i_properties], infolist[i_payload]

        properties = None
        metadata_info = None
        metadata_pb_info = None
        metadata_pb_raw = None

        for info in infolist:
            # Ignore because the plain-text legacy metadata file is regenerated
            # from the new metadata
            if info.filename == PATH_METADATA:
                metadata_info = info
                continue

            # The existing metadata is needed to generate a new signed zip
            elif info.filename == PATH_METADATA_PB:
                metadata_pb_info = info

                with z_in.open(info, 'r') as f_in:
                    metadata_pb_raw = f_in.read()

                continue

            # Use the user's OTA certificate
            elif info.filename == PATH_OTACERT:
                print_status('Replacing', info.filename)

                with (
                    open(cert_ota, 'rb') as f_cert,
                    z_out.open(info, 'w') as f_out,
                ):
                    shutil.copyfileobj(f_cert, f_out)

                continue

            # Copy other files, patching if needed
            with (
                z_in.open(info, 'r') as f_in,
                z_out.open(info, 'w') as f_out,
            ):
                if info.filename == PATH_PAYLOAD:
                    print_status('Patching', info.filename)

                    if info.compress_type != zipfile.ZIP_STORED:
                        raise Exception(
                            f'{info.filename} is not stored uncompressed')

                    properties = patch_ota_payload(
                        f_in,
                        f_out,
                        info.file_size,
                        magisk,
                        privkey_avb,
                        passphrase_avb,
                        privkey_ota,
                        passphrase_ota,
                        cert_ota,
                    )

                elif info.filename == PATH_PROPERTIES:
                    print_status('Patching', info.filename)

                    if info.compress_type != zipfile.ZIP_STORED:
                        raise Exception(
                            f'{info.filename} is not stored uncompressed')

                    f_out.write(properties)

                else:
                    print_status('Copying', info.filename)

                    shutil.copyfileobj(f_in, f_out)

        print_status('Generating', PATH_METADATA, 'and', PATH_METADATA_PB)
        metadata = ota.add_metadata(
            z_out,
            metadata_info,
            metadata_pb_info,
            metadata_pb_raw,
        )

        # Signing process needs to capture the zip central directory
        f_zip_out.start_capture()

        return metadata


def patch_subcommand(args):
    output = args.output
    if output is None:
        output = args.input + '.patched'

    # Get passphrases for keys
    passphrase_avb = openssl.prompt_passphrase(args.privkey_avb)
    passphrase_ota = openssl.prompt_passphrase(args.privkey_ota)

    # Ensure that the certificate matches the private key
    if not openssl.cert_matches_key(args.cert_ota, args.privkey_ota,
                                    passphrase_ota):
        raise Exception('OTA certificate does not match private key')

    start = time.perf_counter_ns()

    with util.open_output_file(output) as temp_raw:
        with (
            ota.open_signing_wrapper(temp_raw, args.privkey_ota,
                                     passphrase_ota, args.cert_ota) as temp,
            ota.match_android_zip64_limit(),
        ):
            metadata = patch_ota_zip(
                args.input,
                temp,
                args.magisk,
                args.privkey_avb,
                passphrase_avb,
                args.privkey_ota,
                passphrase_ota,
                args.cert_ota,
            )

        # We do a lot of low-level hackery. Reopen and verify offsets
        print_status('Verifying metadata offsets')
        with zipfile.ZipFile(temp_raw, 'r') as z:
            ota.verify_metadata(z, metadata)

    # Excluding the time it takes for the user to type in the passwords
    elapsed = time.perf_counter_ns() - start
    print_status(f'Completed after {elapsed / 1_000_000_000:.1f}s')


def extract_subcommand(args):
    with zipfile.ZipFile(args.input, 'r') as z:
        info = z.getinfo(PATH_PAYLOAD)

        with z.open(info, 'r') as f:
            _, manifest, blob_offset = ota.parse_payload(f)
            images, _, _ = get_images(manifest)

            print_status('Extracting', ', '.join(images), 'from the payload')
            os.makedirs(args.directory, exist_ok=True)
            ota.extract_images(f, manifest, blob_offset, args.directory,
                               images)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand', required=True,
                                       help='Subcommands')

    patch = subparsers.add_parser('patch', help='Patch a full OTA zip')

    patch.add_argument('--input', required=True,
                       help='Path to original raw payload or OTA zip')
    patch.add_argument('--output',
                       help='Path to new raw payload or OTA zip')
    patch.add_argument('--magisk', required=True,
                       help='Path to Magisk API')
    patch.add_argument('--privkey-avb', required=True,
                       help='Private key for signing root vbmeta image')
    patch.add_argument('--privkey-ota', required=True,
                       help='Private key for signing OTA payload')
    patch.add_argument('--cert-ota', required=True,
                       help='Certificate for OTA payload signing key')

    extract = subparsers.add_parser(
        'extract', help='Extract patched images from a patched OTA zip')

    extract.add_argument('--input', required=True,
                         help='Path to patched OTA zip')
    extract.add_argument('--directory', default='.',
                         help='Output directory for extracted images')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.subcommand == 'patch':
        patch_subcommand(args)
    elif args.subcommand == 'extract':
        extract_subcommand(args)
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
