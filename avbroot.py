#!/usr/bin/env python3

from avbroot import external

import argparse
import os
import shutil
import tempfile
import zipfile

import avbtool

from avbroot import boot
from avbroot import openssl
from avbroot import ota
from avbroot import util
from avbroot import vbmeta


IMAGES = ('boot', 'vendor_boot', 'vbmeta')
PATH_METADATA_PB = 'META-INF/com/android/metadata.pb'
PATH_PAYLOAD = 'payload.bin'
PATH_PROPERTIES = 'payload_properties.txt'
SKIP_PATHS = (
    PATH_METADATA_PB,
    'META-INF/com/android/metadata',
    'META-INF/com/android/otacert',
)


def print_status(*args, **kwargs):
    print('\x1b[1m*****', *args, '*****\x1b[0m', **kwargs)


def patch_ota_payload(f_in, f_out, file_size, magisk, privkey_avb, privkey_ota,
                      cert_ota):
    with tempfile.TemporaryDirectory() as temp_dir:
        extract_dir = os.path.join(temp_dir, 'extract')
        patch_dir = os.path.join(temp_dir, 'patch')
        payload_dir = os.path.join(temp_dir, 'payload')
        os.mkdir(extract_dir)
        os.mkdir(patch_dir)
        os.mkdir(payload_dir)

        version, manifest, blob_offset = ota.parse_payload(f_in)

        print_status('Extracting', ', '.join(IMAGES), 'from the payload')
        ota.extract_images(f_in, manifest, blob_offset, extract_dir, IMAGES)

        avb = avbtool.Avb()

        print_status('Patching boot image for Magisk root')
        boot.patch_boot(
            avb,
            os.path.join(extract_dir, 'boot.img'),
            os.path.join(patch_dir, 'boot.img'),
            privkey_avb,
            True,
            (
                boot.MagiskRootPatch(magisk),
            ),
        )

        print_status('Patching vendor_boot image to replace OTA certs')
        boot.patch_boot(
            avb,
            os.path.join(extract_dir, 'vendor_boot.img'),
            os.path.join(patch_dir, 'vendor_boot.img'),
            privkey_avb,
            True,
            (
                boot.OtaCertPatch(magisk, cert_ota),
            ),
        )

        print_status('Building new root vbmeta image')
        vbmeta.patch_vbmeta_root(
            avb,
            [os.path.join(patch_dir, f'{i}.img')
                for i in IMAGES if i != 'vbmeta'],
            os.path.join(extract_dir, 'vbmeta.img'),
            os.path.join(patch_dir, 'vbmeta.img'),
            privkey_avb,
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
            {i: os.path.join(patch_dir, f'{i}.img') for i in IMAGES},
            file_size,
            privkey_ota,
        )


def patch_ota_zip(f_zip_in, f_zip_out, magisk, privkey_avb, privkey_ota,
                  cert_ota):
    with (
        zipfile.ZipFile(f_zip_in, 'r') as z_in,
        zipfile.ZipFile(f_zip_out, 'w') as z_out,
    ):
        infolist = z_in.infolist()
        missing = {PATH_METADATA_PB, PATH_PAYLOAD, PATH_PROPERTIES}
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
        metadata = None

        for info in z_in.infolist():
            # The existing metadata is needed to generate a new signed zip
            if info.filename == PATH_METADATA_PB:
                with z_in.open(info, 'r') as f_in:
                    metadata = f_in.read()

            # Skip files that are created during zip signing
            if info.filename in SKIP_PATHS:
                print_status('Skipping', info.filename)
                continue

            # Copy other files, patching if needed
            with (
                z_in.open(info, 'r') as f_in,
                z_out.open(info, 'w') as f_out,
            ):
                if info.filename == PATH_PAYLOAD:
                    print_status('Patching', info.filename)

                    found_payload = True

                    if info.compress_type != zipfile.ZIP_STORED:
                        raise Exception(f'{info.filename} is not stored uncompressed')

                    properties = patch_ota_payload(
                        f_in,
                        f_out,
                        info.file_size,
                        magisk,
                        privkey_avb,
                        privkey_ota,
                        cert_ota,
                    )

                elif info.filename == PATH_PROPERTIES:
                    print_status('Patching', info.filename)

                    if info.compress_type != zipfile.ZIP_STORED:
                        raise Exception(f'{info.filename} is not stored uncompressed')

                    f_out.write(properties)

                else:
                    print_status('Copying', info.filename)

                    shutil.copyfileobj(f_in, f_out)

        return metadata


def patch_subcommand(args):
    output = args.output
    if output is None:
        output = args.input + '.patched'

    # Decrypt keys to temp directory in RAM
    with tempfile.TemporaryDirectory(dir='/dev/shm') as key_dir:
        print_status('Decrypting keys to RAM-based temporary directory')

        # avbtool requires a PEM-encoded private key
        dec_privkey_avb = os.path.join(key_dir, 'avb.key')
        openssl.decrypt_key(args.privkey_avb, dec_privkey_avb)

        # AOSP's OTA utils require a DER-encoded private key with the `.pk8`
        # extension and a PEM-encoded certificate with the `.x509.pem` extension
        dec_privkey_ota = os.path.join(key_dir, 'ota.pk8')
        key_prefix_ota = dec_privkey_ota[:-4]
        openssl.decrypt_key(args.privkey_ota, dec_privkey_ota, out_form='DER')

        cert_ota = os.path.join(key_dir, 'ota.x509.pem')
        shutil.copyfile(args.cert_ota, cert_ota)

        # Ensure that the certificate matches the private key
        if not openssl.cert_matches_key(cert_ota, dec_privkey_ota):
            raise Exception('OTA certificate does not match private key')

        with tempfile.NamedTemporaryFile() as temp_unsigned:
            metadata = patch_ota_zip(
                args.input,
                temp_unsigned,
                args.magisk,
                dec_privkey_avb,
                dec_privkey_ota,
                cert_ota,
            )

            print_status('Signing OTA zip')
            with util.open_output_file(output) as temp_signed:
                ota.sign_zip(
                    temp_unsigned.name,
                    temp_signed.name,
                    key_prefix_ota,
                    metadata,
                )


def extract_subcommand(args):
    with zipfile.ZipFile(args.input, 'r') as z:
        info = z.getinfo(PATH_PAYLOAD)

        with z.open(info, 'r') as f:
            _, manifest, blob_offset = ota.parse_payload(f)

            print_status('Extracting', ', '.join(IMAGES), 'from the payload')
            ota.extract_images(f, manifest, blob_offset, args.directory, IMAGES)


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
