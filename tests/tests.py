#!/usr/bin/env python3

import argparse
import configparser
import hashlib
import os
import subprocess
import sys
import tempfile
import zipfile

sys.path.append(os.path.join(sys.path[0], '..'))
from avbroot import main
from avbroot import ota
from avbroot import util


def url_filename(url):
    return url.split('/')[-1]


def device_configs(args, config, filter=True):
    for section in config.sections():
        assert section == os.path.basename(section)

        if section.startswith('device.'):
            name = section.removeprefix('device.')
            if filter and args.device and name not in args.device:
                continue

            yield name, config[section]


def verify_checksum(path, sha256_hex):
    with open(path, 'rb') as f:
        hasher = util.hash_file(f, hashlib.sha256())

    if hasher.digest() != bytes.fromhex(sha256_hex):
        raise Exception(f'{path}: expected sha256 {sha256_hex}, '
                        f'but have {hasher.hexdigest()}')


def download(directory, url, sha256_hex, revalidate=False, extra_args=[]):
    path = os.path.join(directory, url_filename(url))

    if os.path.exists(path) and not os.path.exists(path + '.aria2'):
        if revalidate:
            print('Verifying checksum of', path)

            verify_checksum(path, sha256_hex)
    else:
        print('Downloading', url, 'to', path)

        subprocess.check_call([
            'aria2c',
            *extra_args,
            '--auto-file-renaming=false',
            f'--checksum=SHA-256={sha256_hex}',
            f'--dir={os.path.dirname(path)}',
            f'--out={os.path.basename(path)}',
            url,
        ])

    return path


def get_boot_partition(zip):
    with zipfile.ZipFile(zip, 'r') as z:
        info = z.getinfo(main.PATH_PAYLOAD)

        with z.open(info, 'r') as f:
            _, manifest, blob_offset = ota.parse_payload(f)
            images = main.get_partitions_by_type(manifest)
            return images['@gki_ramdisk']


def run_tests(args, config, files_dir):
    magisk_file = download(
        os.path.join(files_dir, 'magisk'),
        config['magisk']['url'],
        config['magisk']['sha256'],
        revalidate=args.revalidate,
        extra_args=args.aria2c_arg,
    )

    for device, image in device_configs(args, config):
        image_dir = os.path.join(files_dir, device)
        os.makedirs(image_dir, exist_ok=True)

        image_file = download(
            image_dir,
            image['url'],
            image['sha256'],
            revalidate=args.revalidate,
            extra_args=args.aria2c_arg,
        )
        patched_file = image_file + args.output_file_suffix

        if args.download_only:
            continue

        print('Patching (--magisk)', image_file)

        test_key_prefix = os.path.join(
            sys.path[0], 'keys', 'TEST_KEY_DO_NOT_USE_')

        main.main([
            'patch',
            '--privkey-avb', test_key_prefix + 'avb.key',
            '--privkey-ota', test_key_prefix + 'ota.key',
            '--cert-ota', test_key_prefix + 'ota.crt',
            '--magisk', magisk_file,
            '--input', image_file,
            '--output', patched_file,
        ])
        inode_1 = os.stat(patched_file).st_ino

        print('Verifying checksum of', patched_file)

        verify_checksum(patched_file, image['sha256_patched'])

        with tempfile.TemporaryDirectory() as temp_dir:
            print('Extracting images from', patched_file)

            main.main([
                'extract',
                '--input', patched_file,
                '--directory', temp_dir,
            ])

            boot_partition = get_boot_partition(patched_file)

            # Patch again, but this time, use the previously patched boot image
            # instead of apply the Magisk patch

            print('Patching (--prepatched)', image_file)

            main.main([
                'patch',
                '--privkey-avb', test_key_prefix + 'avb.key',
                '--privkey-ota', test_key_prefix + 'ota.key',
                '--cert-ota', test_key_prefix + 'ota.crt',
                '--prepatched', os.path.join(temp_dir, f'{boot_partition}.img'),
                '--input', image_file,
                '--output', patched_file,
            ])
            inode_2 = os.stat(patched_file).st_ino

            # Sanity check to make sure that the output file was rewritten
            assert inode_1 != inode_2

        print('Verifying checksum of', patched_file)

        verify_checksum(patched_file, image['sha256_patched'])

        if args.delete_on_success:
            os.unlink(patched_file)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--aria2c-arg', default=[], action='append',
                        help='Argument to pass to aria2c')
    parser.add_argument('-d', '--device', action='append',
                        help='Device image to test against')
    parser.add_argument('--delete-on-success', action='store_true',
                        help='Delete output files if patching is successful')
    parser.add_argument('--download-only', action='store_true',
                        help='Skip patching and download OTA images only')
    parser.add_argument('--output-file-suffix', default='.patched',
                        help='Suffix for patched output files')
    parser.add_argument('--revalidate', action='store_true',
                        help='Revalidate checksums for downloaded OTAs')

    args = parser.parse_args()

    if not args.output_file_suffix:
        parser.error('--output-file-suffix cannot be empty')

    return args


def test_main():
    args = parse_args()

    config_file = os.path.join(sys.path[0], 'tests.conf')
    config = configparser.ConfigParser()
    config.read(config_file)

    if args.device:
        devices = set(d for d, _ in device_configs(args, config, filter=False))
        invalid = set(args.device) - devices
        if invalid:
            raise ValueError(f'Invalid devices: {sorted(invalid)}')

    files_dir = os.path.join(sys.path[0], 'files')

    run_tests(args, config, files_dir)


if __name__ == '__main__':
    test_main()
