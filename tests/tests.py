#!/usr/bin/env python3

import argparse
import configparser
import hashlib
import os
import subprocess
import sys

sys.path.append(os.path.join(sys.path[0], '..'))
from avbroot import main
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
        patched_file = image_file + '.patched'

        print('Patching', image_file)

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

        print('Verifying checksum of', patched_file)

        verify_checksum(patched_file, image['sha256_patched'])


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--aria2c-arg', default=[], action='append',
                        help='Argument to pass to aria2c')
    parser.add_argument('-d', '--device', action='append',
                        help='Device image to test against')
    parser.add_argument('--revalidate', action='store_true',
                        help='Revalidate checksums for downloaded OTAs')

    return parser.parse_args()


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
