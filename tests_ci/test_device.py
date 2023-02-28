#!/usr/bin/env python3

import argparse
import glob
import hashlib
import os
import sys
import unittest.mock
import urllib

import tomlkit

sys.path.append(os.path.join(sys.path[0], '..'))
import avbroot.main
from avbroot import util
import dummy_image


def test_device(test_file, magisk_file, hashes, workdir, no_test, db,
                device_name):
    output_file = os.path.join(workdir, 'output.zip')
    test_key_prefix = os.path.join(sys.path[0], os.pardir, 'tests', 'keys',
                                   'TEST_KEY_DO_NOT_USE_')

    # We intentionally create a zip file with an invalid CRC for the payload.
    # The CRC of the zip will be checked when EOF is reached.
    # Although we never intentionally read all the way to the end, prefetching of a file
    # might lead to read until EOF and triggering the CRC check, which will fail.
    with unittest.mock.patch('zipfile.ZipExtFile._update_crc',
                             lambda _, __: None):
        avbroot.main.main([
            'patch',
            '--input',
            test_file,
            '--output',
            output_file,
            '--magisk',
            magisk_file,
            '--privkey-avb',
            test_key_prefix + 'avb.key',
            '--privkey-ota',
            test_key_prefix + 'ota.key',
            '--cert-ota',
            test_key_prefix + 'ota.crt',
        ])

    avbroot.main.main([
        'extract',
        '--input',
        output_file,
        '--directory',
        workdir,
    ])

    if hashes is None:
        with open(db, 'r') as f:
            toml_db = tomlkit.load(f)

        new_hashes = tomlkit.table()
        with open(os.path.join(workdir, 'output.zip'), 'rb') as f:
            new_hashes.update(
                {'output.zip': util.hash_file(f, hashlib.md5()).hexdigest()})

        for i in sorted(glob.glob('*.img', root_dir=workdir)):
            with open(os.path.join(workdir, i), 'rb') as f:
                new_hashes.update(
                    {i: util.hash_file(f, hashlib.md5()).hexdigest()})

        toml_db.get('device').get(device_name).append('hashes', new_hashes)

        with open(db, 'w') as f:
            tomlkit.dump(toml_db, f)

        print(f'{device_name} hashes are added to the database')

        hashes = dict(new_hashes)

    if not no_test:
        for filename, md5_hash in hashes.items():
            with open(os.path.join(workdir, filename), 'rb') as f:
                assert util.hash_file(f, hashlib.md5()).hexdigest() == md5_hash
            os.remove(os.path.join(workdir, filename))


def download_magisk(f_out, url, checksum):
    sha256_hash = hashlib.sha256()

    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as d:
        size = d.info()['Content-Length']
        util.copyfileobj_n(d, f_out, int(size), hasher=sha256_hash)

    if sha256_hash.hexdigest() != checksum:
        raise Exception("ERROR: Checksum of Magisk doesn't match")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d',
        '--device',
        action='append',
        required=True,
        help='Device name to test against',
    )
    parser.add_argument('--db', required=True, help='Path to database file')
    parser.add_argument('--no-test',
                        action='store_true',
                        help="Don't test and clean in final steps")
    parser.add_argument('--workdir',
                        required=True,
                        help='Path to directory which contains images')

    return parser.parse_args()


def test_main():
    args = parse_args()

    with open(args.db, 'r') as f:
        database = tomlkit.load(f)

    magisk_file = os.path.join(args.workdir, database['magisk']['filename'])

    if not os.path.isfile(magisk_file):
        with open(magisk_file, 'wb') as f_out:
            print('Downloading Magisk...')
            download_magisk(f_out, database['magisk']['url'],
                            database['magisk']['sha256'])

    for device_name in args.device:
        device_entry = database.get('device').get(device_name)

        if not device_entry:
            raise Exception(f'Device {device_name} not found in database')

        test_file = os.path.join(args.workdir, device_entry['filename'])

        if not os.path.isfile(test_file):
            print(f'No input file found for {device_name}. Downloading now...')

            dummy_image.main([
                'download',
                '--no-compress',
                '--db',
                args.db,
                '--output',
                test_file,
                device_name,
            ])

        test_device(
            test_file,
            magisk_file,
            device_entry.get('hashes'),
            args.workdir,
            args.no_test,
            args.db,
            device_name,
        )


if __name__ == '__main__':
    test_main()
