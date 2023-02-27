#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import os
import sys
import urllib
import zipfile

import tomlkit

sys.path.append(os.path.join(sys.path[0], ".."))
import avbroot.main
from avbroot import util
import dummy_image


# We intentionally create a zip file with an invalid CRC for the payload.
# The CRC of the zip will be checked when EOF is reached.
# Although we never intentionally read all the way to the end, prefetching of a file
# might lead to read until EOF and triggering the CRC check, which will fail.
@contextlib.contextmanager
def monkey_patches():
    _update_crc = zipfile.ZipExtFile._update_crc

    def _update_crc_new(self, newdata):
        self._expected_crc = None
        return _update_crc(self, newdata)

    zipfile.ZipExtFile._update_crc = _update_crc_new

    yield

    zipfile.ZipExtFile._update_crc = _update_crc


def test_device(test_file, magisk_file, hashes, workdir, no_test):
    output_file = os.path.join(workdir, "output.zip")
    test_key_prefix = os.path.join(
        sys.path[0], os.pardir, "tests", "keys", "TEST_KEY_DO_NOT_USE_"
    )

    with monkey_patches():
        avbroot.main.main(
            [
                "patch",
                "--input",
                test_file,
                "--output",
                output_file,
                "--magisk",
                magisk_file,
                "--privkey-avb",
                test_key_prefix + "avb.key",
                "--privkey-ota",
                test_key_prefix + "ota.key",
                "--cert-ota",
                test_key_prefix + "ota.crt",
            ]
        )

    avbroot.main.main(
        [
            "extract",
            "--input",
            output_file,
            "--directory",
            workdir,
        ]
    )

    if not no_test:
        os.remove(output_file)

        for filename, md5_hash in hashes.items():
            with open(os.path.join(workdir, filename), "rb") as f:
                assert util.hash_file(f, hashlib.md5()).hexdigest() == md5_hash
            os.remove(os.path.join(workdir, filename))


def download_magisk(f_out, url, checksum):
    sha256_hash = hashlib.sha256()

    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as d:
        size = d.info()["Content-Length"]
        util.copyfileobj_n(d, f_out, int(size), hasher=sha256_hash)

    if sha256_hash.hexdigest() != checksum:
        raise Exception("ERROR: Checksum of Magisk doesn't match")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--device",
        action="append",
        required=True,
        help="Device name to test against",
    )
    parser.add_argument("--db", required=True, help="Path to database file")
    parser.add_argument(
        "--no-test", action="store_true", help="Don't test and clean in final steps"
    )
    parser.add_argument(
        "--workdir", required=True, help="Path to directory which contains images"
    )

    return parser.parse_args()


def test_main():
    args = parse_args()

    with open(args.db, "r") as f:
        database = tomlkit.load(f)

    magisk_file = os.path.join(args.workdir, database["magisk"]["filename"])

    if not os.path.isfile(magisk_file):
        with open(magisk_file, "wb") as f_out:
            print("Downloading Magisk...")
            download_magisk(
                f_out, database["magisk"]["url"], database["magisk"]["sha256"]
            )

    for device_name in args.device:
        device_entry = database.get("device").get(device_name)

        if not device_entry:
            raise Exception(f"Device {device_name} not found in database")

        test_file = os.path.join(args.workdir, device_entry["filename"])

        if not os.path.isfile(test_file):
            print(f"No input file found for {device_name}. Downloading now...")

            dummy_image.main(
                [
                    "download",
                    "--no-compress",
                    "--db",
                    args.db,
                    "--output",
                    test_file,
                    device_name,
                ]
            )

        test_device(
            test_file,
            magisk_file,
            device_entry.get("hashes"),
            args.workdir,
            args.no_test,
        )


if __name__ == "__main__":
    test_main()
