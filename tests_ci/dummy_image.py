#!/usr/bin/env python3

import argparse
from binascii import crc32
import contextlib
import gzip
import os.path
import sys
import urllib.request
import zipfile

import tomlkit

sys.path.append(os.path.join(sys.path[0], ".."))
from avbroot import external, ota, util
from avbroot.main import PATH_PAYLOAD
import ota_utils

PARTITIONS_TO_ZERO = {"product", "system", "vendor", "system_ext", "modem"}


class Crc32Hasher:
    existing_crc32 = None

    def get_checksum(self):
        return self.existing_crc32

    def set_checksum(self, existing_crc32):
        self.existing_crc32 = existing_crc32

    def update(self, *args, **kwargs):
        if self.existing_crc32:
            args = args + (self.existing_crc32,)

        self.existing_crc32 = crc32(*args, **kwargs)


@contextlib.contextmanager
def output_open(filename, mode, compress=True):
    if compress and not filename.endswith(".gz"):
        filename += ".gz"

    if compress:
        with gzip.GzipFile(filename, mode, compresslevel=1, mtime=0) as f:
            yield f
    else:
        with open(filename, mode) as f:
            yield f


def output_writer(f_in, f_out, size, db=None):
    if not f_in:
        util.zero_n(f_out, size)
    else:
        crc_hash = None
        mapping = None

        if db is not None and size != 0:
            mapping = True

        if mapping:
            crc_hash = Crc32Hasher()

            # Combine sections if adjacent
            if db and db[-1]["range"][1] == f_out.tell() - 1:
                entry = db.pop()
                crc_hash.set_checksum(entry["checksum"])
                section_start = entry["range"][0]
            else:
                section_start = f_out.tell()

            section_end = f_out.tell() + (size - 1)

        util.copyfileobj_n(f_in, f_out, size, hasher=crc_hash)

        if mapping:
            db.append(
                {
                    "range": [section_start, section_end],
                    "checksum": crc_hash.get_checksum(),
                }
            )


def download_file(f_out, url, section):
    crc_hash = Crc32Hasher()

    req = urllib.request.Request(url)
    req.add_header("Range", f"bytes={section['range'][0]}-{section['range'][1]}")
    with urllib.request.urlopen(req) as data:
        util.copyfileobj_n(
            data, f_out, section["range"][1] - section["range"][0] + 1, hasher=crc_hash
        )

    if crc_hash.get_checksum() != int(section["checksum"], 16):
        raise Exception(f"ERROR: Checksum of range {section['range']} doesn't match")


def download_dummy_image(args):
    with open(args.db, "r") as f:
        database = f.read()

    database = tomlkit.parse(database)

    device_entry = database["device"].get(args.device_name)
    if not device_entry:
        raise Exception(f"ERROR: {args.device_name} cannot be found in the database")

    # Assume we always download the beginning and end (which makes sense for a ZIP file)
    previous_offset = 0
    with output_open(args.output, "wb", args.compress) as f_out:
        for section in device_entry["sections"]:
            util.zero_n(f_out, section["range"][0] - previous_offset)
            download_file(f_out, device_entry["url"], section)
            previous_offset = section["range"][1] + 1


def print_entry(db, original_filename):
    new_map = tomlkit.array()
    new_map.append(tomlkit.nl())

    for section in db:
        entry = tomlkit.inline_table()

        for key, value in section.items():
            entry[key] = f"{value:x}" if key == "checksum" else value

        new_map.append(entry)

    print("*** Add this entry to the database ***")
    print(
        tomlkit.dumps(
            {
                "device": {
                    "new_device_name": {
                        "filename": os.path.basename(original_filename),
                        "url": "",
                        "sections": new_map,
                    }
                }
            }
        )
    )
    print("*** End ***")


def convert_image(args):
    with zipfile.ZipFile(args.input, "r") as z:
        info = z.getinfo(PATH_PAYLOAD)

        with z.open(info, "r") as f:
            _, manifest, blob_offset = ota.parse_payload(f)

        file_offset, _ = ota_utils.GetZipEntryOffset(z, info)

    partition_operations = {}

    for p in manifest.partitions:
        if p.partition_name in PARTITIONS_TO_ZERO:
            old_data_offset = 0

            # Ensure all operations are in order
            for op in p.operations:
                if old_data_offset > op.data_offset:
                    raise Exception("Operations are expected to be ordered")
                old_data_offset = op.data_offset

            partition_operations[p.partition_name] = p.operations

    db = []

    with open(args.input, "rb") as f_in, output_open(
        args.output, "wb", args.compress
    ) as f_out:
        # Copy zip data until payload.bin + payload.bin header
        output_writer(f_in, f_out, file_offset + blob_offset, db)

        # Sort partitions based on data_offset of first operation and iterate
        for _, p_operations in sorted(
            partition_operations.items(), key=lambda x: x[1][0].data_offset
        ):
            # Copy all data until first partition offset
            output_writer(
                f_in,
                f_out,
                p_operations[0].data_offset - (f_in.tell() - file_offset - blob_offset),
                db,
            )

            for op in p_operations:
                if f_out.tell() != (file_offset + blob_offset + op.data_offset):
                    raise Exception("f_out should be equal to the offset")
                output_writer(None, f_out, op.data_length, db)
            f_in.seek(f_out.tell())

        # Copy remaining data
        f_in.seek(0, 2)
        remaining_size = f_in.tell() - f_out.tell()
        f_in.seek(f_out.tell())
        output_writer(f_in, f_out, remaining_size, db)

    print_entry(db, args.input)


def parse_args(args=None):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="subcommand", required=True, help="Subcommands"
    )

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument(
        "--compress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Compress output file",
    )
    base.add_argument("--output", required=True, help="Path to new OTA zip")

    convert = subparsers.add_parser(
        "convert", help="Convert full OTA zip to dummy zip", parents=[base]
    )
    convert.add_argument("--input", required=True, help="Path to original OTA zip")

    download = subparsers.add_parser(
        "download", help="Assemble dummy zip while downloading", parents=[base]
    )
    download.add_argument("--db", required=True, help="Path to database file")
    download.add_argument("device_name", help="Name of device (as in database)")

    return parser.parse_args(args=args)


def main(args=None):
    args = parse_args(args=args)

    if args.subcommand == "convert":
        convert_image(args)
    elif args.subcommand == "download":
        download_dummy_image(args)
    else:
        raise NotImplementedError()


if __name__ == "__main__":
    main()
