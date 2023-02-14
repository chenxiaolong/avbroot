#!/usr/bin/env python3

import argparse
import base64
import os
import sys

sys.path.append(os.path.join(sys.path[0], '..'))
from avbroot.formats import compression
from avbroot.formats import cpio


CONTENT_BEGIN = '----- BEGIN UTF-8 CONTENT -----'
CONTENT_END = '----- END UTF-8 CONTENT -----'
CONTENT_END_NO_NEWLINE = '----- END UTF-8 CONTENT (NO NEWLINE) -----'

BASE64_BEGIN = '----- BEGIN BASE64 CONTENT -----'
BASE64_END = '----- END BASE64 CONTENT -----'
BASE64_END_TRUNCATED = '----- END BASE64 CONTENT (TRUNCATED) -----'

NO_DATA = '----- NO DATA -----'


def print_content(data, truncate=False):
    if not data:
        print(NO_DATA)
        return

    if b'\0' not in data:
        try:
            data_str = data.decode('UTF-8')

            if CONTENT_BEGIN not in data_str \
                    and CONTENT_END not in data_str \
                    and CONTENT_END_NO_NEWLINE not in data_str:
                print(CONTENT_BEGIN)
                print(data_str, end='')
                if data_str[-1] != '\n':
                    print()
                    print(CONTENT_END_NO_NEWLINE)
                else:
                    print(CONTENT_END)

            return
        except UnicodeDecodeError:
            pass

    data_base64 = base64.b64encode(data).decode('ascii')

    print(BASE64_BEGIN)
    for i, offset in enumerate(range(0, len(data_base64), 76)):
        if truncate and i == 5:
            print(BASE64_END_TRUNCATED)
            return

        print(data_base64[offset:offset + 76])
    print(BASE64_END)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand', required=True,
                                       help='Subcommands')

    dump = subparsers.add_parser('dump', help='Dump cpio headers and data')
    repack = subparsers.add_parser('repack', help='Repack cpio archive')

    dump.add_argument('--no-truncate', action='store_true',
                      help='Do not truncate binary file contents')

    for p in (dump, repack):
        p.add_argument('input', help='Path to input cpio file')

    repack.add_argument('output', help='Path to output cpio file')

    return parser.parse_args()


def load_archive(path, **cpio_kwargs):
    with open(path, 'rb') as f_raw:
        decompressed = False

        try:
            with compression.CompressedFile(f_raw, 'rb') as f:
                decompressed = True
                return cpio.load(f.fp, **cpio_kwargs), f.format
        except ValueError:
            # Not the best API
            if decompressed:
                raise
            else:
                f_raw.seek(0)
                return cpio.load(f_raw, **cpio_kwargs), None


def save_archive(path, entries, format):
    with open(path, 'wb') as f_raw:
        if format:
            with compression.CompressedFile(f_raw, 'wb', format=format) as f:
                cpio.save(f.fp, entries)
        else:
            cpio.save(f_raw, entries)


def main():
    args = parse_args()

    if args.subcommand == 'dump':
        entries, format = load_archive(
            args.input,
            # We want to show the headers exactly as they are
            include_trailer=True,
            reassign_inodes=False,
        )

        print('Compression format:', format)
        print()

        for entry in entries:
            print(entry)
            print_content(entry.content, truncate=not args.no_truncate)
            print()

    elif args.subcommand == 'repack':
        entries, format = load_archive(args.input)
        save_archive(args.output, entries, format)

    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()