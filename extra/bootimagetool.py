#!/usr/bin/env python3

import argparse
import itertools
import json
import os
import sys

sys.path.append(os.path.join(sys.path[0], '..'))
from avbroot.formats import bootimage


class BytesDecoder(json.JSONDecoder):
    def __init__(self):
        super().__init__(object_hook=self.from_dict)

    @staticmethod
    def from_dict(d):
        # This is insufficient for arbitrary data, but we're not dealing with
        # arbitrary data
        if 'type' in d:
            if d['type'] == 'UTF-8':
                return d['data'].encode('UTF-8')
            elif d['type'] == 'hex':
                return bytes.fromhex(d['data'])

        return d


class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            if b'\0' not in obj:
                try:
                    return {
                        'type': 'UTF-8',
                        'data': obj.decode('UTF-8'),
                    }
                except UnicodeDecodeError:
                    pass

            return {
                'type': 'hex',
                'data': obj.hex(),
            }

        return super().default(obj)


def read_or_none(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def write_if_not_none(path, data):
    if data is not None:
        with open(path, 'wb') as f:
            f.write(data)


def parse_args():
    parser_kwargs = {'formatter_class': argparse.ArgumentDefaultsHelpFormatter}

    parser = argparse.ArgumentParser(**parser_kwargs)
    subparsers = parser.add_subparsers(dest='subcommand', required=True,
                                       help='Subcommands')

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument('-q', '--quiet', action='store_true',
                      help='Do not print header information')

    pack = subparsers.add_parser('pack', help='Pack a boot image',
                                 parents=[base], **parser_kwargs)
    unpack = subparsers.add_parser('unpack', help='Unpack a boot image',
                                   parents=[base], **parser_kwargs)
    repack = subparsers.add_parser('repack', help='Repack a boot image',
                                   parents=[base], **parser_kwargs)

    for p in (pack, unpack):
        prefix = '--input-' if p == pack else '--output-'

        p.add_argument('boot_image', help='Path to boot image')

        p.add_argument(prefix + 'header', default='header.json',
                       help='Path to header JSON')
        p.add_argument(prefix + 'kernel', default='kernel.img',
                       help='Path to kernel')
        p.add_argument(prefix + 'ramdisk-prefix', default='ramdisk.img.',
                       help='Path prefix for ramdisk')
        p.add_argument(prefix + 'second', default='second.img',
                       help='Path to second stage bootloader')
        p.add_argument(prefix + 'recovery-dtbo', default='recovery_dtbo.img',
                       help='Path to recovery dtbo/acpio')
        p.add_argument(prefix + 'dtb', default='dtb.img',
                       help='Path to device tree blob')
        p.add_argument(prefix + 'bootconfig', default='bootconfig.txt',
                       help='Path to bootconfig')

    repack.add_argument('input', help='Path to input boot image')
    repack.add_argument('output', help='Path to output boot image')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.subcommand == 'pack':
        with open(args.input_header, 'r') as f:
            data = json.load(f, cls=BytesDecoder)

        img = bootimage.create_from_dict(data)

        img.kernel = read_or_none(args.input_kernel)
        img.second = read_or_none(args.input_second)
        img.recovery_dtbo = read_or_none(args.input_recovery_dtbo)
        img.dtb = read_or_none(args.input_dtb)
        img.bootconfig = read_or_none(args.input_bootconfig)

        for i in itertools.count():
            ramdisk = read_or_none(f'{args.input_ramdisk_prefix}{i}')
            if ramdisk is None:
                break

            img.ramdisks.append(ramdisk)

        if not args.quiet:
            print(img)

        with open(args.boot_image, 'wb') as f:
            img.generate(f)

    elif args.subcommand == 'unpack':
        with open(args.boot_image, 'rb') as f:
            img = bootimage.load_autodetect(f)
            if not args.quiet:
                print(img)

        with open(args.output_header, 'w') as f:
            json.dump(img.to_dict(), f, indent=4, cls=BytesEncoder)

        write_if_not_none(args.output_kernel, img.kernel)
        write_if_not_none(args.output_second, img.second)
        write_if_not_none(args.output_recovery_dtbo, img.recovery_dtbo)
        write_if_not_none(args.output_dtb, img.dtb)
        write_if_not_none(args.output_bootconfig, img.bootconfig)

        for i, ramdisk in enumerate(img.ramdisks):
            write_if_not_none(f'{args.output_ramdisk_prefix}{i}', ramdisk)

    elif args.subcommand == 'repack':
        with open(args.input, 'rb') as f:
            img = bootimage.load_autodetect(f)
            if not args.quiet:
                print(img)

        with open(args.output, 'wb') as f:
            img.generate(f)

    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
