#!/usr/bin/env python3

import argparse
import contextlib
import enum
import hashlib
import itertools
import os
import sys
import tempfile
import unittest.mock
import zipfile

sys.path.append(os.path.join(sys.path[0], '..'))
from avbroot import external, ota, util
from avbroot.main import PARTITION_PRIORITIES, PATH_PAYLOAD
import avbroot.main
import ota_utils
import update_metadata_pb2

import config
import downloader

FILES_DIR = os.path.join(sys.path[0], 'files')
TEST_KEY_PREFIX = os.path.join(sys.path[0], 'keys', 'TEST_KEY_DO_NOT_USE_')

PARTITIONS_TO_PRESERVE = set(sum(PARTITION_PRIORITIES.values(), ()))


def hash_zeroes(hasher, size):
    null_buf = memoryview(b'\0' * 65536)

    while size > 0:
        n = min(size, len(null_buf))
        hasher.update(null_buf[:n])
        size -= n


def hash_file_path(path):
    print('Calculating hash of', path)

    with open(path, 'rb') as f:
        return util.hash_file(f, hashlib.sha256())


def verify_hash(path, sha256_hex):
    hasher = hash_file_path(path)

    if hasher.digest() != bytes.fromhex(sha256_hex):
        raise Exception(f'{path}: expected sha256 {sha256_hex}, '
                        f'but have {hasher.hexdigest()}')


def merge_overlapping(sections):
    '''
    Sort and merge overlapping intervals.
    '''

    result = []

    for start, end in sorted(sections):
        if result and start <= result[-1][1]:
            new_section = (result[-1][0], end)
            result.pop()
            result.append(new_section)
        else:
            result.append((start, end))

    return result


def exclusion_to_inclusion(holes, start, end):
    '''
    Convert an exclusion list into an inclusion list in the range [start, end).
    '''

    exclusions = merge_overlapping(holes)

    if exclusions and (exclusions[0][0] < start or exclusions[-1][1] > end):
        raise ValueError(f'Sections are outside of the range [{start}, {end})')

    points = [start, *itertools.chain(*exclusions), end]

    return [(points[i], points[i + 1]) for i in range(0, len(points), 2)
            if points[i] != points[i + 1]]


def strip_image(input, output):
    '''
    Convert a full OTA to a stripped OTA with all non-AVB-related partitions
    removed from the payload. No headers are updated, so the output file will
    have invalid hashes and signatures.

    Returns the list of file sections copied and the sha256 hasher.
    '''

    with open(input, 'rb') as f_in:
        with zipfile.ZipFile(f_in, 'r') as z:
            info = z.getinfo(PATH_PAYLOAD)

            with z.open(info, 'r') as f:
                _, manifest, blob_offset = ota.parse_payload(f)

            file_offset, _ = ota_utils.GetZipEntryOffset(z, info)

        data_holes = []

        Type = update_metadata_pb2.InstallOperation.Type

        for p in manifest.partitions:
            if p.partition_name not in PARTITIONS_TO_PRESERVE:
                for op in p.operations:
                    if op.type == Type.ZERO or op.type == Type.DISCARD:
                        continue

                    start = file_offset + blob_offset + op.data_offset

                    data_holes.append((start, start + op.data_length))

        # Keep all sections outside of the partitions skipped
        file_size = f_in.seek(0, os.SEEK_END)
        sections_to_keep = exclusion_to_inclusion(data_holes, 0, file_size)

        hasher = hashlib.sha256()

        with open(output, 'wb') as f_out:
            f_in.seek(0)
            f_out.truncate(file_size)

            for section in sections_to_keep:
                # Hash holes as zeroes
                if f_in.tell() != section[0]:
                    hash_zeroes(hasher, section[0] - f_in.tell())
                    f_in.seek(section[0])
                    f_out.seek(section[0])

                # Copy and hash preserved sections
                util.copyfileobj_n(f_in, f_out, section[1] - section[0],
                                   hasher=hasher)

            # There can't be a hole at the end of a zip, so nothing to hash

        return sections_to_keep, hasher


def ignore_zip_crc():
    # We intentionally create a zip file with an invalid CRC for the payload.
    # The CRC of the zip will be checked when EOF is reached. Although we never
    # intentionally read all the way to the end, prefetching of a file might
    # lead to read until EOF and triggering the CRC check, which will fail.
    return unittest.mock.patch('zipfile.ZipExtFile._update_crc',
                               lambda _, __: None)


def url_filename(url):
    return url.split('/')[-1]


class Validate(enum.Enum):
    ALWAYS = 1
    IF_NEW = 2
    NEVER = 3


def download(path, url, sha256_hex, sections=None, path_is_dir=False,
             validate=Validate.IF_NEW):
    if path_is_dir:
        path = os.path.join(path, url_filename(url))

    os.makedirs(os.path.dirname(path), exist_ok=True)

    do_validate = validate != Validate.NEVER

    if os.path.exists(path) and not os.path.exists(path + '.state'):
        if validate == Validate.IF_NEW:
            do_validate = False
    else:
        print('Downloading', url, 'to', path)

        downloader.download_ranges(
            path,
            url,
            sections,
            downloader.DefaultDisplayCallback(),
        )

    if do_validate:
        verify_hash(path, sha256_hex)

    return path


def download_magisk(config_data, work_dir, revalidate):
    return download(
        os.path.join(work_dir, 'magisk'),
        config_data['magisk']['url'].data,
        config_data['magisk']['hash'].data,
        path_is_dir=True,
        validate=Validate.ALWAYS if revalidate else Validate.IF_NEW,
    )


def download_image(config_data, device, work_dir, stripped, revalidate):
    image_config = config_data['device'][device]

    sha256_key = 'full'
    image_file = os.path.join(work_dir, device,
                              url_filename(image_config['url'].data))
    sections = None

    if stripped:
        sha256_key = 'stripped'
        image_file += '.stripped'
        sections = [downloader.Range(s['start'].data, s['end'].data)
                    for s in image_config['sections']]

    return download(
        image_file,
        image_config['url'].data,
        image_config['hash']['original'][sha256_key].data,
        sections=sections,
        validate=Validate.ALWAYS if revalidate else Validate.IF_NEW,
    )


def patch_image(input_file, output_file, stripped, extra_args=[]):
    print('Patching', input_file)

    with ignore_zip_crc() if stripped else contextlib.suppress():
        avbroot.main.main([
            'patch',
            '--privkey-avb', TEST_KEY_PREFIX + 'avb.key',
            '--privkey-ota', TEST_KEY_PREFIX + 'ota.key',
            '--cert-ota', TEST_KEY_PREFIX + 'ota.crt',
            '--input', input_file,
            '--output', output_file,
            *extra_args,
        ])


def extract_image(input_file, output_dir):
    print('Extracting AVB partitions from', input_file)

    avbroot.main.main([
        'extract',
        '--input', input_file,
        '--directory', output_dir,
    ])


def get_magisk_partition(zip):
    with zipfile.ZipFile(zip, 'r') as z:
        info = z.getinfo(PATH_PAYLOAD)

        with z.open(info, 'r') as f:
            _, manifest, blob_offset = ota.parse_payload(f)
            images = avbroot.main.get_partitions_by_type(manifest)
            return images['@gki_ramdisk']


def filter_devices(config_data, selected):
    devices = [k.data for k in config_data['device']]

    if selected is not None:
        invalid = set(selected) - set(devices)
        if invalid:
            raise ValueError(f'Invalid devices: {sorted(invalid)}')

        devices = selected

    return devices


def strip_subcommand(args):
    sections, sha256 = strip_image(args.input, args.output)

    print('Preserved sections:')
    for section in sections:
        print(f'- {section[0]}-{section[1]}')

    print('SHA256:', sha256.hexdigest())


def add_subcommand(args):
    config_data = config.load_config()

    image_dir = os.path.join(args.work_dir, args.device)

    full_ota = os.path.join(image_dir, url_filename(args.url))
    full_ota_patched = full_ota + args.output_file_suffix
    stripped_ota = full_ota + '.stripped'
    stripped_ota_patched = stripped_ota + args.output_file_suffix

    full_ota_hash = args.hash

    download(
        full_ota,
        args.url,
        full_ota_hash,
        validate=Validate.ALWAYS if full_ota_hash else Validate.NEVER,
    )

    # Calculate the hash ourselves if one wasn't provided
    if not full_ota_hash:
        full_ota_hash = hash_file_path(full_ota).hexdigest()

    print('Stripping', full_ota, 'to', stripped_ota)
    sections, stripped_ota_hash = strip_image(full_ota, stripped_ota)

    magisk_file = download_magisk(config_data, args.work_dir, True)
    magisk_args = ['--magisk', magisk_file]

    patch_image(full_ota, full_ota_patched, False, magisk_args)
    full_ota_patched_hash = hash_file_path(full_ota_patched)

    patch_image(stripped_ota, stripped_ota_patched, True, magisk_args)
    stripped_ota_patched_hash = hash_file_path(stripped_ota_patched)

    with tempfile.TemporaryDirectory() as temp_dir:
        extract_image(full_ota_patched, temp_dir)

        avb_hashes = {}

        with os.scandir(temp_dir) as it:
            for entry in it:
                avb_hashes[entry.name] = hash_file_path(entry.path).hexdigest()

    print('Adding', args.device, 'to config file')

    # In strictyaml/ruamel, comments are associated with the previously parsed
    # node. When updating an existing device config, the comment for the next
    # device config is lost because it's attached to the last key/value pair
    # of avb_images. It's easier to manually add back the comments than hacking
    # around strictyaml's internals to fix this.

    config_data['device'][args.device] = {
        'url': args.url,
        'sections': [{'start': s[0], 'end': s[1]} for s in sections],
        'hash': {
            'original': {
                'full': full_ota_hash,
                'stripped': stripped_ota_hash.hexdigest(),
            },
            'patched': {
                'full': full_ota_patched_hash.hexdigest(),
                'stripped': stripped_ota_patched_hash.hexdigest(),
            },
            'avb_images': {n: avb_hashes[n] for n in sorted(avb_hashes)},
        }
    }

    config.save_config(config_data)

    if args.delete_on_success:
        os.unlink(full_ota_patched)
        os.unlink(stripped_ota_patched)


def download_subcommand(args):
    config_data = config.load_config()
    devices = filter_devices(config_data, args.device)

    if not args.magisk and not devices:
        raise ValueError('No downloads selected')

    if args.magisk:
        download_magisk(config_data, args.work_dir, args.revalidate)

    for device in devices:
        download_image(
            config_data,
            device,
            args.work_dir,
            args.stripped,
            args.revalidate,
        )


def test_subcommand(args):
    config_data = config.load_config()
    devices = filter_devices(config_data, args.device)

    magisk_file = download_magisk(config_data, args.work_dir, args.revalidate)

    for device in devices:
        image = config_data['device'][device]

        image_file = download_image(
            config_data,
            device,
            args.work_dir,
            args.stripped,
            args.revalidate,
        )
        patched_file = image_file + args.output_file_suffix
        sha256_key = 'stripped' if args.stripped else 'full'
        patched_hash = image['hash']['patched'][sha256_key].data

        patch_image(image_file, patched_file, args.stripped, [
            '--magisk', magisk_file,
        ])

        with tempfile.TemporaryDirectory() as temp_dir:
            extract_image(patched_file, temp_dir)

            # Check partitions first so we fail fast if the issue is with AVB
            avb_images = image['hash']['avb_images']
            expected = set(k.data for k in avb_images)
            extracted = set(os.listdir(temp_dir))
            if extracted != expected:
                raise Exception(f'Expected {expected} AVB images, '
                                f'but have {extracted} instead')

            for name in extracted:
                verify_hash(os.path.join(temp_dir, name),
                            avb_images[name].data)

            # Then, validate the hash of everything
            verify_hash(patched_file, patched_hash)

            # Patch again, but this time, use the previously patched boot image
            # instead of applying the Magisk patch
            magisk_partition = get_magisk_partition(patched_file)

            os.unlink(patched_file)

            patch_image(image_file, patched_file, args.stripped, [
                '--prepatched',
                os.path.join(temp_dir, f'{magisk_partition}.img'),
            ])

        verify_hash(patched_file, patched_hash)

        if args.delete_on_success:
            os.unlink(patched_file)


class SortingHelpFormatter(argparse.HelpFormatter):
    def add_arguments(self, actions):
        super().add_arguments(sorted(actions, key=self._sort_key))

    @staticmethod
    def _sort_key(action):
        if action.option_strings:
            # Make single dash options appear first
            option = action.option_strings[0].casefold()

            leading_dashes = 0
            for c in option:
                if c == '-':
                    leading_dashes += 1
                else:
                    break

            return ' ' * (2 - leading_dashes) + option
        else:
            return ''


def parse_args(args=None):
    kwargs = {'formatter_class': SortingHelpFormatter}
    parser = argparse.ArgumentParser(**kwargs)

    # Common arguments used by multiple subcommands

    p_devices = argparse.ArgumentParser(add_help=False)
    p_devices.add_argument(
        '-d', '--device',
        action='append',
        help='Device config name',
    )

    p_download = argparse.ArgumentParser(add_help=False)
    p_download.add_argument(
        '--revalidate',
        action=argparse.BooleanOptionalAction,
        help='Revalidate hash of existing download',
    )
    p_download.add_argument(
        '--stripped',
        action=argparse.BooleanOptionalAction,
        help='Download stripped OTA instead of full OTA',
    )

    p_patch = argparse.ArgumentParser(add_help=False)
    p_patch.add_argument(
        '--delete-on-success',
        action=argparse.BooleanOptionalAction,
        help='Delete output files on success',
    )
    p_patch.add_argument(
        '--output-file-suffix',
        default='.patched',
        help='Suffix for patched output files',
    )

    p_work_dir = argparse.ArgumentParser(add_help=False)
    p_work_dir.add_argument(
        '-w', '--work-dir',
        default=FILES_DIR,
        help='Working directory for storing images',
    )

    # Subcommands

    subparsers = parser.add_subparsers(
        dest='subcommand',
        required=True,
        help='Subcommands',
    )

    strip = subparsers.add_parser(
        'strip',
        help='Convert full OTA to stripped form',
        **kwargs,
    )
    strip.add_argument(
        '-i', '--input',
        required=True,
        help='Path to original OTA zip',
    )
    strip.add_argument(
        '-o', '--output',
        required=True,
        help='Path to new stripped OTA zip',
    )

    add = subparsers.add_parser(
        'add',
        parents=[p_patch, p_work_dir],
        help='Add new image to config',
        **kwargs,
    )
    add.add_argument(
        '-u', '--url',
        required=True,
        help='URL to full OTA zip',
    )
    add.add_argument(
        '-d', '--device',
        required=True,
        help='Device config name',
    )
    add.add_argument(
        '-H', '--hash',
        help='Expected hash of full OTA zip',
    )

    download = subparsers.add_parser(
        'download',
        parents=[p_devices, p_download, p_work_dir],
        help='Download device image',
        **kwargs,
    )
    download.add_argument(
        '--magisk',
        default=True,
        action=argparse.BooleanOptionalAction,
        help='Download Magisk APK',
    )
    download.add_argument(
        '--no-devices',
        dest='device',
        action='store_const',
        const=[],
        help='Skip downloading any device images',
    )

    subparsers.add_parser(
        'test',
        parents=[p_devices, p_download, p_patch, p_work_dir],
        help='Run tests',
        **kwargs,
    )

    return parser.parse_args(args=args)


def main(args=None):
    args = parse_args(args=args)

    if args.subcommand == 'strip':
        strip_subcommand(args)
    elif args.subcommand == 'download':
        download_subcommand(args)
    elif args.subcommand == 'add':
        add_subcommand(args)
    elif args.subcommand == 'test':
        test_subcommand(args)
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
