#!/usr/bin/env python3

# This script builds a virtual machine image suitable for running magiskboot
# and associated scripts.
#
# Alpine Linux, with its busybox-based userspace, is used as the base. This is
# sufficiently close the Android environment that Magisk expects. There is
# currently no dependency on Android-specific kernel features, like binder, so
# we just use Alpine's kernel. If this changes in the future, another approach
# will be needed because the prebuilt GKI kernel is built without support for
# devtmpfs or 9p.

import binascii
import gzip
import hashlib
import os
import shutil
import sys
import typing
import urllib.request

import pycdlib

import minicpio


ALPINE_ARCH = 'aarch64'
ALPINE_VERSION = '3.17.1'
ALPINE_MINIROOTFS_SHA512 = 'f7dfac4fd4a847eb72d67aed5fdee55779b5da9643eb78e2a2781c08ce7ca12508053af7013612e4ae3e8f0483c449be9565e7ed10ad96f1e6f4421b43e04331'

Path = typing.Union[str, bytes, os.PathLike]


def unlink_file(path: Path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def download(url: str, path: Path, checksum: bytes) -> Path:
    hasher = hashlib.sha512()

    if os.path.exists(path):
        print(f'Verifying checksum of {path}')

        with open(path, 'rb') as f:
            while True:
                data = f.read(1024 * 1024)
                if not data:
                    break

                hasher.update(data)
    else:
        print(f'Downloading {url} to {path}')

        try:
            with urllib.request.urlopen(url) as f_in:
                with open(path, 'wb') as f_out:
                    while True:
                        data = f_in.read(1024 * 1024)
                        if not data:
                            break

                        hasher.update(data)
                        f_out.write(data)
        except Exception:
            unlink_file(path)
            raise

    if hasher.digest() != checksum:
        expected = binascii.hexlify(checksum).decode('ascii')
        raise Exception(f'Expected {expected}, but have {hasher.hexdigest()}')

    return path


def download_alpine_image(directory: Path) -> Path:
    major_minor = '.'.join(ALPINE_VERSION.split('.')[0:2])
    filename = f'alpine-virt-{ALPINE_VERSION}-{ALPINE_ARCH}.iso'
    url = f'https://dl-cdn.alpinelinux.org/alpine/v{major_minor}/releases/' + \
        f'{ALPINE_ARCH}/{filename}'
    path = os.path.join(directory, filename)

    return download(url, path, binascii.unhexlify(ALPINE_MINIROOTFS_SHA512))


# modloop has a complete copy of the subset in the ramdisk. Only loop and
# squashfs needs to remain so that modloop can be mounted.
def is_unneeded_kmod(entry: minicpio.CpioEntryNew) -> bool:
    # The kernel requires directory entries to exist. Just keep empty
    # directories around since they take almost no space.
    return entry.name.endswith(b'.ko') \
        and not entry.name.endswith(b'/loop.ko') \
        and not entry.name.endswith(b'/squashfs.ko')


# Busybox provides everything we need
def is_unneeded_bin_or_lib(entry: minicpio.CpioEntryNew) -> bool:
    return \
        (entry.name.startswith(b'bin/') and entry.name != b'bin/busybox') \
        or entry.name.startswith(b'sbin/') \
        or (b'.so.' in entry.name and b'musl' not in entry.name)


def main():
    dist_dir = os.path.join(sys.path[0], 'dist')
    os.makedirs(dist_dir, exist_ok=True)

    alpine = download_alpine_image(dist_dir)
    iso = pycdlib.PyCdlib()
    cpio = minicpio.CpioFile()

    with open(alpine, 'rb') as f_iso:
        iso.open_fp(f_iso)

        try:
            rr = iso.get_rock_ridge_facade()

            print('Extracting kernel')
            with rr.open_file_from_iso('/boot/vmlinuz-virt') as f_in:
                with open(os.path.join(dist_dir, 'kernel'), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            print('Loading original ramdisk')
            with rr.open_file_from_iso('/boot/initramfs-virt') as f_in_raw:
                with gzip.open(f_in_raw) as f_in:
                    cpio.load(f_in)

            print('Adding modloop image to ramdisk')
            cpio.entries.append(minicpio.CpioEntryNew.new_directory(b'boot'))
            with rr.open_file_from_iso('/boot/modloop-virt') as f_in:
                cpio.entries.append(minicpio.CpioEntryNew.new_file(
                    b'boot/modloop-virt', data=f_in.read()))
        finally:
            iso.close()

    print('Deleting unneeded files')
    cpio.entries = [e for e in cpio.entries if not (
        is_unneeded_kmod(e)
        or is_unneeded_bin_or_lib(e)
        # We use our custom init
        or e.name == b'init'
        or e.name == b'newroot'
        # We don't need any existing configs
        or e.name.startswith(b'etc/')
        or e.name.startswith(b'lib/mdev')
        or e.name.startswith(b'media')
        # We don't need modloop verification keys
        or e.name.startswith(b'var')
    )]

    print('Adding custom startup scripts and build.prop')
    cpio.entries.append(minicpio.CpioEntryNew.new_directory(b'system'))
    for filename, opts in {
        'build.prop': {'name': b'system/build.prop', 'perms': 0o644},
        'init': {'name': b'init', 'perms': 0o755},
        'inittab': {'name': b'etc/inittab', 'perms': 0o644},
        'startup': {'name': b'startup', 'perms': 0o755},
    }.items():
        with open(os.path.join(sys.path[0], filename), 'rb') as f_in:
            cpio.entries.append(minicpio.CpioEntryNew.new_file(
                opts['name'], perms=opts['perms'], data=f_in.read()))

    print('Writing new ramdisk')
    with open(os.path.join(dist_dir, 'ramdisk'), 'wb') as f:
        cpio.write(f)


if __name__ == '__main__':
    main()
