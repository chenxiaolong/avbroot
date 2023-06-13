import contextlib
import os
import typing
import unittest.mock

import avbtool

from . import openssl
from . import util


class SmuggledViaKernelCmdlineDescriptor:
    def __init__(self):
        self.kernel_cmdline = None

    def encode(self):
        return self.kernel_cmdline.encode()


@contextlib.contextmanager
def smuggle_descriptors():
    '''
    Smuggle predefined vbmeta descriptors into Avb.make_vbmeta_image via the
    kernel_cmdlines parameter. The make_vbmeta_image function will:

    * loop through kernel_cmdlines
    * create a AvbKernelCmdlineDescriptor instance for each item
    * assign kernel_cmdline to each descriptor instance
    * call encode on each descriptor
    '''

    with unittest.mock.patch('avbtool.AvbKernelCmdlineDescriptor',
                             SmuggledViaKernelCmdlineDescriptor):
        yield


def _get_descriptor_overrides(
    avb: avbtool.Avb,
    images: dict[str, os.PathLike[str]],
) -> typing.Tuple[dict[str, bytes], dict[str, avbtool.AvbDescriptor]]:
    '''
    Build a set of public key (chain) and hash/hashtree descriptor overrides
    that should be inserted in the parent vbmeta image for the given partition
    images.

    If a partition image itself is signed, then a chain descriptor will be used.
    Otherwise, the existing hash or hashtree descriptor is used.
    '''

    # Partition name -> raw public key
    out_public_keys = {}
    # Partition name -> descriptor
    out_descriptors = {}

    # Construct descriptor overrides
    for name, path in images.items():
        image = avbtool.ImageHandler(path, read_only=True)
        footer, header, descriptors, image_size = avb._parse_image(image)

        if name in out_public_keys or name in out_descriptors:
            raise ValueError(f'Duplicate partition name: {name}')

        if header.public_key_size:
            # vbmeta is signed; use a chain descriptor
            blob = avb._load_vbmeta_blob(image)
            offset = header.SIZE + \
                header.authentication_data_block_size + \
                header.public_key_offset
            out_public_keys[name] = \
                blob[offset:offset + header.public_key_size]
        else:
            # vbmeta is unsigned; use the existing descriptor in the footer
            partition_descriptor = next(
                (d for d in descriptors
                    if (isinstance(d, avbtool.AvbHashDescriptor)
                        or isinstance(d, avbtool.AvbHashtreeDescriptor))
                        and d.partition_name == name),
                None,
            )
            if partition_descriptor is None:
                raise ValueError(f'{path} has no descriptor for itself')

            out_descriptors[name] = partition_descriptor

    return (out_public_keys, out_descriptors)


def get_vbmeta_deps(
    avb: avbtool.Avb,
    vbmeta_images: dict[str, os.PathLike[str]],
) -> dict[str, set[str]]:
    '''
    Return the forward and reverse dependency tree for the specified vbmeta
    images.
    '''

    deps = {}

    for name, path in vbmeta_images.items():
        image = avbtool.ImageHandler(path, read_only=True)
        _, _, descriptors, _ = avb._parse_image(image)

        deps.setdefault(name, set())

        for d in descriptors:
            if isinstance(d, avbtool.AvbChainPartitionDescriptor) \
                or isinstance(d, avbtool.AvbHashDescriptor) \
                    or isinstance(d, avbtool.AvbHashtreeDescriptor):
                deps[name].add(d.partition_name)
                deps.setdefault(d.partition_name, set())

    return deps


def patch_vbmeta_image(
    avb: avbtool.Avb,
    images: dict[str, os.PathLike[str]],
    input_path: os.PathLike[str],
    output_path: os.PathLike[str],
    key: os.PathLike[str],
    passphrase: str,
    padding_size: int,
    clear_flags: bool,
):
    '''
    Patch the vbmeta image to reference the provided images.
    '''

    # Load the original root vbmeta image
    image = avbtool.ImageHandler(input_path, read_only=True)
    footer, header, descriptors, image_size = avb._parse_image(image)

    if header.flags != 0:
        if clear_flags:
            header.flags = 0
        else:
            raise ValueError(f'vbmeta flags disable AVB: 0x{header.flags:x}')

    # Build a set of new descriptors in the same order as the original
    # descriptors, except with the descriptors patched to reference the given
    # images
    override_public_keys, override_descriptors = \
        _get_descriptor_overrides(avb, images)
    new_descriptors = []

    for d in descriptors:
        if isinstance(d, avbtool.AvbChainPartitionDescriptor) and \
                d.partition_name in override_public_keys:
            d.public_key = override_public_keys.pop(d.partition_name)
        elif (isinstance(d, avbtool.AvbHashDescriptor) or \
                isinstance(d, avbtool.AvbHashtreeDescriptor)) and \
                d.partition_name in override_descriptors:
            d = override_descriptors.pop(d.partition_name)

        new_descriptors.append(d)

    if override_public_keys:
        raise Exception(f'Unused public key overrides: {override_public_keys}')
    if override_descriptors:
        raise Exception(f'Unused descriptor overrides: {override_descriptors}')

    algorithm_name = avbtool.lookup_algorithm_by_type(header.algorithm_type)[0]

    # Some older Pixel devices' vbmeta images are originally signed by a
    # 2048-bit RSA key, but avbroot expects RSA 4096 keys
    if algorithm_name == 'SHA256_RSA2048':
        algorithm_name = 'SHA256_RSA4096'

    with util.open_output_file(output_path) as f:
        # Smuggle in the prebuilt descriptors via kernel_cmdlines
        with (
            smuggle_descriptors(),
            openssl.inject_passphrase(passphrase),
        ):
            avb.make_vbmeta_image(
                output=f,
                chain_partitions=None,
                algorithm_name=algorithm_name,
                key_path=key,
                public_key_metadata_path=None,
                rollback_index=header.rollback_index,
                flags=header.flags,
                rollback_index_location=header.rollback_index_location,
                props=None,
                props_from_file=None,
                kernel_cmdlines=new_descriptors,
                setup_rootfs_from_kernel=None,
                include_descriptors_from_image=None,
                signing_helper=None,
                signing_helper_with_files=None,
                release_string=header.release_string,
                append_to_release_string=False,
                print_required_libavb_version=False,
                padding_size=padding_size,
            )
