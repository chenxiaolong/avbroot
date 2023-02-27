import contextlib
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


def _get_descriptor_overrides(avb, paths):
    '''
    Build a set of chain and hash descriptor overrides for the given paths
    based on whether they are signed.
    '''

    # Partition name -> raw public key
    chains = {}
    # Partition name -> hash descriptor
    hashes = {}

    # Construct descriptor overrides
    for path in paths:
        image = avbtool.ImageHandler(path, read_only=True)
        footer, header, descriptors, image_size = avb._parse_image(image)

        # Find the partition name in the first hash descriptor
        hash = next(d for d in descriptors
                    if isinstance(d, avbtool.AvbHashDescriptor))

        if hash is None:
            raise Exception(f'{path} has no hash descriptor')
        elif hash.partition_name in chains or hash.partition_name in hashes:
            raise Exception(f'Duplicate partition name: {hash.partition_name}')

        if header.public_key_size:
            # vbmeta is signed; use a chain descriptor
            blob = avb._load_vbmeta_blob(image)
            offset = header.SIZE + \
                header.authentication_data_block_size + \
                header.public_key_offset
            chains[hash.partition_name] = \
                blob[offset:offset + header.public_key_size]
        else:
            # vbmeta is unsigned; use a hash descriptor
            hashes[hash.partition_name] = hash

    return (chains, hashes)


def patch_vbmeta_root(avb, images, input_path, output_path, key, passphrase,
                      padding_size, clear_flags):
    '''
    Patch the root vbmeta image to reference the provided images.
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
    chains, hashes = _get_descriptor_overrides(avb, images)
    new_descriptors = []

    for d in descriptors:
        if isinstance(d, avbtool.AvbChainPartitionDescriptor) and \
                d.partition_name in chains:
            d.public_key = chains.pop(d.partition_name)
        elif isinstance(d, avbtool.AvbHashDescriptor) and \
                d.partition_name in hashes:
            d = hashes.pop(d.partition_name)

        new_descriptors.append(d)

    if chains:
        raise Exception(f'Unused chain overrides: {chains}')
    if hashes:
        raise Exception(f'Unused hash overrides: {hashes}')

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
