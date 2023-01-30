import base64
import binascii
import bz2
import hashlib
import lzma
import os
import struct
import sys

# Silence undesired warning
orig_argv0 = sys.argv[0]
sys.argv[0] = sys.argv[0].removesuffix('.py')
import common
sys.argv[0] = orig_argv0

import ota_metadata_pb2
import ota_utils
import update_metadata_pb2

from . import openssl
from . import util


OTA_MAGIC = b'CrAU'


def parse_payload(f):
    '''
    Parse payload header from a file-like object. After this function returns,
    the file position is set to the beginning of the blob section.
    '''

    f.seek(0)

    # Validate header
    magic = f.read(4)
    if magic != OTA_MAGIC:
        raise Exception(f'Invalid magic: {magic}')

    version, = struct.unpack('!Q', f.read(8))
    if version != 2:
        raise Exception(f'Unsupported version: {version}')

    manifest_size, = struct.unpack('!Q', f.read(8))
    metadata_signature_size, = struct.unpack('!I', f.read(4))

    # Read manifest
    manifest_raw = f.read(manifest_size)
    manifest = update_metadata_pb2.DeltaArchiveManifest()
    manifest.ParseFromString(manifest_raw)

    if any(p.HasField('old_partition_info') for p in manifest.partitions):
        raise Exception('File is a delta OTA, not a full OTA')

    # Skip manifest signatures
    f.seek(metadata_signature_size, os.SEEK_CUR)

    return (version, manifest, f.tell())


def _extract_image(f_payload, f_out, block_size, blob_offset, partition):
    '''
    Extract the partition image from <f_payload> to <f_out> by processing the
    manifests list of install operations.
    '''

    Type = update_metadata_pb2.InstallOperation.Type

    for op in partition.operations:
        for extent in op.dst_extents:
            f_payload.seek(blob_offset + op.data_offset)
            f_out.seek(extent.start_block * block_size)
            h_data = hashlib.sha256()

            if op.type == Type.REPLACE:
                util.copyfileobj_n(f_payload, f_out, op.data_length,
                                   hasher=h_data)
            elif op.type == Type.REPLACE_BZ:
                decompressor = bz2.BZ2Decompressor()
                util.decompress_n(decompressor, f_payload, f_out, op.data_length,
                                  hasher=h_data)
            elif op.type == Type.REPLACE_XZ:
                decompressor = lzma.LZMADecompressor()
                util.decompress_n(decompressor, f_payload, f_out, op.data_length,
                                  hasher=h_data)
            elif op.type == Type.ZERO or op.type == Type.DISCARD:
                util.zero_n(f_out, extent.num_blocks * block_size)
            else:
                raise Exception(f'Unsupported operation: {op.type}')

            if h_data.digest() != op.data_sha256_hash:
                raise Exception('Expected hash %s, but got %s' %
                                (h_data.hexdigest(),
                                 binascii.hexlify(op.data_sha256_hash)))


def extract_images(f, manifest, blob_offset, output_dir, partition_names):
    '''
    Extract the specified partition images from the payload into <output_dir>.
    '''

    remaining = set(partition_names)

    for p in manifest.partitions:
        if p.partition_name not in remaining:
            continue

        remaining.remove(p.partition_name)

        output_path = os.path.join(output_dir, p.partition_name + '.img')

        with open(output_path, 'wb') as f_out:
            _extract_image(f, f_out, manifest.block_size, blob_offset, p)

    if remaining:
        raise Exception(f'Images not found: {remaining}')


def _compress_image(partition, block_size, input_path, output_path):
    '''
    XZ-compress the image at <input_path> to <output_path> and update the
    partition metadata with the appropriate checksums and install operations
    metadata.

    The size in the (sole) install operation is set correctly, but the offset
    must be manually updated. It is initially set to the maximum uint64 value.
    '''

    h_uncompressed = hashlib.sha256()
    h_compressed = hashlib.sha256()
    size_uncompressed = 0
    size_compressed = 0
    # AOSP's payload_consumer does not support CRC during decompression
    compressor = lzma.LZMACompressor(check=lzma.CHECK_NONE)
    buf = bytearray(16384)
    buf_view = memoryview(buf)

    with (
        open(input_path, 'rb', buffering=0) as f_in,
        open(output_path, 'wb') as f_out,
    ):
        while n := f_in.readinto(buf_view):
            h_uncompressed.update(buf_view[:n])
            size_uncompressed += n

            xz_data = compressor.compress(buf_view[:n])
            h_compressed.update(xz_data)
            size_compressed += len(xz_data)
            f_out.write(xz_data)

        xz_data = compressor.flush()
        h_compressed.update(xz_data)
        size_compressed += len(xz_data)
        f_out.write(xz_data)

    if size_uncompressed % block_size:
        raise Exception('Size of %s (%d) is not aligned to the block size (%d)'
                        % (partition.partition_name, size_uncompressed,
                           block_size))

    partition.new_partition_info.size = size_uncompressed
    partition.new_partition_info.hash = h_uncompressed.digest()

    extent = update_metadata_pb2.Extent()
    extent.start_block = 0
    extent.num_blocks = size_uncompressed // block_size

    operation = update_metadata_pb2.InstallOperation()
    operation.type = update_metadata_pb2.InstallOperation.Type.REPLACE_XZ
    # Must be manually updated by the caller
    operation.data_offset = 2 ** 64 - 1
    operation.data_length = size_compressed
    operation.dst_extents.append(extent)
    operation.data_sha256_hash = h_compressed.digest()

    partition.ClearField('operations')
    partition.operations.append(operation)


def _recompute_offsets(manifest, new_images):
    '''
    Recompute the blob offsets to account for the new images.

    Returns ([(<image file>, <data offset>, <data size>)], <blob size>). If the
    image file is None, then the data offset is relative to the blob offset of
    the original payload. Otherwise, the data offset is an absolute offset into
    the image file.
    '''

    # (<image file>, <data offset>, <data size>)
    data_list = []
    offset = 0

    for p in manifest.partitions:
        is_patched = p.partition_name in new_images
        p_offset = 0

        for op in p.operations:
            if is_patched:
                data_list.append((
                    new_images[p.partition_name],
                    p_offset,
                    op.data_length,
                ))
            else:
                data_list.append((
                    None,
                    op.data_offset,
                    op.data_length,
                ))

            op.data_offset = offset
            p_offset += op.data_length
            offset += op.data_length

    return (data_list, offset)


def _sign_hash(hash, key, max_sig_size):
    '''
    Sign <hash> with <key> and return a Signatures protobuf struct with the
    signature padded to <max_sig_size>.
    '''

    hash_signed = openssl.sign_data(key, hash)
    assert len(hash_signed) <= max_sig_size

    signature = update_metadata_pb2.Signatures.Signature()
    signature.unpadded_signature_size = len(hash_signed)
    signature.data = hash_signed + b'\0' * (max_sig_size - len(hash_signed))

    signatures = update_metadata_pb2.Signatures()
    signatures.signatures.append(signature)

    return signatures


def patch_payload(f_in, f_out, version, manifest, blob_offset, temp_dir,
                  patched, file_size, key):
    '''
    Copy the payload from <f_in> to <f_out>, updating references to <patched>
    images as they are encountered. <f_out> will be signed with <key>.
    '''

    max_sig_size = openssl.max_signature_size(key)

    # Strip out old payload signature
    if manifest.HasField('signatures_size'):
        trunc_file_size = blob_offset + manifest.signatures_offset
        if trunc_file_size > file_size:
            raise Exception('Payload signature offset is beyond EOF')
        file_size = trunc_file_size

    # Partition name -> compressed image path
    compressed = {}

    # Update the partition manifests to refer to the patched images
    for name, path in patched.items():
        # Find the partition in the manifest
        partition = next((p for p in manifest.partitions
            if p.partition_name == name), None)
        if partition is None:
            raise Exception(f'Partition {name} not found in manifest')

        # Compress the image and update the partition manifest accordingly
        compressed_path = os.path.join(temp_dir, f'{name}.img')
        _compress_image(
            partition,
            manifest.block_size,
            path,
            compressed_path,
        )
        compressed[name] = compressed_path

    # Fill out blob offsets and compute final size
    blob_data_list, blob_size = _recompute_offsets(manifest, compressed)

    # Get the length of an dummy signature struct since the length fields are
    # part of the data to be signed
    dummy_sig = _sign_hash(hashlib.sha256().digest(), key, max_sig_size)
    dummy_sig_size = len(dummy_sig.SerializeToString())

    # Fill out new payload signature information
    manifest.signatures_offset = blob_size
    manifest.signatures_size = dummy_sig_size

    # Build new manifest
    manifest_raw_new = manifest.SerializeToString()

    class MultipleHasher:
        def __init__(self, hashers):
            self.hashers = hashers

        def update(self, data):
            for hasher in self.hashers:
                hasher.update(data)

    # Excludes signatures (hashes are for signing)
    h_partial = hashlib.sha256()
    # Includes signatures (hashes are for properties file)
    h_full = hashlib.sha256()
    # Updates both of the above
    h_both = MultipleHasher((h_partial, h_full))

    def write(hasher, data):
        hasher.update(data)
        f_out.write(data)

    # Write header to output file
    write(h_both, OTA_MAGIC)
    write(h_both, struct.pack('!Q', version))
    write(h_both, struct.pack('!Q', len(manifest_raw_new)))
    write(h_both, struct.pack('!I', dummy_sig_size))

    # Write new manifest
    write(h_both, manifest_raw_new)

    # Sign metadata (header + manifest) hash. The signature is not included in
    # the payload hash.
    metadata_hash = h_partial.digest()
    metadata_sig = _sign_hash(metadata_hash, key, max_sig_size)
    write(h_full, metadata_sig.SerializeToString())

    # Write new blob
    for image_file, data_offset, data_length in blob_data_list:
        if image_file is None:
            f_in.seek(blob_offset + data_offset)
            util.copyfileobj_n(f_in, f_out, data_length, hasher=h_both)
        else:
            with open(image_file, 'rb') as f_image:
                f_image.seek(data_offset)
                util.copyfileobj_n(f_image, f_out, data_length, hasher=h_both)

    # Append payload signature
    payload_sig = _sign_hash(h_partial.digest(), key, max_sig_size)
    write(h_full, payload_sig.SerializeToString())

    # Generate properties file
    metadata_offset = len(OTA_MAGIC) + struct.calcsize('!QQI')
    metadata_size = metadata_offset + len(manifest_raw_new)
    blob_size = manifest.signatures_offset + manifest.signatures_size
    new_file_size = metadata_size + dummy_sig_size + blob_size

    b64 = lambda d: base64.b64encode(d)
    props = [
        b'FILE_HASH=%s\n' % b64(h_full.digest()),
        b'FILE_SIZE=%d\n' % new_file_size,
        b'METADATA_HASH=%s\n' % b64(metadata_hash),
        b'METADATA_SIZE=%d\n' % metadata_size,
    ]

    return b''.join(props)


def sign_zip(input_path, output_path, key_prefix, metadata_raw):
    '''
    Sign an unsigned OTA zip. <metadata_raw> should be the serialized OTA
    metadata protobuf struct from the original OTA. The property files contained
    within the metadata that reference stored zip entries will be deleted and
    recreated during signing.
    '''

    metadata = ota_metadata_pb2.OtaMetadata()
    metadata.ParseFromString(metadata_raw)

    metadata.property_files.clear()

    # We can't replace common.OPTIONS itself because ota_utils holds a reference
    # to the original instance
    attrs = (
        'search_path',
        'signapk_shared_library_path',
        'signapk_path',
    )
    orig_attrs = {a: getattr(common.OPTIONS, a) for a in attrs}

    try:
        common.OPTIONS.search_path = '/var/empty'
        common.OPTIONS.signapk_shared_library_path = '/var/empty'
        common.OPTIONS.signapk_path = os.path.join(
            os.path.dirname(__file__),
            '..', 'signapk', 'build', 'libs', 'signapk-all.jar',
        )

        ota_utils.FinalizeMetadata(
            metadata,
            input_path,
            output_path,
            package_key=key_prefix,
        )

    finally:
        common.Cleanup()

        for k, v in orig_attrs.items():
            setattr(common.OPTIONS, k, v)
