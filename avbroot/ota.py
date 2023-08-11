import base64
import binascii
import bz2
import collections
import concurrent.futures
import contextlib
import hashlib
import io
import lzma
import os
import struct
import sys
import subprocess
import threading
import unittest.mock
import zipfile

# Silence undesired warning
orig_argv0 = sys.argv[0]
sys.argv[0] = os.path.basename(sys.argv[0]).removesuffix('.py')
import ota_utils
sys.argv[0] = orig_argv0

import ota_metadata_pb2
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


def _extract_image(f_payload, f_out, block_size, blob_offset, partition,
                   cancel_signal):
    '''
    Extract the partition image from <f_payload> to <f_out> by processing the
    manifests list of install operations.
    '''

    Type = update_metadata_pb2.InstallOperation.Type

    for op in partition.operations:
        for extent in op.dst_extents:
            if cancel_signal.is_set():
                raise Exception('Interrupted')

            f_payload.seek(blob_offset + op.data_offset)
            f_out.seek(extent.start_block * block_size)
            h_data = hashlib.sha256()

            if op.type == Type.REPLACE:
                util.copyfileobj_n(f_payload, f_out, op.data_length,
                                   hasher=h_data)
            elif op.type == Type.REPLACE_BZ:
                decompressor = bz2.BZ2Decompressor()
                util.decompress_n(decompressor, f_payload, f_out,
                                  op.data_length, hasher=h_data)
            elif op.type == Type.REPLACE_XZ:
                decompressor = lzma.LZMADecompressor()
                util.decompress_n(decompressor, f_payload, f_out,
                                  op.data_length, hasher=h_data)
            elif op.type == Type.ZERO or op.type == Type.DISCARD:
                util.zero_n(f_out, extent.num_blocks * block_size)
            else:
                raise Exception(f'Unsupported operation: {op.type}')

            if h_data.digest() != op.data_sha256_hash and op.type != Type.ZERO:
                raise Exception('Expected hash %s, but got %s' %
                                (h_data.hexdigest(),
                                 binascii.hexlify(op.data_sha256_hash)))


def extract_images(f, manifest, blob_offset, output_dir, partition_names):
    '''
    Extract the specified partition images from the payload into <output_dir>.

    If <f> is callable, then it should produce a new file object each time it
    is called. This allows extracting images in parallel.
    '''

    remaining = set(partition_names)
    max_workers = len(remaining)
    cancel_signal = threading.Event()
    futures = []

    if not callable(f):
        f_orig = f

        @contextlib.contextmanager
        def dummy():
            yield f_orig

        f = dummy
        max_workers = 1

    def extract(p):
        output_path = os.path.join(output_dir, p.partition_name + '.img')

        with (
            f() as f_in,
            open(output_path, 'wb') as f_out,
        ):
            _extract_image(f_in, f_out, manifest.block_size, blob_offset, p,
                           cancel_signal)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers) as executor:
        try:
            for p in manifest.partitions:
                if p.partition_name not in remaining:
                    continue

                remaining.remove(p.partition_name)

                futures.append(executor.submit(extract, p))

            for future in concurrent.futures.as_completed(futures):
                future.result()
        except BaseException:
            cancel_signal.set()
            raise

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


def _sign_hash(hash, key, passphrase, max_sig_size):
    '''
    Sign <hash> with <key> and return a Signatures protobuf struct with the
    signature padded to <max_sig_size>.
    '''

    hash_signed = openssl.sign_data(key, passphrase, hash)
    assert len(hash_signed) <= max_sig_size

    signature = update_metadata_pb2.Signatures.Signature()
    signature.unpadded_signature_size = len(hash_signed)
    signature.data = hash_signed + b'\0' * (max_sig_size - len(hash_signed))

    signatures = update_metadata_pb2.Signatures()
    signatures.signatures.append(signature)

    return signatures


def _serialize_protobuf(p):
    return p.SerializeToString(deterministic=True)


def patch_payload(f_in, f_out, version, manifest, blob_offset, temp_dir,
                  patched, file_size, key, passphrase):
    '''
    Copy the payload from <f_in> to <f_out>, updating references to <patched>
    images as they are encountered. <f_out> will be signed with <key>.
    '''

    max_sig_size = openssl.max_signature_size(key, passphrase)

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
    dummy_sig = _sign_hash(hashlib.sha256().digest(), key, passphrase,
                           max_sig_size)
    dummy_sig_size = len(_serialize_protobuf(dummy_sig))

    # Fill out new payload signature information
    manifest.signatures_offset = blob_size
    manifest.signatures_size = dummy_sig_size

    # Build new manifest
    manifest_raw_new = _serialize_protobuf(manifest)

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
    metadata_sig = _sign_hash(metadata_hash, key, passphrase, max_sig_size)
    write(h_full, _serialize_protobuf(metadata_sig))

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
    payload_sig = _sign_hash(h_partial.digest(), key, passphrase, max_sig_size)
    write(h_full, _serialize_protobuf(payload_sig))

    # Generate properties file
    metadata_offset = len(OTA_MAGIC) + struct.calcsize('!QQI')
    metadata_size = metadata_offset + len(manifest_raw_new)
    blob_size = manifest.signatures_offset + manifest.signatures_size
    new_file_size = metadata_size + dummy_sig_size + blob_size

    def b64(d): return base64.b64encode(d)
    props = [
        b'FILE_HASH=%s\n' % b64(h_full.digest()),
        b'FILE_SIZE=%d\n' % new_file_size,
        b'METADATA_HASH=%s\n' % b64(metadata_hash),
        b'METADATA_SIZE=%d\n' % metadata_size,
    ]

    return b''.join(props)


def _get_property_files():
    '''
    Return the set of property files to add to the OTA metadata files.
    '''

    return (
        ota_utils.AbOtaPropertyFiles(),
        ota_utils.StreamingPropertyFiles(),
    )


def _serialize_metadata(metadata):
    '''
    Generate the legacy plain-text and protobuf serializations of the given
    metadata instance.
    '''

    legacy_metadata = ota_utils.BuildLegacyOtaMetadata(metadata)
    legacy_metadata_str = "".join([f'{k}={v}\n' for k, v in
                                   sorted(legacy_metadata.items())])
    metadata_bytes = _serialize_protobuf(metadata)

    return legacy_metadata_str.encode('UTF-8'), metadata_bytes


_FileRange = collections.namedtuple(
    '_FileRange', ('start', 'end', 'data_or_fp'))


class _ConcatenatedFileDescriptor:
    '''
    A read-only seekable file descriptor that presents several file descriptors
    or byte arrays as a single concatenated file.
    '''

    def __init__(self):
        # List of (start, end, data_or_fp)
        self.ranges = []
        self.offset = 0

    def _get_range(self):
        for range in self.ranges:
            if self.offset >= range.start and self.offset < range.end:
                return range

        return None

    def _eof_offset(self):
        return self.ranges[-1].end if self.ranges else 0

    def add_file(self, fp):
        start = self._eof_offset()
        self.ranges.append(_FileRange(start, start + fp.tell(), fp))

    def add_bytes(self, data):
        start = self._eof_offset()
        self.ranges.append(_FileRange(start, start + len(data), data))

    def read(self, size=None):
        buf = b''

        while size is None or size > 0:
            range = self._get_range()
            if not range:
                break

            to_read = range.end - self.offset
            if size is not None:
                to_read = min(to_read, size)
            data_offset = self.offset - range.start

            if isinstance(range.data_or_fp, bytes):
                data = range.data_or_fp[data_offset:data_offset + to_read]
            else:
                range.data_or_fp.seek(data_offset)
                data = range.data_or_fp.read(to_read)

            if not buf:
                buf = data
            else:
                buf += data

            if len(data) < to_read:
                if range is not self.ranges[-1]:
                    raise Exception('Unexpected EOF')
                else:
                    break

            if size is not None:
                size -= to_read

        return buf

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.offset = offset
        elif whence == os.SEEK_CUR:
            self.offset += offset
        elif whence == os.SEEK_END:
            self.offset = self._eof_offset() + offset
        else:
            raise ValueError(f'Invalid whence: {whence}')

    def tell(self):
        return self.offset


class _MemoryFile(io.BytesIO):
    '''
    Subclass of io.BytesIO where seeking can be conditionally disabled.
    '''

    def __init__(self, *args, allow_seek=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.allow_seek = allow_seek

    def seek(self, *args, **kwargs):
        if not self.allow_seek:
            raise AttributeError('seek is not supported')

        return super().seek(*args, **kwargs)


class _FakeZipFile:
    '''
    A wrapper around a ZipFile instance that allows appending new entries in
    memory without modifying the backing file.

    NOTE: The underlying ZipFile's file descriptor's position may be changed.
    '''

    def __init__(self, z):
        self.zip = z

        self.fp = _ConcatenatedFileDescriptor()

        # We have a seekable underlying file descriptor to the zip, but we
        # intentionally don't allow _TeeFileDescriptor to be seekable to
        # guarantee that ZipFile writes sequentially.
        self.orig_fp = self.zip.fp
        if isinstance(self.orig_fp, _TeeFileDescriptor):
            self.orig_fp = self.orig_fp.backing

        self.fp.add_file(self.orig_fp)

        self.next_offset = self.zip.start_dir

        self.extra_infos = {}

    def getinfo(self, name):
        if name in self.extra_infos:
            return self.extra_infos[name]
        else:
            return self.zip.getinfo(name)

    def namelist(self):
        return self.zip.namelist() + list(self.extra_infos.keys())

    def add_file(self, info, data):
        # Disable seeking to ensure that data descriptors are written, like the
        # backing ZipFile
        with _MemoryFile(allow_seek=False) as mem:
            with zipfile.ZipFile(mem, 'w') as z:
                with z.open(info, 'w') as f:
                    f.write(data)

                # Capture local file header, data, and data descriptor
                buf_without_footer = mem.getvalue()
                self.fp.add_bytes(buf_without_footer)

                # Fix offset and add to fake entries
                new_info = z.infolist()[-1]
                new_info.header_offset = self.next_offset
                self.extra_infos[new_info.filename] = new_info

                self.next_offset += len(buf_without_footer)


def add_metadata(z_out, metadata_info, metadata_pb_info, metadata_pb_raw):
    '''
    Add metadata files to the output OTA zip. <metadata_info> and
    <metadata_pb_info> should be the ZipInfo instances associated with the
    files from the original OTA zip. <metadata_pb_raw> should be the serialized
    OTA metadata protobuf struct from the original OTA.

    The zip file's backing file position MUST BE set to where the central
    directory would start.
    '''

    metadata = ota_metadata_pb2.OtaMetadata()
    metadata.ParseFromString(metadata_pb_raw)

    metadata.property_files.clear()

    props = _get_property_files()

    # Create a fake zip instance that allows appending new entries in memory so
    # that ota_utils can compute offsets for the property files
    fake_zip = _FakeZipFile(z_out)

    # Compute initial property files with reserved space as placeholders to
    # store the self-referential metadata entries later
    for p in props:
        metadata.property_files[p.name] = p.Compute(fake_zip)

    # Add the placeholders to the fake zip to compute final property files
    new_metadata_raw, new_metadata_pb_raw = _serialize_metadata(metadata)
    fake_zip.add_file(metadata_info, new_metadata_raw)
    fake_zip.add_file(metadata_pb_info, new_metadata_pb_raw)

    # Compute the final property files using the offsets of the fake entries
    for p in props:
        metadata.property_files[p.name] = \
            p.Finalize(fake_zip, len(metadata.property_files[p.name]))

    # Offset computation changes the file offset of the actual file. Seek back
    # to where the next entry or central directory would go
    fake_zip.orig_fp.seek(z_out.start_dir)

    # Add the final metadata files to the real zip
    new_metadata_raw, new_metadata_pb_raw = _serialize_metadata(metadata)
    with z_out.open(metadata_info, 'w') as f:
        f.write(new_metadata_raw)
    with z_out.open(metadata_pb_info, 'w') as f:
        f.write(new_metadata_pb_raw)

    return metadata


def verify_metadata(z, metadata):
    '''
    Verify that the offsets and file sizes within the metadata file properties
    of a fully written OTA zip are correct.
    '''

    for p in _get_property_files():
        p.Verify(z, metadata.property_files[p.name].strip())


class _TeeFileDescriptor:
    '''
    A file-like instance that propagates writes to multiple streams.

    start_capture() is used to pause output and divert writes to a memory
    buffer until _finish_capture(), which can modify the buffer.
    '''

    def __init__(self, streams, file_index=None):
        self.streams = streams
        self.capture = None
        self.backing = None if file_index is None else streams[file_index]

    def write(self, data):
        if self.capture:
            self.capture.write(data)
        else:
            for stream in self.streams:
                # Naive hole punching to create sparse files
                if stream is self.backing and util.is_zero(data):
                    stream.seek(len(data), os.SEEK_CUR)
                else:
                    stream.write(data)

        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()

    def tell(self):
        if self.backing is None:
            # Fake non-existance
            raise AttributeError('tell is not supported')

        capture_len = self.capture.tell() if self.capture else 0
        return self.backing.tell() + capture_len

    def start_capture(self):
        if self.capture is not None:
            raise RuntimeError('Capture already started')

        self.capture = _MemoryFile()

    @contextlib.contextmanager
    def _finish_capture(self):
        if not self.capture:
            raise RuntimeError('No capture started')

        yield self.capture

        for stream in self.streams:
            stream.write(self.capture.getbuffer())

        self.capture.close()
        self.capture = None


@contextlib.contextmanager
def open_signing_wrapper(f, privkey, passphrase, cert):
    '''
    Create a file-like wrapper around an existing file object that performs CMS
    signing as data is being written.
    '''

    with openssl.inject_passphrase(passphrase):
        session_kwargs = {}
        if os.name != 'nt':
            # We don't want the controlling terminal to interrupt openssl on
            # ^C or ^\. That'll cause _TeeFileDescriptor's writes to the stdin
            # pipe to fail, and certain classes, like ZipFile, will write to
            # the fd in their __exit__ methods. This causes a BrokenPipeError
            # to be raised while the existing KeyboardInterrupt is being
            # propagated up. We'll handling killing openssl ourselves.
            session_kwargs['start_new_session'] = True

        process = subprocess.Popen(
            [
                'openssl',
                'cms',
                '-sign',
                '-binary',
                '-outform', 'DER',
                '-inkey', privkey,
                '-signer', cert,
                # Mimic signapk behavior by excluding signed attributes
                '-noattr',
                '-nosmimecap',
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            **session_kwargs,
        )

    try:
        wrapper = _TeeFileDescriptor((f, process.stdin), file_index=0)
        yield wrapper

        with wrapper._finish_capture() as f_buffer:
            # Save a copy of the zip central directory
            f_buffer.seek(0)
            footer = f_buffer.read()

            # Delete the archive comment size field
            if len(footer) < 2:
                raise Exception('zip central directory is too small')
            elif footer[-2:] != b'\x00\x00':
                raise Exception('zip has unexpected archive comment')

            f_buffer.seek(-2, os.SEEK_CUR)
            f_buffer.truncate(f_buffer.tell())

        process.stdin.close()
        signature = process.stdout.read()
    except BaseException:
        process.kill()
        raise
    finally:
        process.wait()

    if process.returncode != 0:
        raise Exception(f'openssl exited with status: {process.returncode}')

    # Double check that the EOCD magic is where it should be when there is no
    # archive comment
    if footer[-22:-18] != zipfile.stringEndArchive:
        raise Exception('EOCD magic not found')

    # Build a new archive comment that contains the signature
    with io.BytesIO() as comment:
        message = b'signed by avbroot\0'
        comment.write(message)
        comment.write(signature)

        comment_size = comment.tell() + 6

        if comment_size > 0xffff:
            raise Exception('Archive comment with signature is too large')

        comment.write(struct.pack(
            '<HHH',
            # Absolute value of the offset of the signature from the end of the
            # archive comment
            comment_size - len(message),
            0xffff,
            comment_size,
        ))

        # Verify that we won't be producing a duplicate EOCD magic
        if zipfile.stringEndArchive in comment.getbuffer():
            raise Exception('Archive comment contains EOCD magic')

        # Write comment size to output file (which was removed before)
        f.write(struct.pack('<H', comment_size))

        # Write comment to output file
        f.write(comment.getbuffer())


@contextlib.contextmanager
def match_android_zip64_limit():
    '''
    Python's ZipFile implementation uses zip64 when the size of an entry is >
    0x7fffffff. However, Android's libarchive behavior is incorrect [1] and
    treats the data descriptor size fields as 32-bit unless the compressed or
    uncompressed size in the central directory is >= 0xffffffff. This causes
    files containing entries with sizes in [2 GiB, 4 GiB - 2] to fail to flash
    in Android's recovery environment. Work around this by changing ZipFile's
    threshold to match Android's.

    [1] https://cs.android.com/android/platform/superproject/+/android-13.0.0_r18:system/libziparchive/zip_archive.cc;l=692
    '''

    # Because Python uses > and Android uses >= 0xffffffff
    with unittest.mock.patch('zipfile.ZIP64_LIMIT', 0xfffffffe):
        yield
