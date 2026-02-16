# avbroot extra

avbroot includes several feature-complete parsers for various things, like boot images. Some of these are exposed as extra subcommands. They aren't needed for normal OTA patching, but may be useful in other scenarios.

Note that while avbroot maintains a stable command line interface for the patching-related subcommands, these extra subcommands do not have backwards compatibility guarantees.

## `avbroot avb`

### Unpacking an AVB image

```bash
avbroot avb unpack -i <input AVB image>
```

This subcommand unpacks the vbmeta header and footer into `avb.toml`. If a footer is present, then the corresponding raw partition image is extracted into `raw.img`. Root vbmeta images (eg. `vbmeta` and `vbmeta_vendor`) do not have footers, while appended vbmeta images (eg. `boot` and `system`) do.

The vbmeta descriptor digests are validated during unpacking. For dm-verity images, if the image is corrupt, avbroot will attempt to use the FEC data to repair the file. If there is unrepairable data corruption, the command will fail, though the corrupted `raw.img` will still be fully written. If, for whatever reason, a successful exit status of 0 is needed even for corrupted files, use `--ignore-invalid`.

### Packing an AVB image

```bash
avbroot avb pack -o <output AVB image> [-k <AVB private key>]
```

This subcommand packs a new AVB image from the `avb.toml` file and, for appended vbmeta images, the `raw.img` file.

* If the original image was signed and the new data is unmodified, then the original signature is used as-is. (This means just unpacking and packing an image will always result in a byte-for-byte identical file.)
* If the original image was signed and the new data is modified, then the newly packed image will be signed with the `--key`.
* If the original image was not signed, then the newly packed image is not signed.
* To force an image to be signed, use `--key <path> --force`.
* To force an image to be unsigned, use `--force` without specifying `--key`.

By default, for appended vbmeta images, the output image size will match the size of the original image that was unpacked. This size is specified by the `image_size` field in `avb.toml`. If the image is resizable (eg. `system`), then passing in `--recompute-size` will cause the `image_size` field to be ignored and the smallest possible output file that fits the raw image and AVB metadata will be built. This avoids wasting space if `raw.img` shrunk or allows the packing to work at all if `raw.img` grew. **Do not use this option for non-resizable images** (eg. `boot`) or else the device won't be able to boot.

When packing an image, several of the fields in `avb.toml` may potentially be recomputed. To write a TOML file containing the new values, use `--output-info <output TOML>`. It is safe to overwrite the existing `avb.toml` if desired.

### Repacking an AVB image

```bash
avbroot avb repack -i <input AVB image> -o <output AVB image>
```

This subcommand is equivalent to `avbroot avb unpack` followed by `avbroot avb pack`, except it doesn't need to write any intermediate files to disk.

This is useful for repairing a dm-verify image or for re-signing any image with a specific key.

### Showing vbmeta header and footer information

```bash
avbroot avb info -i <image>
```

This subcommand shows all of the vbmeta header and footer fields. `vbmeta` partition images will only have a header, while partitions with actual data (eg. boot images) will have both a header and a footer.

(The `unpack`, `pack`, and `repack` subcommands also show this information. This specific subcommand just does so without performing any other operation.)

### Verifying AVB hashes and signatures

```bash
avbroot avb verify -i <root vbmeta image> -p <public key>
```

This subcommand verifies the vbmeta header signature and the hashes for all vbmeta descriptors (including hash tree descriptors). If the vbmeta image has a chain descriptor for another partition, that partition image will be verified as well (recursively). All images are expected to be in the same directory as the vbmeta image being verified. Missing images are ignored by default because the vbmeta images in some OTAs reference partitions that only exist on a real device. `--fail-if-missing` can be used to override this.

If `-p` is omitted, the signatures and hashes are checked only for validity, not that they are trusted.

By default, this command will not write to any file and fails if an image is corrupt or invalid. To attempt to repair corrupted dm-verity images, pass in `--repair`.

### Verifying AVB hashes and signatures on device

```bash
# Run from a root adb shell:
avbroot avb verify-device [-p <public key>]
```

This subcommand is like `avbroot avb verify`, except that it verifies the actual partitions on the device instead of a directory of image files. This is only available in the Android build of avbroot.

If `-p` is omitted, the signatures are verified against the public key SHA-256 digest reported by the bootloader. This is the same digest shown on screen every time the device boots.

### Computing vbmeta digest

```bash
avbroot avb digest -i <root vbmeta image>
```

This subcommand computes the vbmeta digest, which is defined as the SHA256 digest of the root vbmeta partition's header, followed by the chained partitions' headers (if any) in the order that they are listed. Chained partitions more than one level deep are ignored.

This digest is equal to the value of the `ro.boot.vbmeta.digest` property or the `RootOfTrust.verifiedBootHash` hardware attestation field.

## `avbroot boot`

### Unpacking a boot image

```bash
avbroot boot unpack -i <input boot image>
```

This subcommand unpacks all of the components of the boot image into the current directory by default (see `--help`). The header fields are saved to `boot.toml` and each blob section is saved to a separate file. Each blob is written to disk as-is, without decompression.

### Packing a boot image

```bash
avbroot boot pack -o <output boot image>
```

This subcommand packs a new boot image from the individual components in the current directory by default (see `--help`). The default input filenames are the same as the output filenames for the `unpack` subcommand.

### Repacking a boot image

```bash
avbroot boot repack -i <input boot image> -o <output boot image>
```

This subcommand repacks a boot image without writing the individual components to disk first. This is useful for roundtrip testing of avbroot's boot image parser. The output should be identical to the input, minus any footers, like the AVB footer.

### Showing information about a boot image

```bash
avbroot boot info -i <input boot image>
```

This subcommand shows the information contained in the boot image's header. To show avbroot's internal representation of the information, pass in `-d`.

(All of the `boot` subcommands show this information. This specific subcommand just does so without performing any other operation.)

## `avbroot cpio`

### Unpacking a cpio archive

```bash
avbroot cpio unpack -i <input cpio archive>
```

This subcommand unpacks the cpio archive. The list of file entries and their metadata, like permissions, are written to `cpio.toml`. The contents of regular files are extracted to `cpio_tree/`. Other file types, like symlinks and block devices, are not extracted at all. Their information only exists in the TOML file.

The files inside the tree will have default permissions, ownership, and modification timestamps. This metadata exists only inside the TOML file in order to ensure that the behavior is the same across all platforms.

Both uncompressed archives and compressed archives (gzip or legacy lz4) are supported.

### Packing a cpio archive

```bash
avbroot cpio pack -o <output cpio archive>
```

This subcommand packs a new cpio archive from the file entries listed in `cpio.toml` and the file contents in `cpio_tree/`. Note that **only entries listed in the TOML file are packed**. Extra files inside the tree are silently ignored.

The files are packed in the order listed in the TOML file. When packing ramdisks specifically, it's important to ensure that files are listed after their parent directories (which also **must** exist). Otherwise, the kernel will ignore them. As long as the file paths don't contain anything weird (eg. `a//b` or `a/./b`), sorting the entires with `--sort` should do the trick.

The new archive will be written in the same format (compressed or uncompressed) as the original archive.

### Repacking a cpio archive

```bash
avbroot cpio repack -i <input cpio archive> -o <output cpio archive>
```

This is almost equivalent to running `avbroot cpio unpack` followed by `avbroot cpio pack`, except inode numbers will not be reassigned.

### Showing information about a cpio archive

```bash
avbroot cpio info -i <input cpio archive>
```

This subcommand shows details about every entry in the archive.

(All of the `cpio` subcommands show this information. This specific subcommand just does so without performing any other operation.)

## `avbroot fec`

This set of commands is for working with dm-verity FEC (forward error correction) data. The FEC data allows small errors in partition data to be corrected. This increases reliability of the system because when dm-verity encounters data that doesn't match the expected checksum, it will either trigger a kernel panic or reboot the system.

The same raw FEC data can be stored in several ways:

* cryptsetup's `veritysetup` does not use any file format at all. It must be told the FEC location and parameters using the `--fec-*` options.
* AOSP's AVB 2.0 stores the FEC data inside the partition as `[Partition data][Hash tree][FEC data]`. The location and parameters are stored in the vbmeta hash tree descriptors.
* AOSP's `fec` tool stores the FEC data in a standalone file with a header containing the FEC parameters.

The `avbroot fec` commands use AOSP's standalone FEC file format.

The FEC data is not generated from a sequential read of the input file, but rather from an interleaved read. If the input file's offsets are visualized as a 2D table:

```
| 0    1    2    3    ... 4095  |
| 4096 4097 4098 4099 ... 8191  |
| 8192 8193 8194 8195 ... 12287 |
| .... .... .... .... ... ..... |
```

then the file access pattern can be thought of as being column-by-column instead of row-by-row.

Data correction happens at the codeword level. A Reed-Solomon codeword is 255 bytes where some portion is file data and the rest is parity data. AOSP and avbroot both default to 253 bytes of data and 2 bytes of parity information. Each column in the table represents the 253-byte data portion of the codeword. Larger files have more columns.

A contiguous sequence of corrupted data will span multiple columns. Since error correction happens at the column level, this interleaving increases the chances of recovery. For more details about the specifics, see the implementation in [`fec.rs`](./avbroot/src/format/fec.rs).

### Generating FEC data

```bash
avbroot fec generate -i <input data file> -f <output FEC file>
```

The default behavior is to use 2 bytes of parity information per 253 bytes of input data. Within each 253-byte column described above, this is sufficient for correcting a single corrupted byte in the column (`⌊parity / 2⌋` bytes in general).

The number of parity bytes (between 2 and 24, inclusive) can be configured using `--parity`.

### Updating FEC data

```bash
avbroot fec update -i <input data file> -f <FEC file> [-r <start> <end>]...
```

This will update the FEC data corresponding to the specified regions. This can be significantly faster than generating new FEC data from scratch for large files if the regions where data was modified are known.

### Verifying a file

```bash
avbroot fec verify -i <input data file> -f <input FEC file>
```

This will check if the input file has any corrupted bytes. This command runs significantly faster than `avbroot fec repair` and is useful if only detection of corrupted data is needed.

Note that FEC is **not** a replacement for checksums, like SHA-256. When there are too many errors, there can be false positives where the corrupted data is reported as being valid.

### Repairing a file

```bash
avbroot fec repair -i <input/output data file> -f <input FEC file>
```

This will repair the file in place. As described above, in each column, up to `parity / 2` bytes can be corrected.

Note that FEC is **not** a replacement for checksums, like SHA-256. When there are too many errors, the file can potentially be "successfully repaired" to some incorrect data.

## `avbroot hash-tree`

This set of commands is for working with dm-verity hash tree data. They are not especially useful outside of debugging avbroot itself because the output format is custom. There is a custom header that sits in front of the standard dm-verity hash tree data.

| Offsets    | Type   | Description                    |
|------------|--------|--------------------------------|
| 0..16      | ASCII  | `avbroot!hashtree` magic bytes |
| 16..18     | U16LE  | Version (currently 1)          |
| 18..26     | U64LE  | Image size                     |
| 26..30     | U32LE  | Block size                     |
| 30..46     | ASCII  | Hash algorithm                 |
| 46..48     | U16LE  | Salt size                      |
| 48..50     | U16LE  | Root digest size               |
| 50..54     | U32LE  | Hash tree size                 |
| (Variable) | BINARY | Salt                           |
| (Variable) | BINARY | Root digest                    |
| (Variable) | BINARY | Hash tree                      |

For more information on the hash tree data, see the [Linux kernel documentation](https://docs.kernel.org/admin-guide/device-mapper/verity.html#hash-tree) or avbroot's implementation in [`hashtree.rs`](./avbroot/src/format/hashtree.rs).

### Generating hash tree

```bash
avbroot hash-tree generate -i <input data file> -H <output hash tree file>
```

The default behavior is to use a block size of 4096, the `sha256` algorithm, and an empty salt. These can be changed with the `-b`, `-a`, and `-s` options, respectively.

All parameters needed for verification are included in the hash tree file's header.

### Updating hash tree

```bash
avbroot hash-tree update -i <input data file> -H <hash tree file> [-r <start> <end>]...
```

This will update the hash tree data corresponding to the specified regions. This can be significantly faster than generating new hash tree data from scratch for large files if the regions where data was modified are known.

### Verifying a file

```bash
avbroot hash-tree verify -i <input data file> -H <input hash tree file>
```

This will check if the input file has any corrupted blocks. Currently, the command cannot report which specific blocks are corrupted, only whether the file is valid.

## `avbroot lp`

This set of commands is for working with LP (logical partition) images. These are the containers for dynamically-allocated partitions, like `system`. All LP images are supported:

* Empty images: These are the `super_empty.img` images in the factory images for newer Google Pixel devices. They define the layout of the `super` partition, but don't contain any actual data. They also do not contain a backup copy of the metadata. As an optimization, `fastboot` can fill in the actual data during flashing to avoid needing to reboot to fastbootd mode.
* Normal images backed by a single device: These are standalone `super.img` images and are how logical partitions are physically stored on disk in most newer devices. They contain a backup copy of all metadata as well as actual partition data.
* Normal images backed by multiple devices: These are images split across multiple files/partitions and are used on devices where support for LP was retrofitted. For example, the LP setup on newer Android builds for the Google Pixel 3a XL reuse the legacy `system` and `vendor` partitions because there is no `super` partition. These are similar to the single-file LP setups, except that data can be stored across all of the LP images. However, the metadata is only stored on the first LP image.

### Unpacking an LP image

```bash
avbroot lp unpack -i <input LP image> [-i <input LP image>]...
```

This subcommand unpacks the LP metadata to `lp.toml` and the partition images to the `lp_images` directory (for normal images).

If there are multiple images, they must be specified in order. If the order is not known, run `avbroot lp info` on each of the images. The one that successfully parses is the first image and the `block_devices` field in the output specifies the full ordering.

An LP image can have multiple slots. If the LP image originated from a factory image or OTA, all slots are likely identical. If the LP image was dumped from a real device that installed OTA updates in the past, the slots may differ. If the slots are not identical, then the `--slot` option is required to specify which slot to unpack.

### Packing an LP image

```bash
avbroot lp pack -o <output LP image> [-o <output LP image>]...
```

This subcommand packs a new LP image from the `lp.toml` file and `lp_images` directory (for normal images). Any `.img` files in the `lp_images` directory that don't have a corresponding entry in `lp.toml` are silently ignored.

All metadata slots in the newly packed LP image will be identical.

### Repacking an LP image

```bash
avbroot lp repack -i <input LP image> [-i <input LP image>]... -o <output LP image> [-o <output LP image>]...
```

This subcommand is logically equivalent to `avbroot lp unpack` followed by `avbroot lp pack`, except more efficient. Instead of unpacking and packing all partition images, the raw data is directly copied from the old LP image to the new LP image.

When `--slot` is specified, this is useful for discarding unwanted metadata slots and the partition data exclusive to them.

### Showing LP image metadata

```bash
avbroot lp info -i <first LP image>
```

This subcommand shows the LP image metadata, including all metadata slots. If there are multiple images, only the first one is needed because it is the only one that stores the metadata.

(All of the `lp` subcommands show this information. This specific subcommand just does so without performing any other operation.)

## `avbroot payload`

This set of commands is for working with payload binary files (`payload.bin`). The `unpack` and `pack` commands can only work with full payloads because they require the complete data to be available, but the `repack` and `info` commands also work with delta payloads.

### Unpacking a payload binary

```bash
avbroot payload unpack -i <input payload>
```

This subcommand unpacks the payload header information to `payload.toml` and the partition images to the `payload_images` directory.

Only full payload binaries can be unpacked. Delta payload binaries from incremental OTAs are not supported.

### Packing a payload binary

```bash
avbroot payload pack -o <output payload> -k <OTA private key> [-O <output properties>]
```

This subcommand packs a new payload binary from the `payload.toml` file and `payload_images` directory. Any `.img` files in the `payload_images` directory that don't have a corresponding entry in `payload.toml` are silently ignored.

When replacing the payload binary in an OTA, it is not sufficient to only update `payload.bin`. The checksums in `payload_properties.txt` need to be updated as well. Use `--output-properties` to generate a new properties file.

Packing a payload binary requires compressing all of the partition images, which is very CPU intensive. If re-signing an existing payload binary without making any other modifications is all that's needed, use the `repack` subcommand instead.

### Repacking a payload binary

```bash
avbroot payload repack -i <input payload> -o <output payload> -k <OTA private key> [-O <output properties>]
```

This subcommand is logically equivalent to `avbroot payload unpack` followed by `avbroot payload pack`, except significantly more efficient. Instead of decompressing and recompressing all partition images, the raw data is directly copied from the input payload binary.

This is useful for re-signing a payload binary without making any other changes.

### Showing payload header information

```bash
avbroot payload info -i <payload>
```

This subcommand shows all of the payload header fields (which will likely be extremely long).

(All of the `payload` subcommands show this information. This specific subcommand just does so without performing any other operation.)

## `avbroot sparse`

This set of commands is for working with Android sparse images. All features of the file format are supported, including hole chunks and CRC32 checksums.

### Unpacking a sparse image

```bash
avbroot sparse unpack -o <input sparse image> -o <output raw image>
```

This subcommand unpacks a sparse image to a raw image. If the sparse image contains CRC32 checksums, they will be validated during unpacking. If the sparse image contains holes, the output image will be created as a native sparse file.

Certain fastboot factory images may have multiple sparse images, like `super_1.img`, `super_2.img`, etc., where they all touch a disjoint set of regions on the same partition. These can be unpacked by running this subcommand for each sparse image and specifying the `--preserve` option along with using the same output file. This preserves the existing data in the output file when unpacking each sparse image.

### Packing a sparse image

```bash
avbroot sparse pack -i <input raw image> -o <output sparse image>
```

This subcommand packs a new sparse image from a raw image. The default block size is 4096 bytes, which can be changed with the `--block-size` option.

By default, this will pack the entire input file. However, on Linux, there is an optimization where all holes in the input file, if it is a native sparse file, will be stored as hole chunks instead of `0`-filled chunks in the output sparse image.

To pack a partial sparse image, such as those used in the special fastboot factory images mentioned above, pass in `--region <start> <end>`. This option can be specified multiple times to pack multiple regions.

Unlike AOSP's `img2simg` tool, which never writes CRC32 checksums, this subcommand will write checksums if the input file has no holes and the entire file is being packed.

### Repacking a sparse image

```bash
avbroot sparse repack -i <input sparse image> -o <output sparse image>
```

This subcommand is logically equivalent to `avbroot sparse unpack` followed by `avbroot sparse pack`, except more efficient. This is useful for roundtrip testing of avbroot's sparse file parser.

### Showing sparse image metadata

```bash
avbroot sparse info -i <input sparse image>
```

This subcommand shows the sparse image metadata, including the header and all chunks.

(All of the `sparse` subcommands show this information. This specific subcommand just does so without performing any other operation.)

## `avbroot zip`

This set of commands is for working with raw OTA zip files. They are intentionally placed outside of `avbroot ota` to make them less discoverable by accident. These commands are useful for creating OTA zip files without going through the normal `avbroot ota patch` mechanism.

**WARNING**: Make sure to run `avbroot ota verify` on OTA files before installing them. These pack commands are low level operations that only check that the file structure of the OTA itself is valid, not the contents contained within.

### Unpacking an OTA zip

```bash
avbroot ota unpack -i <input OTA>
```

This subcommand unpacks the OTA metadata to `ota.toml` and the OTA files to the `ota_files` directory.

### Packing an OTA zip

```bash
avbroot ota pack -o <output OTA> -k <OTA private key>
```

This subcommand packs a new OTA zip from the `ota.toml` file and `ota_files` directory. Any files in the `ota_files` directory that don't have a corresponding entry in `ota.toml` are silently ignored.

When packing an OTA zip, the `metadata.property_files` field in `ota.toml` may potentially be recomputed. To write a TOML file containing the new values, use `--output-info <output TOML>`. It is safe to overwrite the existing `ota.toml` if desired.

### Repacking an OTA zip

```bash
avbroot ota repack -i <input OTA> -o <output OTA> -k <OTA private key>
```

This subcommand is logically equivalent to `avbroot ota unpack` followed by `avbroot ota pack`, except more efficient.

**WARNING**: This is generally not a useful command. Resigning the OTA zip without also resigning the payload binary inside results in an invalid OTA.

### Showing OTA metadata

```bash
avbroot ota info -i <input OTA>
```

This subcommand shows all of the OTA metadata fields. If both the modern protobuf metadata and the legacy plain text metadata exist, the protobuf metadata takes precedence.

(All of the `ota` subcommands show this information. This specific subcommand just does so without performing any other operation.)
