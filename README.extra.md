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
avbroot avb pack -o <output AVB image> [--key <AVB private key>]
```

This subcommand packs a new AVB image from the `avb.toml` file and, for appended vbmeta images, the `raw.img` file.

* If the original image was signed and the new data is unmodified, then the original signature is used as-is. (This means just unpacking and packing an image will always result in a byte-for-byte identical file.)
* If the original image was signed and the new data is modified, then the newly packed image will be signed with the `--key`.
* If the original image was not signed, then the newly packed image is not signed.
* To force an image to be signed, use `--key <path> --force`.
* To force an image to be unsigned, use `--force` without specifying `--key`.

Note that if the image is an appended image and its hash or hash tree descriptor uses an insecure algorithm, like `sha1`, then it will automatically be promoted to `sha256`.

By default, for appended vbmeta images, the output image size will match the size of the original image that was unpacked. This size is specified by the `image_size` field in `avb.toml`. If the image is resizable (eg. `system`), then passing in `--recompute-size` will cause the `image_size` field to be ignored and the smallest possible output file that fits the raw image and AVB metadata will be built. This avoids wasting space if `raw.img` shrunk or allows the packing to work at all if `raw.img` grew. **Do not use this option for non-resizable images** (eg. `boot`) or else the device won't be able to boot.

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

### Verifying AVB hashes and signatures

```bash
avbroot avb verify -i <root vbmeta image> -p <public key>
```

This subcommand verifies the vbmeta header signature and the hashes for all vbmeta descriptors (including hash tree descriptors). If the vbmeta image has a chain descriptor for another partition, that partition image will be verified as well (recursively). All partitions are expected to be in the same directory as the vbmeta image being verified.

If `-p` is omitted, the signatures and hashes are checked only for validity, not that they are trusted.

By default, this command will not write to any file and fails if an image is corrupt or invalid. To attempt to repair corrupted dm-verity images, pass in `--repair`.

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

All of the `boot` subcommands show the boot image information. This specific subcommand just does it without performing any other operation. To show avbroot's internal representation of the information, pass in `-d`.

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

All of the `cpio` subcommands show details about all the entries in the archive. This specific subcommand just does it without performing any other operation.

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
