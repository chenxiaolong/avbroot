# avbroot extra

avbroot includes several feature-complete parsers for various things, like boot images. Some of these are exposed as extra subcommands. They aren't needed for normal OTA patching, but may be useful in other scenarios.

Note that while avbroot maintains a stable command line interface for the patching-related subcommands, these extra subcommands do not have backwards compatibility guarantees.

## `avbroot avb`

### Showing vbmeta header and footer information

```bash
avbroot avb dump -i <image>
```

This subcommand shows all of the vbmeta header and footer fields. `vbmeta` partition images will only have a header, while partitions with actual data (eg. boot images) will have both a header and a footer.

### Verifying AVB hashes and signatures

```bash
avbroot avb verify -i <root vbmeta image> -p <public key>
```

This subcommand verifies the vbmeta header signature and the hashes for all vbmeta descriptors (including hashtree descriptors). If the vbmeta image has a chain descriptor for another partition, that partition image will be verified as well (recursively). All partitions are expected to be in the same directory as the vbmeta image being verified.

If `-p` is omitted, the signatures and hashes are checked only for validity, not that they are trusted.

## `avbroot boot`

### Unpacking a boot image

```bash
avbroot boot unpack -i <input boot image>
```

This subcommand unpacks all of the components of the boot image into the current directory by default (see `--help`). The header fields are saved to `header.toml` and each blob section is saved to a separate file. Each blob is written to disk as-is, without decompression.

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

## `avbroot fec`

This set of commands is for working with dm-verity FEC (forward error correction) data. The FEC data allows small errors in partition data to be corrected. This increases reliability of the system because when dm-verity encounters data that doesn't match the expected checksum, it will either trigger a kernel panic or reboot the system.

The same raw FEC data can be stored in several ways:

* cryptsetup's `veritysetup` does not use any file format at all. It must be told the FEC location and parameters using the `--fec-*` options.
* AOSP's AVB 2.0 stores the FEC data inside the partition as `[Partition data][Hashtree][FEC data]`. The location and parameters are stored in the vbmeta hashtree descriptors.
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

## `avbroot ramdisk`

### Dumping a cpio archive

```bash
avbroot ramdisk dump -i <cpio archive>
```

This subcommand dumps all information about a cpio archive to stdout. This includes the compression format, all header fields (including the trailer entry), and all data. If an entry's data can be decoded as UTF-8, then it is printed out as text. Otherwise, the binary data is printed out `\x##`-encoded for non-ASCII bytes. The escape-encoded data is truncated to 512 bytes by default to avoid outputting too much data, but this behavior can be disabled with `--no-truncate`.

### Repacking a cpio archive

```bash
avbroot ramdisk repack -i <input cpio archive> -o <output cpio archive>
```

This subcommand repacks a cpio archive, including recompression if needed. This is useful for roundtrip testing of avbroot's cpio parser and compression handling. The uncompressed output should be identical to the uncompressed input, except:

* files are sorted by name
* inodes are reassigned, starting from 300000
* there is no excess padding at the end of the file

The compressed output may differ from what other tools produce due to differences in compression levels and header metadata. avbroot avoids specifying header information where possible (eg. gzip timestamp) for reproducibility.
