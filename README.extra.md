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
