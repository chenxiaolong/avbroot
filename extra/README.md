# avbroot extra

This directory contains some extra scripts that aren't required for avbroot's operation, but may be useful for troubleshooting.

## `bootimagetool`

This is a frontend to the [`avbroot/formats/bootimage.py`](../avbroot/formats/bootimage.py) library for working with boot images.

### Unpacking a boot image

```bash
python bootimagetool.py unpack <input boot image>
```

This subcommand unpacks all of the components of the boot image into the current directory by default (see `--help`). The header fields are saved to `header.json` and each blob section is saved to a separate file. Each blob is written to disk as-is, without decompression.

### Packing a boot image

```bash
python bootimagetool.py pack <output boot image>
```

This subcommand packs a new boot image from the individual components in the current directory by default (see `--help`). The default input filenames are the same as the output filenames for the `unpack` subcommand.

### Repacking a boot image

```bash
python bootimagetool.py repack <input boot image> <output boot image>
```

This subcommand repacks a boot image without writing the individual components to disk first. This is useful for roundtrip testing of avbroot's boot image parser. The output should be identical to the input, minus any footers, like the AVB footer. The only exception is the VTS signature for v4 boot images, which is always stripped out.

## `cpiotool`

This is a frontend to the [`avbroot/formats/compression.py`](../avbroot/formats/compression.py) and [`avbroot/formats/cpio.py`](../avbroot/formats/cpio.py) libraries. It is useful for inspecting compressed and uncompressed cpio archives.

### Dumping a cpio archive

```bash
python cpiotool.py dump <cpio archive>
```

This subcommand dumps all information about a cpio archive to stdout. This includes the compression format, all header fields (including the trailer entry), and all data. If an entry's data can be decoded as UTF-8, then it is printed out as text. Otherwise, the binary data is printed out base64-encoded. The base64-encoded data is truncated to 5 lines by default to avoid outputting too much data, but this behavior can be disabled with `--no-truncate`.

### Repacking a cpio archive

```bash
python cpiotool.py repack <input cpio archive> <output cpio archive>
```

This subcommand repacks a cpio archive, including recompression if needed. This is useful for roundtrip testing of avbroot's cpio parser and compression handling. The uncompressed output should be identical to the uncompressed input, except:

* files are sorted by name
* inodes are reassigned, starting from 300000
* there is no excess padding at the end of the file

The compressed output may differ from what other tools produce because:

* LZ4 legacy chunks are packed to exactly 8 MiB, except for the last chunk, which may be smaller.
* LZ4 legacy uses the high compression mode with a compression level of 12.
* The GZIP header has the modification timestamp set to 0 (Unix epoch time).
* GZIP uses a compression level of 9.
