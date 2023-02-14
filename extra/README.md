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
