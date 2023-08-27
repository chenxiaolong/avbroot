# End-to-end tests

avbroot's output file is reproducible for a given input file. [`e2e.toml`](./e2e.toml) lists some OTA images with unique properties and the expected checksums before and after patching. These tests use pregenerated, hardcoded test keys for signing. **These keys should NEVER be used for any other purpose.**

For each image listed in the config, the test process will:

1. Download the OTA if it doesn't already exist in `./files/<device>/` (or the workdir specified by `-w`)
2. Verify the OTA checksum
3. Run avbroot against the OTA using `--magisk`
4. Extract the AVB-related partitions from the patched OTA and verify their checksums
5. Verify the patched OTA checksum
6. Run avbroot against the OTA again using `--prepatched`
7. Verify the patched OTA checksum again

For more efficient CI testing, the tests can operate on "stripped" OTAs. A stripped OTA is identical to the full OTA, except that partitions in `payload.bin` unrelated to AVB are zeroed out. This reduces the download size and disk space requirements by a couple orders of magnitude. **A stripped OTA is NOT bootable and should never be flashed on a real device.**

## Running the tests

To test against the device OTA images listed in [`e2e.toml`](./e2e.toml), run:

```bash
# To test all device OTAs
cargo run --release -- test -a
# Or to test against specific device OTAs
cargo run --release -- test -d cheetah -d bluejay
```

To test against stripped OTAs (smaller download, but not bootable), pass in `--stripped`.

## Downloading a device image

To download a full OTA image, run:

```bash
cargo run --release -- download -d <device>
```

This normally happens automatically when running the `test` subcommand. To download the stripped OTA image instead, pass in `--stripped`.

If the image file does not already exist, then it will be downloaded and the checksums will be validated. If the download is interrupted, it will automatically resume when the command is rerun. If the file is already downloaded, the command is effectively a no-op unless `--revalidate` is passed in to revalidate the image checksums.

## Adding a new device image

To add a new device image to the testing configuration, run:

```bash
cargo run --release -- add -d <device> -u <full OTA URL> -H <expected checksum>
```

If the OS vendor does not provide a SHA-256 checksum, omit `-H` and the program will compute the checksum from the downloaded data.

This process will download the full OTA, strip it, patch the full OTA, patch the stripped OTA, extract the AVB partitions, and write all of the checksums to [`e2e.toml`](./e2e.toml).

The process for updating an existing device config is exactly the same as adding a new one.

## Stripping a full OTA

To convert a full OTA to the stripped form, run:

```bash
cargo run --release -- strip -i <input zip> -o <output zip>
```

This normally happens automatically as a part of adding a new device image.
