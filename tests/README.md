# avbroot tests

avbroot's output files are reproducible for the given input files. [`tests.yaml`](./tests.yaml) lists some OTA images with unique properties and the expected checksums before and after patching. These tests use pregenerated, hardcoded test keys for signing. **These keys should NEVER be used for any other purpose.**

For each image listed in the config, the test process will:

1. Download the OTA if it doesn't already exist in `tests/files/<device>/` (or the workdir specified by `-w`)
2. Verify the OTA checksum
3. Run avbroot against the OTA using `--magisk`
4. Extract the AVB-related partitions from the patched OTA and verify their checksums
5. Verify the patched OTA checksum
6. Run avbroot against the OTA again using `--prepatched`
7. Verify the patched OTA checksum again

For more efficient CI testing, the tests can operate on "stripped" OTAs. A stripped OTA is identical to the full OTA, except that partitions in `payload.bin` unrelated to AVB are zeroed out. This reduces the download size and disk space requirements by a couple orders of magnitude. **A stripped OTA is NOT bootable and should never be flashed on a real device.**

## Running the tests

To test against the device OTA images listed in [`tests.yaml`](./tests.yaml), run:

```bash
# To test all device OTAs
python tests/tests.py test -a
# Or to test against specific device OTAs
python tests/tests.py test -d cheetah -d bluejay
```

To test against stripped OTAs (smaller download, but not bootable), pass in `--stripped`.

## Running the tests in a container

The tests can also be run inside a podman container for easy testing on various Linux distros. To do so, run:

```bash
python tests/tests_containerized.py
```

This will build all of the images defined in [`distros/Containerfile.<distro>`](./distros/) and run the tests inside new container instances concurrently. By default, the number of concurrent jobs is set to the number of CPUs. This can be changed with `-j <num>`.

To only run tests against a specific set of distro images, use `-d <distro>`, which can be specified multiple times. All arguments after a `--` argument are passed to `tests.py` directly.

For example, to test patching the `cheetah` OTA against the Fedora and Arch images, run:

```bash
python tests/tests_containerized.py -d fedora -d arch -- -d cheetah
```

## Downloading a device image

To download a full OTA image, run:

```bash
python tests/tests.py download -d <device>
```

This normally happens automatically when running [`tests.py`](./tests.py). To download the stripped OTA image instead, pass in `--stripped`.

If the image file does not already exist, then it will be downloaded and the checksums will be validated. If the download is interrupted, it will automatically resume when the command is rerun. If the file is already downloaded, the command is effectively a no-op unless `--revalidate` is passed in to revalidate the image checksums.

## Adding a new device image

To add a new device image to the testing configuration, run:

```bash
python tests/tests.py add -d <device> -u <full OTA URL> -H <expected checksum>
```

If the OS vendor does not provide a SHA-256 checksum, omit `-H` and the script will compute the checksum from the downloaded data.

This process will download the full OTA, strip it, patch the full OTA, patch the stripped OTA, extract the AVB partitions, and write all of the checksums to [`tests.yaml`](./tests.yaml).

The process for updating an existing device config is exactly the same as adding a new one.

(Note: Due to how the strictyaml library handles comments, this might cause some comments in the config file to be removed. They'll need to be added back manually.)

## Stripping a full OTA

To convert a full OTA to the stripped form, run:

```bash
python tests/tests.py strip -i <input zip> -o <output zip>
```

This normally happens automatically as a part of adding a new device image.
