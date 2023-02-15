# avbroot tests

avbroot's output files are reproducible for the given input files. [`tests.conf`](./tests.conf) lists some OTA images with unique properties and the expected checksums before and after patching. These tests use pregenerated, hardcoded test keys for signing. **These keys should NEVER be used for any other purpose.**

For each image listed in the config, the test process will:

1. Download the OTA if it doesn't already exist in `tests/files/<device>/`
2. Verify the OTA checksum
3. Run avbroot against the OTA
4. Verify the patched OTA checksum

## Running the tests

aria2 must be installed before running the tests. It is used for downloading the OTA images.

To test against all of the device OTA images listed in [`tests.conf`](./tests.conf), run:

```bash
python tests/tests.py
```

To only run the tests for a specific device, pass in `-d <device>`. This argument can be specified multiple times (eg. `-d GooglePixel7Pro -d GooglePixel6a`).

To pass in extra arguments to `aria2c`, use `-a=<arg>`. This can be used to enable concurrent downloads (eg. `-a=-x4 -a=-s4`).

## Running the tests in a container

The tests can also be run inside a podman container for easy testing on various Linux distros. To do so, run:

```bash
python tests/tests_containerized.py
```

This will build all of the images defined in [`distros/Containerfile.<distro>`](./distros/) and run the tests inside new container instances concurrently. By default, the number of concurrent jobs is set to the number of CPUs. This can be changed with `-j <num>`.

To only run tests against a specific set of distro images, use `-d <distro>`, which can be specified multiple times. All arguments after a `--` argument are passed to `tests.py` directly.

For example, to test patching the Google Pixel 7 Pro OTA against the Fedora and Arch images, run:

```bash
python tests/tests_containerized.py -d fedora -d arch -- -d GooglePixel7Pro
```
