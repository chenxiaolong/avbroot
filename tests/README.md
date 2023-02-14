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
