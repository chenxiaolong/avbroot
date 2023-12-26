# End-to-end tests

avbroot's output file is reproducible for a given input file. [`e2e.toml`](./e2e.toml) lists some profiles for generating mock OTA images with unique properties and the expected checksums before and after patching. These tests use pregenerated, hardcoded test keys for signing. **These keys should NEVER be used for any other purpose.**

For each profile listed in the config, the test process will:

1. Generate a mock OTA based on the specification
2. Verify tha original OTA checksum
3. Run avbroot against the OTA using `--magisk` (with a mock Magisk APK)
4. Verify the patched OTA checksum
5. Extract the AVB-related partitions from the patched OTA
6. Run avbroot against the OTA again using `--prepatched`
7. Verify the patched OTA checksum again

The default profiles shipped with the project mimic how various stock OTAs for Pixel devices are built. The generated mock OTAs have valid signatures and data structures for all components, but without any actual data where possible. For example, most files in the ramdisks are empty files. To ensure the mock OTAs cannot be mistakenly installed on a real device, the OTA metadata lists a fake device name in the preconditions section.

## Running the tests

To test against the profiles listed in [`e2e.toml`](./e2e.toml), run:

```bash
# To test all profiles
cargo run --release -- test -a
# Or to test against specific profiles
cargo run --release -- test -p pixel_v4_gki -p pixel_v4_non_gki
```
