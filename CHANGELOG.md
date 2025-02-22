<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Fix parsing Samsung `super.img` files in `avbroot lp` due to Samsung putting their own data structures in a region that's supposed to be filled with zeros ([PR #415])
* Add advanced option to skip replacing the OTA certificate in the system image ([Discussion #417], [PR #418])
* Switch to stable bzip2-rs release and use zlib-rs as the backend for flate2 ([PR #421])
* Switch to the aws-lc cryptography library for SHA1 and SHA2 hashing ([PR #422])
    * The ring library is no longer maintained
* Fix incorrect `Partitions aren't protected by AVB: system` warning when using `--skip-system-ota-cert` ([PR #423])

### Version 3.12.0

* Add new `-p <name>` option to `avbroot ota extract` for extracting specific partitions ([PR #408])
* Deprecate the `--boot-only` option in `avbroot ota extract` ([PR #408])
    * The option will remain indefinitely for backwards compatibility, but is hidden from `--help`
* Add support for extracting the embedded OTA certificate and AVB public key in `avbroot ota extract` ([PR #409])
* Rename `avbroot key extract-avb` to `avbroot key encode-avb` for consistency with `avbroot key decode-avb` ([PR #410])
    * The old syntax will remain supported indefinitely for backwards compatibility, but is hidden from `--help`
* Update dependencies ([PR #411])

### Version 3.11.0

* Fix crash when ignoring warning about `--magisk-preinit-device` not being specified ([PR #394])
* When using `--ignore-magisk-warnings`, assume that unsupported Magisk versions newer than the latest supported version are capable of all features ([Issue #393], [PR #395])
* Update bzip2-rs and switch to the Rust backend ([PR #397], [PR #402])
* Minor code cleanup for custom integer range type ([PR #398])
* Improve errors to make them less ambiguous about what went wrong ([PR #401])
* Fix bug where a vendor v4 boot image that was truncated in the bootconfig padding section would be accepted as valid ([PR #401])
* Avoid performing many small I/O operations when reading and writing cpio archives ([PR #403])
* Update dependencies ([PR #404])

### Version 3.10.0

* Switch to using zerocopy library for all binary file format parsers ([PR #384])
* Update to latest AOSP protobuf schema for the `payload.bin` metadata file format ([PR #385])
* Update dependencies and pin Github Actions actions to specific commits ([PR #386], [PR #392])
* Improve error messages from file format parsers ([PR #390])
* Add support for Magisk 28100 ([PR #391])

### Version 3.9.0

* Update all dependencies ([PR #368], [PR #377])
* Add advanced option to skip replacing the OTA certificate in the recovery image ([Issue #366], [PR #367], [PR #371])
* Improve error message when an incompatible RSA key is used for AVB signing ([Issue #366], [PR #369])
* Fix clippy warnings ([PR #370])
* Allow `avbroot ota verify` to verify OTAs that lack `META-INF/com/android/metadata.pb` ([Issue #366], [PR #373])
* Allow `avbroot ota verify` to verify OTAs where the payload signature does not set `unpadded_signature_size` ([Issue #366], [PR #374])
* Allow `avbroot sparse` to parse sparse images with unknown fields (matches AOSP implementation) ([PR #376])

### Version 3.8.0

* Add `avbroot avb digest` subcommand for computing the special vbmeta digest ([PR #363])
* Update all dependencies ([PR #364])

### Version 3.7.1

* Add support for Magisk 28000 ([PR #362])

### Version 3.7.0

* Fix a nasty regression since version 2.0.0 where recovery mode's `otacerts.zip` modifications were lost when using `--prepatched` with Magisk on some older devices, like the Pixel 4a ([Issue #356], [PR #357])
    * This affected older devices without `vendor_boot` or `recovery` partitions.
    * **This caused sideloading patched OTA updates from recovery mode to break on the affected devices.** To fix the problem without wiping the device and starting fresh, please follow the [steps in the PR](https://github.com/chenxiaolong/avbroot/pull/357#issuecomment-2365343050).
* Print a useful error message when trying to prompt for a passphrase without an interactive terminal ([PR #336])
* Add a new `--zip-mode seekable` option to allow writing OTA zip files without data descriptors ([Issue #328], [PR #337])
* Add new commands for packing and unpacking logical partition images (`super.img`) ([PR #342], [PR #343])
* Add new commands for packing and unpacking Android sparse images ([PR #347])
* Allow `avbroot payload repack` and `avbroot payload info` commands to read delta payloads ([PR #354])
* Switch to passterm library for password prompts ([PR #355])

### Version 3.6.0

* Add support for gzip compression when computing CoW size estimates ([Issue #332], [PR #333])
  * This allows `--replace` to successfully replace dynamic partitions on legacy devices, like the Pixel 4a 5G
* Minor code cleanup ([PR #334], [PR #335])

### Version 3.5.0

* Update all dependencies ([PR #329])
* Add new unpack and pack commands for `payload.bin` files ([Issue #328], [PR #331])

### Version 3.4.1

* Update all dependencies ([PR #321])
* Add support for Magisk 27006 ([PR #323])

### Version 3.4.0

* Fix (unreachable) minor error handling logic when attempting to use unsupported AVB signing algorithms ([PR #311])
* Add support for performing signing operations with external programs ([Issue #310], [PR #312])
  * See the linked issue for an example of how to sign with a Yubikey.

### Version 3.3.0

* Recompute CoW size estimate when replacing dynamic partitions ([Issue #306], [PR #307])
  * Fixes out of space error when flashing a patched OTA that uses `--replace` to replace a dynamic partition (eg. `system`) with a larger or more incompressible image
* Add `avbroot payload info` subcommand for inspecting `payload.bin` headers ([PR #309])

### Version 3.2.3

* Add prebuilt binary for Android (aarch64) ([PR #304])

### Version 3.2.2

* Add new `--recompute-size` option to `avbroot avb pack` to automatically recompute the image size for resizable images ([Discussion #294], [PR #296])
* Add new `--output-info` option to `avbroot avb pack` to write a new `avb.toml` file containing computed values ([PR #297])
* Add support for upcoming Magisk Canary 27003 ([Issue #301], [PR #268])

### Version 3.2.1

* Increase hash tree and FEC size limits to accommodate partition images up to 8 GiB ([Issue #291], [PR #293])

### Version 3.2.0

* Fix potential infinite loop when interrupting avbroot at the right moment to a bug in the bzip2-rs library ([Issue #285], [PR #287])
* Update all dependencies and fix new clippy lints ([PR #288])
* Add support for adding the custom AVB public key to the list of trusted keys for DSU (booting signed GSIs) ([Discussion #286], [PR #289])

### Version 3.1.3

* Build universal binary for macOS ([Issue #278], [PR #279])

### Version 3.1.2

* Use `fastboot flashall` for initial setup to avoid needing to manually flash every partition ([PR #253])
* Remove binary test files in the git repo and generate them at runtime ([Issue #265], [PR #276])
* Fix portions of a couple error messages being incorrectly quoted ([PR #277])

### Version 3.1.1

* Cache salted SHA-256 contexts for a small performance improvement ([PR #257])
* Fix loading certificates that have extra text outside of the marker lines ([PR #261])

### Version 3.1.0

* The `OEMUnlockOnBoot` module has been split out to a separate repo ([Discussion #235], [PR #246])
    * https://github.com/chenxiaolong/OEMUnlockOnBoot
    * The new module supports the automatic update mechanism within Magisk/KernelSU
* Add support for Magisk v27.0 ([PR #255])
* Switch to using a proper logging library ([PR #251])
    * Folks who want to see the juicy details during patching can use `--log-level debug` or `--log-level trace`

Behind-the-scenes changes:

* Switch from xz2 to liblzma (maintained fork of xz2) ([PR #247])
* Update all dependencies ([PR #256])

### Version 3.0.0

Happy New Year! This release brings two major changes:

1. The OTA certificates (`otacerts.zip`) in the system partition are now patched. The `clearotacerts` module from avbroot (or the `customotacerts` module from Custota) are no longer needed and can be safely uninstalled.

    This makes it possible to use Pixel's new Repair Mode safely. To do so, follow the instructions in the [documentation here](./README.md#repair-mode).

2. Autodetection for boot partitions is now significantly more reliable. For KernelSU users or folks who have more obscure devices, the `--boot-partition` option is no longer required (and is now ignored).

Full list of changes:

* Add support for AVB 2.0 format 1.3.0 (for Android 15) ([PR #210])
* Add new `avbroot key decode-avb` command for converting AVB-encoded public keys to the standard PKCS8-encoded format ([PR #219])
* Improve autodetection of boot images ([Issue #218], [PR #221], [PR #237])
* Build precompiled executables as statically linked executables ([Issue #222], [PR #224], [PR #227])
* Limit critical partition check to bootloader-verified partitions ([Issue #223], [PR #226])
* Improve patching performance by spliiting new partition images into chunks and compressing them in parallel ([PR #228])
* Also verify whole-partition hashes when running `avbroot ota verify` ([PR #229])
* Add support for patching `otacerts.zip` on the system partition ([Issue #225], [PR #240], [PR #244])
* Document how to use Repair Mode safely ([Issue #216], [PR #243])

Behind-the-scenes changes:

* Fix lint warnings introduced in Rust 1.74.0 ([PR #211])
* Temporarily silence [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) warning in cargo-deny ([PR #214])
* Add support for partially updating FEC data ([PR #230], [PR #231], [PR #234])
* Fix hash tree calculation for images smaller than one block ([PR #232])
* Refactor hash tree code and add tests, CLI commands, and support for partial updates ([PR #233])
* Generate mock OTAs to use for end-to-end tests ([PR #241])
* Update all dependencies ([PR #245])

### Version 2.3.3

* Add support for XZ-compressed ramdisks ([Issue #203], [PR #207])
* Merge property and kernel command line AVB descriptors when replacing partitions ([Issue #203], [PR #208])

### Version 2.3.2

* Improve error messages when using `--replace` with an image that has the wrong AVB descriptor type ([Issue #201], [PR #202])
* Automatically update legacy `dm=` kernel command line descriptor when packing AVB images ([Issue #203], [PR #205])
* Automatically promote insecure hash algorithms (eg. sha1) to sha256 when packing AVB images ([Issue #203], [PR #206])

### Version 2.3.1

* Mark Magisk 264xx as supported ([PR #199])

### Version 2.3.0

* Fix missing `--help` text for `avbroot avb unpack`'s `--ignore-invalid` option ([PR #183])
* Group `avbroot ota patch --help` output into more readable sections ([PR #184])
* Add more checks to ensure that the OTA has a secure AVB setup ([PR #188])
    * OTAs with blatantly insecure or missing AVB configuration are now more likely to be rejected by avbroot to avoid providing a false sense of security.
* Allow `avbroot avb verify` and `avbroot ota verify` to work for dm-verity partitions that use insecure SHA1 hashes ([PR #190])
* Add support for legacy Android 11 OTAs ([Discussion #195], [PR #196])

Behind-the-scenes changes:

* Bump maximum payload manifest size to 4 MiB ([PR #182])
* Rework file handle reopen functionality to use traits instead of callbacks ([PR #189])
* Don't set signature algorithm field for indirectly signed boot images ([PR #191])
* Update dependencies ([PR #197])

### Version 2.2.0

It's Android 14 release day! All versions of avbroot, including the old Python version, are compatible with Android 14 OTAs.

Changes:

* Add new unpack and pack commands for cpio archives (ramdisks) ([PR #173], [PR #178])
* Rename `header.toml` to `boot.toml` for the boot image unpack and pack commands ([PR #175])
    * Also changes the file format a bit to make it more readable.

Behind-the-scenes changes:

* Add streaming CPIO reader and writer ([PR #172])
* Update dependencies ([PR #174], [PR #181])
* Switch to prost for protobuf encoding/decoding ([PR #176])

### Version 2.1.1

This release is all about hardening avbroot against untrusted (or corrupted) inputs. While all of avbroot's parsers are memory-safe, it's still possible for crashes to occur due to logic issues like allocating too much memory or dividing by zero. With this release, most of these potential issues have been fixed and fuzz tests have been added to help find more of these situations.

On the filesystem side of things, it is no longer possible for a nefarious program to cause avbroot to write to unintended locations by eg. swapping out an output directory or temp directory with a symlink while it is running.

Behind-the-scenes changes:

* Consolidate logic for handling `--pass-file` and `--pass-env-var` ([PR #156])
* cargo-deny: Block executables in dependencies ([PR #133])
* Implement size limits for parsers to prevent allocating too much memory ([Issue #157], [PR #158], [PR #159], [PR #164], [PR #168], [PR #169], [PR #170])
* Add fuzzers to help catch panics/crashes ([Issue #160], [PR #161], [PR #162], [PR #163], [PR #165], [PR #167])
* Use handle-based directory operations instead of path-based directory operations ([Issue #166], [PR #171])

### Version 2.1.0

* Add support for dm-verify FEC (forward error correction) ([Issue #145], [PR #146])
    * `ota verify` and `avb verify` will now check the FEC data.
* Print status and warning messages to stderr ([PR #149])
* Add new `avb unpack`, `avb pack`, and `avb repack` commands for AVB images ([Issue #144], [Issue #148], [PR #152])
    * `avb verify` now optionally accepts `--repair` to fix corrupted dm-verity images.

Behind-the-scenes changes:

* Remove unnecessary use of `Arc` ([PR #147])
* Use bstr crate to escape mostly UTF-8 binary data ([PR #150])
* Improve error fields and error contest ([PR #153])

### Version 2.0.3

* Upgrade xz version in precompiled binaries ([Issue #138], [PR #139])
    * This fixes the `ota extract` and `ota verify` commands in some multithreaded situations.
* Add `--version` option to print out avbroot's version ([Issue #138], [PR #140])

### Version 2.0.2

* Fix `data_offset` being set for payload operations that don't need it ([PR #136])
    * This fixes patched stock OnePlus images from being rejected when flashing.

Behind-the-scenes changes:

* Move full OTA check to CLI functions to allow library functions to parse delta OTAs ([PR #135])
* Remove unnecessary use of `anyhow` macro ([PR #137])

### Version 2.0.1

* Add support for Magisk 263xx ([PR #132])

### Version 2.0.0

* Initial Rust release. The old Python implementation can be found in the `python` branch. ([PR #130])

<!-- Do not manually edit the lines below. Use `cargo xtask update-changelog` to regenerate. -->
[Discussion #195]: https://github.com/chenxiaolong/avbroot/discussions/195
[Discussion #235]: https://github.com/chenxiaolong/avbroot/discussions/235
[Discussion #286]: https://github.com/chenxiaolong/avbroot/discussions/286
[Discussion #294]: https://github.com/chenxiaolong/avbroot/discussions/294
[Discussion #417]: https://github.com/chenxiaolong/avbroot/discussions/417
[Issue #138]: https://github.com/chenxiaolong/avbroot/issues/138
[Issue #144]: https://github.com/chenxiaolong/avbroot/issues/144
[Issue #145]: https://github.com/chenxiaolong/avbroot/issues/145
[Issue #148]: https://github.com/chenxiaolong/avbroot/issues/148
[Issue #157]: https://github.com/chenxiaolong/avbroot/issues/157
[Issue #160]: https://github.com/chenxiaolong/avbroot/issues/160
[Issue #166]: https://github.com/chenxiaolong/avbroot/issues/166
[Issue #201]: https://github.com/chenxiaolong/avbroot/issues/201
[Issue #203]: https://github.com/chenxiaolong/avbroot/issues/203
[Issue #216]: https://github.com/chenxiaolong/avbroot/issues/216
[Issue #218]: https://github.com/chenxiaolong/avbroot/issues/218
[Issue #222]: https://github.com/chenxiaolong/avbroot/issues/222
[Issue #223]: https://github.com/chenxiaolong/avbroot/issues/223
[Issue #225]: https://github.com/chenxiaolong/avbroot/issues/225
[Issue #265]: https://github.com/chenxiaolong/avbroot/issues/265
[Issue #278]: https://github.com/chenxiaolong/avbroot/issues/278
[Issue #285]: https://github.com/chenxiaolong/avbroot/issues/285
[Issue #291]: https://github.com/chenxiaolong/avbroot/issues/291
[Issue #301]: https://github.com/chenxiaolong/avbroot/issues/301
[Issue #306]: https://github.com/chenxiaolong/avbroot/issues/306
[Issue #310]: https://github.com/chenxiaolong/avbroot/issues/310
[Issue #328]: https://github.com/chenxiaolong/avbroot/issues/328
[Issue #332]: https://github.com/chenxiaolong/avbroot/issues/332
[Issue #356]: https://github.com/chenxiaolong/avbroot/issues/356
[Issue #366]: https://github.com/chenxiaolong/avbroot/issues/366
[Issue #393]: https://github.com/chenxiaolong/avbroot/issues/393
[PR #130]: https://github.com/chenxiaolong/avbroot/pull/130
[PR #132]: https://github.com/chenxiaolong/avbroot/pull/132
[PR #133]: https://github.com/chenxiaolong/avbroot/pull/133
[PR #135]: https://github.com/chenxiaolong/avbroot/pull/135
[PR #136]: https://github.com/chenxiaolong/avbroot/pull/136
[PR #137]: https://github.com/chenxiaolong/avbroot/pull/137
[PR #139]: https://github.com/chenxiaolong/avbroot/pull/139
[PR #140]: https://github.com/chenxiaolong/avbroot/pull/140
[PR #146]: https://github.com/chenxiaolong/avbroot/pull/146
[PR #147]: https://github.com/chenxiaolong/avbroot/pull/147
[PR #149]: https://github.com/chenxiaolong/avbroot/pull/149
[PR #150]: https://github.com/chenxiaolong/avbroot/pull/150
[PR #152]: https://github.com/chenxiaolong/avbroot/pull/152
[PR #153]: https://github.com/chenxiaolong/avbroot/pull/153
[PR #156]: https://github.com/chenxiaolong/avbroot/pull/156
[PR #158]: https://github.com/chenxiaolong/avbroot/pull/158
[PR #159]: https://github.com/chenxiaolong/avbroot/pull/159
[PR #161]: https://github.com/chenxiaolong/avbroot/pull/161
[PR #162]: https://github.com/chenxiaolong/avbroot/pull/162
[PR #163]: https://github.com/chenxiaolong/avbroot/pull/163
[PR #164]: https://github.com/chenxiaolong/avbroot/pull/164
[PR #165]: https://github.com/chenxiaolong/avbroot/pull/165
[PR #167]: https://github.com/chenxiaolong/avbroot/pull/167
[PR #168]: https://github.com/chenxiaolong/avbroot/pull/168
[PR #169]: https://github.com/chenxiaolong/avbroot/pull/169
[PR #170]: https://github.com/chenxiaolong/avbroot/pull/170
[PR #171]: https://github.com/chenxiaolong/avbroot/pull/171
[PR #172]: https://github.com/chenxiaolong/avbroot/pull/172
[PR #173]: https://github.com/chenxiaolong/avbroot/pull/173
[PR #174]: https://github.com/chenxiaolong/avbroot/pull/174
[PR #175]: https://github.com/chenxiaolong/avbroot/pull/175
[PR #176]: https://github.com/chenxiaolong/avbroot/pull/176
[PR #178]: https://github.com/chenxiaolong/avbroot/pull/178
[PR #181]: https://github.com/chenxiaolong/avbroot/pull/181
[PR #182]: https://github.com/chenxiaolong/avbroot/pull/182
[PR #183]: https://github.com/chenxiaolong/avbroot/pull/183
[PR #184]: https://github.com/chenxiaolong/avbroot/pull/184
[PR #188]: https://github.com/chenxiaolong/avbroot/pull/188
[PR #189]: https://github.com/chenxiaolong/avbroot/pull/189
[PR #190]: https://github.com/chenxiaolong/avbroot/pull/190
[PR #191]: https://github.com/chenxiaolong/avbroot/pull/191
[PR #196]: https://github.com/chenxiaolong/avbroot/pull/196
[PR #197]: https://github.com/chenxiaolong/avbroot/pull/197
[PR #199]: https://github.com/chenxiaolong/avbroot/pull/199
[PR #202]: https://github.com/chenxiaolong/avbroot/pull/202
[PR #205]: https://github.com/chenxiaolong/avbroot/pull/205
[PR #206]: https://github.com/chenxiaolong/avbroot/pull/206
[PR #207]: https://github.com/chenxiaolong/avbroot/pull/207
[PR #208]: https://github.com/chenxiaolong/avbroot/pull/208
[PR #210]: https://github.com/chenxiaolong/avbroot/pull/210
[PR #211]: https://github.com/chenxiaolong/avbroot/pull/211
[PR #214]: https://github.com/chenxiaolong/avbroot/pull/214
[PR #219]: https://github.com/chenxiaolong/avbroot/pull/219
[PR #221]: https://github.com/chenxiaolong/avbroot/pull/221
[PR #224]: https://github.com/chenxiaolong/avbroot/pull/224
[PR #226]: https://github.com/chenxiaolong/avbroot/pull/226
[PR #227]: https://github.com/chenxiaolong/avbroot/pull/227
[PR #228]: https://github.com/chenxiaolong/avbroot/pull/228
[PR #229]: https://github.com/chenxiaolong/avbroot/pull/229
[PR #230]: https://github.com/chenxiaolong/avbroot/pull/230
[PR #231]: https://github.com/chenxiaolong/avbroot/pull/231
[PR #232]: https://github.com/chenxiaolong/avbroot/pull/232
[PR #233]: https://github.com/chenxiaolong/avbroot/pull/233
[PR #234]: https://github.com/chenxiaolong/avbroot/pull/234
[PR #237]: https://github.com/chenxiaolong/avbroot/pull/237
[PR #240]: https://github.com/chenxiaolong/avbroot/pull/240
[PR #241]: https://github.com/chenxiaolong/avbroot/pull/241
[PR #243]: https://github.com/chenxiaolong/avbroot/pull/243
[PR #244]: https://github.com/chenxiaolong/avbroot/pull/244
[PR #245]: https://github.com/chenxiaolong/avbroot/pull/245
[PR #246]: https://github.com/chenxiaolong/avbroot/pull/246
[PR #247]: https://github.com/chenxiaolong/avbroot/pull/247
[PR #251]: https://github.com/chenxiaolong/avbroot/pull/251
[PR #253]: https://github.com/chenxiaolong/avbroot/pull/253
[PR #255]: https://github.com/chenxiaolong/avbroot/pull/255
[PR #256]: https://github.com/chenxiaolong/avbroot/pull/256
[PR #257]: https://github.com/chenxiaolong/avbroot/pull/257
[PR #261]: https://github.com/chenxiaolong/avbroot/pull/261
[PR #268]: https://github.com/chenxiaolong/avbroot/pull/268
[PR #276]: https://github.com/chenxiaolong/avbroot/pull/276
[PR #277]: https://github.com/chenxiaolong/avbroot/pull/277
[PR #279]: https://github.com/chenxiaolong/avbroot/pull/279
[PR #287]: https://github.com/chenxiaolong/avbroot/pull/287
[PR #288]: https://github.com/chenxiaolong/avbroot/pull/288
[PR #289]: https://github.com/chenxiaolong/avbroot/pull/289
[PR #293]: https://github.com/chenxiaolong/avbroot/pull/293
[PR #296]: https://github.com/chenxiaolong/avbroot/pull/296
[PR #297]: https://github.com/chenxiaolong/avbroot/pull/297
[PR #304]: https://github.com/chenxiaolong/avbroot/pull/304
[PR #307]: https://github.com/chenxiaolong/avbroot/pull/307
[PR #309]: https://github.com/chenxiaolong/avbroot/pull/309
[PR #311]: https://github.com/chenxiaolong/avbroot/pull/311
[PR #312]: https://github.com/chenxiaolong/avbroot/pull/312
[PR #321]: https://github.com/chenxiaolong/avbroot/pull/321
[PR #323]: https://github.com/chenxiaolong/avbroot/pull/323
[PR #329]: https://github.com/chenxiaolong/avbroot/pull/329
[PR #331]: https://github.com/chenxiaolong/avbroot/pull/331
[PR #333]: https://github.com/chenxiaolong/avbroot/pull/333
[PR #334]: https://github.com/chenxiaolong/avbroot/pull/334
[PR #335]: https://github.com/chenxiaolong/avbroot/pull/335
[PR #336]: https://github.com/chenxiaolong/avbroot/pull/336
[PR #337]: https://github.com/chenxiaolong/avbroot/pull/337
[PR #342]: https://github.com/chenxiaolong/avbroot/pull/342
[PR #343]: https://github.com/chenxiaolong/avbroot/pull/343
[PR #347]: https://github.com/chenxiaolong/avbroot/pull/347
[PR #354]: https://github.com/chenxiaolong/avbroot/pull/354
[PR #355]: https://github.com/chenxiaolong/avbroot/pull/355
[PR #357]: https://github.com/chenxiaolong/avbroot/pull/357
[PR #362]: https://github.com/chenxiaolong/avbroot/pull/362
[PR #363]: https://github.com/chenxiaolong/avbroot/pull/363
[PR #364]: https://github.com/chenxiaolong/avbroot/pull/364
[PR #367]: https://github.com/chenxiaolong/avbroot/pull/367
[PR #368]: https://github.com/chenxiaolong/avbroot/pull/368
[PR #369]: https://github.com/chenxiaolong/avbroot/pull/369
[PR #370]: https://github.com/chenxiaolong/avbroot/pull/370
[PR #371]: https://github.com/chenxiaolong/avbroot/pull/371
[PR #373]: https://github.com/chenxiaolong/avbroot/pull/373
[PR #374]: https://github.com/chenxiaolong/avbroot/pull/374
[PR #376]: https://github.com/chenxiaolong/avbroot/pull/376
[PR #377]: https://github.com/chenxiaolong/avbroot/pull/377
[PR #384]: https://github.com/chenxiaolong/avbroot/pull/384
[PR #385]: https://github.com/chenxiaolong/avbroot/pull/385
[PR #386]: https://github.com/chenxiaolong/avbroot/pull/386
[PR #390]: https://github.com/chenxiaolong/avbroot/pull/390
[PR #391]: https://github.com/chenxiaolong/avbroot/pull/391
[PR #392]: https://github.com/chenxiaolong/avbroot/pull/392
[PR #394]: https://github.com/chenxiaolong/avbroot/pull/394
[PR #395]: https://github.com/chenxiaolong/avbroot/pull/395
[PR #397]: https://github.com/chenxiaolong/avbroot/pull/397
[PR #398]: https://github.com/chenxiaolong/avbroot/pull/398
[PR #401]: https://github.com/chenxiaolong/avbroot/pull/401
[PR #402]: https://github.com/chenxiaolong/avbroot/pull/402
[PR #403]: https://github.com/chenxiaolong/avbroot/pull/403
[PR #404]: https://github.com/chenxiaolong/avbroot/pull/404
[PR #408]: https://github.com/chenxiaolong/avbroot/pull/408
[PR #409]: https://github.com/chenxiaolong/avbroot/pull/409
[PR #410]: https://github.com/chenxiaolong/avbroot/pull/410
[PR #411]: https://github.com/chenxiaolong/avbroot/pull/411
[PR #415]: https://github.com/chenxiaolong/avbroot/pull/415
[PR #418]: https://github.com/chenxiaolong/avbroot/pull/418
[PR #421]: https://github.com/chenxiaolong/avbroot/pull/421
[PR #422]: https://github.com/chenxiaolong/avbroot/pull/422
[PR #423]: https://github.com/chenxiaolong/avbroot/pull/423
