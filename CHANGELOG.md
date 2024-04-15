<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Use `fastboot flashall` for initial setup to avoid needing to manually flash every partition ([PR #253])

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
