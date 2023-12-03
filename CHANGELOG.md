<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Add support for AVB 2.0 format 1.3.0 (for Android 15) ([PR #210])

Behind-the-scenes changes:

* Fix lint warnings introduced in Rust 1.74.0 ([PR #211])
* Temporarily silence [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) warning in cargo-deny ([PR #214])

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
[Issue #138]: https://github.com/chenxiaolong/avbroot/issues/138
[Issue #144]: https://github.com/chenxiaolong/avbroot/issues/144
[Issue #145]: https://github.com/chenxiaolong/avbroot/issues/145
[Issue #148]: https://github.com/chenxiaolong/avbroot/issues/148
[Issue #157]: https://github.com/chenxiaolong/avbroot/issues/157
[Issue #160]: https://github.com/chenxiaolong/avbroot/issues/160
[Issue #166]: https://github.com/chenxiaolong/avbroot/issues/166
[Issue #201]: https://github.com/chenxiaolong/avbroot/issues/201
[Issue #203]: https://github.com/chenxiaolong/avbroot/issues/203
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
