<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Implement size limits for parsers to prevent allocating too much memory ([Issue #157], [PR #158], [PR #159], [PR #164], [PR #168], [PR #169])
  * avbroot is memory-safe, but malicious/corrupted images previously could potentially cause too much memory to be allocated, leading to the OS killing the process.
* Add fuzzers to help catch panics/crashes ([Issue #160], [PR #161], [PR #162], [PR #163], [PR #165], [PR #167])

Behind-the-scenes changes:

* Consolidate logic for handling `--pass-file` and `--pass-env-var` ([PR #156])
* cargo-deny: Block executables in dependencies ([PR #133])

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
[Issue #138]: https://github.com/chenxiaolong/avbroot/issues/138
[Issue #144]: https://github.com/chenxiaolong/avbroot/issues/144
[Issue #145]: https://github.com/chenxiaolong/avbroot/issues/145
[Issue #148]: https://github.com/chenxiaolong/avbroot/issues/148
[Issue #157]: https://github.com/chenxiaolong/avbroot/issues/157
[Issue #160]: https://github.com/chenxiaolong/avbroot/issues/160
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
