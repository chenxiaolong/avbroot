<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0 @user] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

Behind-the-scenes changes:

* Move full OTA check to CLI functions to allow library functions to parse delta OTAs ([PR #135 @chenxiaolong])

### Version 2.0.1

* Add support for Magisk 263xx ([PR #132 @chenxiaolong])

### Version 2.0.0

* Initial Rust release. The old Python implementation can be found in the `python` branch. ([PR #130 @chenxiaolong])

<!-- Do not manually edit the lines below. Use `cargo xtask update-changelog` to regenerate. -->
[PR #130 @chenxiaolong]: https://github.com/chenxiaolong/avbroot/pull/130
[PR #132 @chenxiaolong]: https://github.com/chenxiaolong/avbroot/pull/132
[PR #135 @chenxiaolong]: https://github.com/chenxiaolong/avbroot/pull/135
