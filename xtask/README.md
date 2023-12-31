# Release tools

## Updating the project version

To update the project version, run:

```bash
cargo xtask set-version -V <version>
```

This will update the main [`Cargo.toml`](../Cargo.toml) file.

## Updating changelog links

To add an entry to [`CHANGELOG.md`](../CHANGELOG.md), the user should manually type in a message and add repository references, like `[Issue #0]` or `[PR #0 @user]`.

Then, run the following command to generate the appropriate link references:

```bash
cargo xtask update-changelog
```
