# avbroot

(This page is also available in: [Russian (Русский)](./README.ru.md).)

avbroot is a program for patching Android A/B-style OTA images for root access while preserving AVB (Android Verified Boot) using custom signing keys. It is compatible with both Magisk and KernelSU. If desired, it can also just re-sign an OTA without enabling root access.

Having a good understanding of how AVB and A/B OTAs work is recommended prior to using avbroot. At the very least, please make sure the [warnings and caveats](#warnings-and-caveats) are well-understood to avoid the risk of hard bricking.

**NOTE:** avbroot 2.0 has been rewritten in Rust and no longer relies on any AOSP code. The CLI is fully backwards compatible, but the old Python implementation can be found in the `python` branch if needed.

## Requirements

* Only devices that use modern A/B partitioning are supported. This is the case for most non-Samsung devices launched with Android 10 or newer. To check if a device uses this partitioning scheme, open the OTA zip file and check that:

  * `payload.bin` exists
  * `META-INF/com/android/metadata` (Android 10-11) or `META-INF/com/android/metadata.pb` (Android 12+) exists

* The device must support using a custom public key for the bootloader's root of trust. This is normally done via the `fastboot flash avb_custom_key` command.

  A list of devices known to work can be found in the issue tracker at [#299](https://github.com/chenxiaolong/avbroot/issues/299).

## Patches

avbroot applies the following patches to the partition images:

* The `boot` or `init_boot` image, depending on device, is patched to enable root access. For Magisk, the patch is equivalent to what would be normally done by the Magisk app.

* The `boot`, `recovery`, or `vendor_boot` image, depending on device, is patched to replace the OTA signature verification certificates with the custom OTA signing certificate. This allows future patched OTAs to be sideloaded from recovery mode after the bootloader has been locked. It also prevents accidental flashing of the original unpatched OTA.

* The `system` image is also patched to replace the OTA signature verification certificates. This prevents the OS' system updater app from installing an unpatched OTA and also allows the use of custom OTA updater apps.

## Warnings and Caveats

* **Always leave the `OEM unlocking` checkbox enabled when using a locked bootloader with root.** This is critically important. Root access allows the boot partition to potentially be overwritten, either accidentally or intentionally, with an image that is not properly signed. In this scenario, if the checkbox is turned off, both the OS and recovery mode will be made unbootable and `fastboot flashing unlock` will not be allowed. This effectively renders the device **_hard bricked_**.

    Repeat: **_ALWAYS leave `OEM unlocking` enabled if rooted._**

* Any operation that causes an improperly-signed boot image to be flashed will result in the device being unbootable and unrecoverable without unlocking the bootloader again (and thus, triggering a data wipe). A couple ways an improperly-signed boot image could be flashed include:

    * The `Direct install` method for updating Magisk. Magisk updates **must** be done by repatching the OTA, not via the app.

    * The `Uninstall Magisk` feature in Magisk. If root access is no longer needed, Magisk **must** be removed by repatching the OTA with the `--rootless` option, not via the app.

    If the boot image is ever modified, **do not reboot**. [Open an issue](https://github.com/chenxiaolong/avbroot/issues/new) for support and be very clear about what steps were done that lead to the situation. If Android is still running and root access works, it might be possible to recover without wiping and starting over.

## Usage

1. Make sure the [caveats listed above](#warnings-and-caveats) are understood. It is possible to hard brick by doing the wrong thing!

2. Download the latest version from the [releases page](https://github.com/chenxiaolong/avbroot/releases). To verify the digital signature, see the [verifying digital signatures](#verifying-digital-signatures) section.

    avbroot is a standalone executable. It does not need to be installed and can be run from anywhere.

3. Follow the steps to [generate signing keys](#generating-keys).

4. Patch the OTA zip. The base command is:

    ```bash
    avbroot ota patch \
        --input /path/to/ota.zip \
        --key-avb /path/to/avb.key \
        --key-ota /path/to/ota.key \
        --cert-ota /path/to/ota.crt \
    ```

    Add the following additional arguments to the end of the command depending on how you want to configure root access.

    * To enable root access with Magisk:

        ```bash
        --magisk /path/to/magisk.apk \
        --magisk-preinit-device <name>
        ```

        If you don't know the Magisk preinit partition name, see the [Magisk preinit device section](#magisk-preinit-device) for steps on how to find it.

        If you prefer to manually patch the boot image via the Magisk app instead of letting avbroot handle it, use the following arguments instead:

        ```bash
        --prepatched /path/to/magisk_patched-xxxxx_yyyyy.img
        ```

    * To enable root access with KernelSU:

        ```bash
        --prepatched /path/to/kernelsu/boot.img
        ```

    * To leave the OS unrooted:

        ```bash
        --rootless
        ```

    For more details on the options above, see the [advanced usage section](#advanced-usage).

    If `--output` is not specified, then the output file is written to `<input>.patched`.

5. The patched OTA is ready to go! To flash it for the first time, follow the steps in the [initial setup section](#initial-setup). For updates, follow the steps in the [updates section](#updates).

## Generating Keys

avbroot signs several components while patching an OTA zip:

* the boot images
* the vbmeta images
* the OTA payload
* the OTA zip itself

The first two components are signed with an AVB key and latter two components are signed with an OTA key. They can be the same key, though the following steps show how to generate two separate keys.

When patching OTAs for multiple devices, generating unique keys for each device is strongly recommended because it prevents an OTA for the wrong device being accidentally flashed.

1. Generate the AVB and OTA signing keys.

    ```bash
    avbroot key generate-key -o avb.key
    avbroot key generate-key -o ota.key
    ```

2. Convert the public key portion of the AVB signing key to the AVB public key metadata format. This is the format that the bootloader requires when setting the custom root of trust.

    ```bash
    avbroot key encode-avb -k avb.key -o avb_pkmd.bin
    ```

3. Generate a self-signed certificate for the OTA signing key. This is used by recovery to verify OTA updates when sideloading.

    ```bash
    avbroot key generate-cert -k ota.key -o ota.crt
    ```

The commands above are provided for convenience. avbroot is compatible with any standard PKCS#8-encoded 4096-bit RSA private key and PEM-encoded X509 certificate, like those generated by openssl.

If you lose your AVB or OTA signing key, you will no longer be able to sign new OTA zips. You will have to generate new signing keys and unlock your bootloader again (triggering a data wipe). Follow the [Usage section](#usage) as if doing an initial setup.

## Initial setup

1. Make sure that the version of fastboot is 34 or newer. Older versions have bugs that prevent the `fastboot flashall` command (required later) from working properly.

    ```bash
    fastboot --version
    ```

2. Reboot into fastboot mode and unlock the bootloader if it isn't already unlocked. This will trigger a data wipe.

    ```bash
    fastboot flashing unlock
    ```

3. When setting things up for the first time, the device must already be running the correct OS. Flash the original unpatched OTA if needed.

4. Extract the partition images from the patched OTA that are different from the original.

    ```bash
    avbroot ota extract \
        --input /path/to/ota.zip.patched \
        --directory extracted \
        --fastboot
    ```

    If you prefer to extract and flash all OS partitions just to be safe, pass in `--all`.

5. Set the `ANDROID_PRODUCT_OUT` environment variable to the directory containing the extracted files.

    For sh/bash/zsh (Linux, macOS, WSL):

    ```bash
    export ANDROID_PRODUCT_OUT=extracted
    ```

    For PowerShell (Windows):

    ```powershell
    $env:ANDROID_PRODUCT_OUT = "extracted"
    ```

    For cmd (Windows):

    ```bat
    set ANDROID_PRODUCT_OUT=extracted
    ```

6. Flash the partition images that were extracted.

    ```bash
    fastboot flashall --skip-reboot
    ```

    Note that this only flashes the OS partitions. The bootloader and modem/radio partitions are left untouched due to fastboot limitations. If they are not already up to date or if unsure, after fastboot completes, follow the steps in the [updates section](#updates) to sideload the patched OTA once. Sideloading OTAs always ensures that all partitions are up to date.

    Alternatively, for Pixel devices, running `flash-base.sh` from the factory image will also update the bootloader and modem.

7. Set up the custom AVB public key in the bootloader after rebooting from fastbootd to bootloader.

    ```bash
    fastboot reboot-bootloader
    fastboot erase avb_custom_key
    fastboot flash avb_custom_key /path/to/avb_pkmd.bin
    ```

8. **[Optional]** Before locking the bootloader, reboot into Android once to confirm that everything is properly signed.

    Install the Magisk or KernelSU app and run the following command:

    ```bash
    adb shell su -c 'dmesg | grep libfs_avb'
    ```

    If AVB is working properly, the following message should be printed out:

    ```bash
    init: [libfs_avb]Returning avb_handle with status: Success
    ```

9. Reboot back into fastboot and lock the bootloader. This will trigger a data wipe again.

    ```bash
    fastboot flashing lock
    ```

    Confirm by pressing volume down and then power. Then reboot.

    Remember: **Do not uncheck `OEM unlocking`!**

    **WARNING**: If you are flashing CalyxOS, the setup wizard will [automatically turn off the `OEM unlocking` switch](https://github.com/CalyxOS/platform_packages_apps_SetupWizard/blob/7d2df25cedcbff83ddb608e628f9d97b38259c26/src/org/lineageos/setupwizard/SetupWizardApp.java#L135-L140). Make sure to manually reenable it again from Android's developer settings. Consider using the [`OEMUnlockOnBoot` module](https://github.com/chenxiaolong/OEMUnlockOnBoot) to automatically ensure OEM unlocking is enabled on every boot.

10. That's it! To install future OS, Magisk, or KernelSU updates, see the [next section](#updates).

## Updates

Updates to Android, Magisk, and KernelSU are all done the same way by patching (or repatching) the OTA.

1. If Magisk or KernelSU is being updated, first install their new `.apk`. If you happen to open the app, make sure it **does not** flash the boot image. Cancel the boot image update prompts if needed.

2. Follow the step in the [usage section](#usage) to patch the new OTA.

3. Reboot to recovery mode. If the screen is stuck at a `No command` message, press the volume up button once while holding down the power button.

4. Sideload the patched OTA with `adb sideload`.

5. That's it!

## Reverting to stock firmware

To stop using avbroot and revert to the stock firmware:

1. Reboot into fastboot mode and unlock the bootloader. This will trigger a data wipe.

2. Erase the custom AVB public key.

    ```bash
    fastboot erase avb_custom_key
    ```

3. Flash the stock firmware.

4. That's it! There are no other remnants to clean up.

## OTA updates

avbroot replaces `/system/etc/security/otacerts.zip` in both the system and recovery partitions with a new zip that contains the custom OTA signing certificate. This prevents an unpatched OTA from inadvertently being installed both when booted into Android and when sideloading from recovery.

Disabling the system updater app is recommended to prevent it from even attempting to install an unpatched OTA. To do so:

* Stock OS: Turn off `Automatic system updates` in Android's Developer Options.
* Custom OS: Disable the system updater app (or block its network access) from Settings -> Apps -> See all apps -> (three-dot menu) -> Show system -> (find updater app).

This is especially important for some custom OS's because their system updater app may get stuck in an infinite loop downloading an OTA update and then retrying when signature verification fails.

To self-host a custom OTA server, see [Custota](https://github.com/chenxiaolong/Custota).

## Repair mode

Some devices now ship with a Repair Mode feature that boots the system with a fresh `userdata` image so that repair technicians are able to run on-device diagnostics without needing the user's credentials to unlock the device.

When the device is rooted, it is unsafe to use Repair Mode. Unless you are using release builds of Magisk/KernelSU signed with your own keys, it's trivial for someone to just install the Magisk/KernelSU app while in repair mode to gain root access with no authentication.

To safely use Repair Mode:

1. Unroot the device by repatching the OTA with the `--rootless` option (instead of `--magisk` or `--prepatched`) and flashing it.

2. Turn on Repair Mode.

3. After receiving the repaired device, exit Repair Mode.

4. Flash the (rooted) patched OTA as normal.

Because the unrooting and rooting are done by flashing OTAs, the device's data will not be wiped.

## Magisk preinit device

Magisk versions 25211 and newer require a writable partition for storing custom SELinux rules that need to be accessed during early boot stages. This can only be determined on a real device, so avbroot requires the partition to be explicitly specified via `--magisk-preinit-device <name>`. To find the partition name:

1. Extract the boot image from the original/unpatched OTA:

    ```bash
    avbroot ota extract \
        --input /path/to/ota.zip \
        --partition <name> # init_boot or boot, depending on device
    ```

2. Patch the boot image via the Magisk app. This **MUST** be done on the target device or a device of the same model! The partition name will be incorrect if patched from Magisk on a different device model.

    The Magisk app will print out a line like the following in the output:

    ```
    - Pre-init storage partition device ID: <name>
    ```

    Alternatively, avbroot can print out what Magisk detected by running:

    ```bash
    avbroot boot magisk-info \
        --image magisk_patched-*.img
    ```

    The partition name will be shown as `PREINITDEVICE=<name>`.

    Now that the partition name is known, it can be passed to avbroot when patching via `--magisk-preinit-device <name>`. The partition name should be saved somewhere for future reference since it's unlikely to change across Magisk updates.

If it's not possible to run the Magisk app on the target device (eg. device is currently unbootable), patch and flash the OTA once using `--ignore-magisk-warnings`, follow these steps, and then repatch and reflash the OTA with `--magisk-preinit-device <name>`.

## Verifying OTAs

To verify all signatures and hashes related to the OTA installation and AVB boot process, run:

```bash
avbroot ota verify \
    --input /path/to/ota.zip \
    --cert-ota /path/to/ota.crt \
    --public-key-avb /path/to/avb_pkmd.bin
```

This command works for any OTA, regardless if it's patched or unpatched.

If the `--cert-ota` and `--public-key-avb` options are omitted, then the signatures are only checked for validity, not that they are trusted.

## Tab completion

Since avbroot has tons of command line options, it may be useful to set up tab completions for the shell. These configs can be generated from avbroot itself.

#### bash

Add to `~/.bashrc`:

```bash
eval "$(avbroot completion -s bash)"
```

#### zsh

Add to `~/.zshrc`:

```bash
eval "$(avbroot completion -s zsh)"
```

#### fish

Add to `~/.config/fish/config.fish`:

```bash
avbroot completion -s fish | source
```

#### PowerShell

Add to PowerShell's `profile.ps1` startup script:

```powershell
Invoke-Expression (& avbroot completion -s powershell)
```

## Advanced Usage

### Using a prepatched boot image

avbroot can replace the boot image with a prepatched image instead of applying the root patch itself. This is useful for using a boot image patched by the Magisk app or for KernelSU. To use a prepatched Magisk boot image or a KernelSU boot image, pass in `--prepatched <boot image>` instead of `--magisk <apk>`. When using `--prepatched`, avbroot will skip applying the Magisk root patch, but will still apply the OTA certificate patch.

Note that avbroot will validate that the prepatched image is compatible with the original. If, for example, the header fields do not match or a boot image section is missing, then the patching process will abort. The checks are not foolproof, but should help protect against accidental use of the wrong boot image. To bypass a somewhat "safe" subset of the checks, use `--ignore-prepatched-compat`. To ignore all checks (strongly discouraged!), pass it in twice.

### Skipping root patches

avbroot can be used for just re-signing an OTA by specifying `--rootless` instead of `--magisk`/`--prepatched`. With this option, the patched OTA will not be rooted. The only modification applied is the replacement of the OTA verification certificate so that the OS can be upgraded with future (patched) OTAs.

### Skipping OTA certificate patches

avbroot can skip modifying `otacerts.zip` with the `--skip-system-ota-cert` and `--skip-recovery-ota-cert` options. **Do not use these unless you have a good reason to do so.**

When `--skip-system-ota-cert` is used, the OTA certificates in the `system` partition will not be modified. This prevents custom OTA updater apps from installing further patched OTAs while booted into Android.

When `--skip-recovery-ota-cert` is used, the OTA certificates in the `vendor_boot` or `recovery` partition will not be modified. **This prevents sideloading further patched OTAs from recovery mode.**

If `--skip-recovery-ota-cert` is used because the OTA certificate was already manually added to the boot image, then [verifying the patched OTA](#verifying-otas) afterwards is recommended to ensure that it was properly done. The verification process is only capable of checking the boot image's copy of the OTA certificates, not the system image's copy of them.

### Skipping all patches

To have avbroot make the absolute minimal changes:

* Specify `--skip-system-ota-cert`
* Specify `--skip-recovery-ota-cert`
* Specify `--rootless`
* Omit `--dsu`

This will re-sign the `vbmeta` partition and the OTA with the custom keys, but leave all other partitions untouched.

**This should only be used for advanced troubleshooting.** Without the OTA certificate patches, the resulting OTA will not be able to install further updates.

### Replacing partitions

avbroot supports replacing entire partitions in the OTA, even partitions that are not boot images (eg. `vendor_dlkm`). A partition can be replaced by passing in `--replace <partition name> /path/to/partition.img`.

The only behavior this changes is where the partition is read from. When using `--replace`, instead of reading the partition image from the original OTA's `payload.bin`, it is read from the specified file. Thus, the replacement partition images must have proper vbmeta footers, like the originals.

This has no impact on what patches are applied. For example, when using Magisk, the root patch is applied to the boot partition, no matter if the partition came from the original `payload.bin` or from `--replace`.

### Booting signed GSIs

Android's [Dynamic System Updates (DSU)](https://developer.android.com/topic/dsu) feature uses a different root of trust than the regular system. Instead of using the bootloader's `avb_custom_key`, it obtains the trusted keys from the `first_stage_ramdisk/avb/*.avbpubkey` files inside the `init_boot` or `vendor_boot` ramdisk. These files are encoded in the same binary format as `avb_pkmd.bin`.

avbroot can add the custom AVB public key to this directory by passing in `--dsu` when patching an OTA. This allows booting [Generic System Images (GSI)](https://developer.android.com/topic/generic-system-image) signed by the custom AVB key.

### Clearing vbmeta flags

Some Android builds may ship with a root `vbmeta` image with the flags set such that AVB is effectively disabled. When avbroot encounters these images, the patching process will fail with a message like:

```
Verified boot is disabled by vbmeta's header flags: 0x3
```

To forcibly enable AVB (by clearing the flags), pass in `--clear-vbmeta-flags`.

### Non-interactive use

avbroot prompts for the private key passphrases interactively by default. To run avbroot non-interactively, either:

* Supply the passphrases via files.

    ```bash
    avbroot ota patch \
        --pass-avb-file /path/to/avb.passphrase \
        --pass-ota-file /path/to/ota.passphrase \
        <...>
    ```

    On Unix-like systems, the "files" can be pipes. With shells that support process substituion (bash, zsh, etc.), the passphrase can be queried from a command (eg. querying a password manager).

    ```bash
    avbroot ota patch \
        --pass-avb-file <(command to query AVB passphrase) \
        --pass-ota-file <(command to query OTA passphrase) \
        <...>
    ```

* Supply the passphrases via environment variables. This is less secure since any process running as the same user can see the environment variable values.

    ```bash
    export PASSPHRASE_AVB="the AVB passphrase"
    export PASSPHRASE_OTA="the OTA passphrase"

    avbroot ota patch \
        --pass-avb-env-var PASSPHRASE_AVB \
        --pass-ota-env-var PASSPHRASE_OTA \
        <...>
    ```

* Use unencrypted private keys. This is strongly discouraged.

### Extracting an OTA

To extract the partition images contained within an OTA's `payload.bin`, run:

```bash
avbroot ota extract \
    --input /path/to/ota.zip \
    --directory extracted
```

By default, this only extracts the images that could potentially be patched by avbroot. To extract all images, use the `--all` option. To extract specific images, use the `--partition <name>` option, which can be specified multiple times.

This command also supports extracting the embedded OTA certificate and AVB public key using the `--cert-ota` and `--public-key-avb` options. To extract only these components, pass in `--none` to skip extracting partition images.

### Zip write mode

By default, avbroot uses streaming writes for the output OTA during patching. This means it computes the sha256 digest for the digital signature as the file is being written. This mode causes the zip file to contain data descriptors, which is part of the zip standard and works on the vast majority of devices. However, some devices may have broken zip file parsers and fail to properly read OTA zip files containing data descriptors. If this is the case, pass in `--zip-mode seekable` when patching.

The seekable mode writes zip files without data descriptors, but as the name implies, requires seeking around the file instead of writing it sequentially. The sha256 digest for the digital signature is computed after the zip file has been fully written.

### Signing with an external program

avbroot supports delegating all RSA signing operations to an external program with the `--signing-helper` option. When using this option, the `--key-avb` and `--key-ota` options must be given a public key instead of a private key.

For each signing operation, avbroot will invoke the program with:

```bash
<helper> <algorithm> <public key>
```

The algorithm is one of `SHA{256,512}_RSA{2048,4096}` and the public key is what was passed to avbroot. The program can use the public key to find the corresponding private key (eg. on a hardware security module). avbroot will write a PKCS#1 v1.5 padded digest to `stdin` and the helper program is expected to perform a raw RSA signing operation and write the raw signature (octet string matching key size) to `stdout`.

By default, this behavior is compatible with the `--signing_helper` option in AOSP's avbtool. However, avbroot additionally extends the arguments to support non-interactive use. If `--pass-{avb,ota}-file` or `--pass-{avb,ota}-env-var` are used, then the helper program will be invoked with two additional arguments that point to the password file or environment variable.

```bash
<helper> <algorithm> <public key> file <pass file>
# or
<helper> <algorithm> <public key> env <env file>
```

Note that avbroot will verify the signature returned by helper program against the public key. This ensures that the patching process will fail appropriately if the wrong private key was used.

### 16K page size developer option

On recent devices running Android 16 and newer, there may be an option in Android's developer options to switch to a 16K page size kernel. This will not work when running an avbroot-patched OS. The switch internally works by flashing incremental OTAs:

* `/vendor/boot_otas/boot_ota_16k.zip` to switch to the 16K page size kernel (requires the `boot` partition to be currently flashed with the 4K kernel)
* `/vendor/boot_otas/boot_ota_4k.zip` to switch to the 4K page size kernel (requires the `boot` partition to be currently flashed with the 16K kernel)

These `boot_otas` are unflashable when running an avbroot-patched OS because the `payload.bin` inside of them are signed by the OEM's key. These are also not proper OTA files. They don't contain any OTA metadata and the zip file itself is not signed. It's nothing more than a plain old zip file that stores a signed `payload.bin`.

There are no plans to add support for patching these `boot_otas`. It requires support for modifying filesystems and handling incremental OTAs, both of which are very non-trivial.

Folks who are determined to make this work anyway can try these manual steps to sign these `boot_otas` with your own key. Since the incremental OTAs are not being regenerated, the `boot` partition must be left unmodified when running `avbroot ota patch`.

1. Unpack `vendor.img` with avbroot and [afsr](https://github.com/chenxiaolong/afsr).

    ```bash
    avbroot avb unpack -i vendor.img
    afsr unpack -i raw.img
    ```

2. Extract `payload.bin` from `boot_otas/boot_ota_16k.zip`.

3. Re-sign `payload.bin` with your OTA key.

    ```bash
    avbroot payload repack \
        -i payload.bin.orig \
        -o payload.bin \
        -k ota.key \
        --output-properties payload_properties.txt
    ```

4. Create a new zip of `payload.bin` and `payload_properties.txt`. The files must be stored uncompressed (eg. with `zip -0`).

5. Repeat the procedure for `boot_otas/boot_ota_4k.zip`.

6. Repack `vendor.img` and sign it with your AVB key.

    ```bash
    afsr pack -o raw.img
    avbroot avb pack -o vendor.img -k avb.key --recompute-size
    ```

7. Patch the (normal) OTA with:

    ```bash
    avbroot ota patch \
        --replace vendor <modified vendor> \
        <normal arguments...>
    ```

## Building from source

Make sure the [Rust toolchain](https://www.rust-lang.org/) is installed. Then run:

```bash
cargo build --release
```

The output binary is written to `target/release/avbroot`.

Debug builds work too, but they will run significantly slower (in the sha256 computations) due to compiler optimizations being turned off.

By default, the executable links to the system's bzip2 and liblzma libraries, which are the only external libraries avbroot depends on. To compile and statically link these two libraries, pass in `--features static`.

### Android cross-compilation

To cross-compile for Android, install [cargo-android](https://github.com/chenxiaolong/cargo-android) and use the `cargo android` wrapper. To make a release build for aarch64, run:

```bash
cargo android build --release --target aarch64-linux-android
```

It is possible to run the tests if the host is running Linux, qemu-user-static is installed, and the executable is built with `RUSTFLAGS=-C target-feature=+crt-static` and `--features static`.

## Verifying digital signatures

To verify the digital signatures of the downloads, follow [the steps here](https://github.com/chenxiaolong/chenxiaolong/blob/master/VERIFY_SSH_SIGNATURES.md).

## Contributing

Contributions are welcome! However, I'm unlikely to accept changes for supporting devices that behave significantly differently from Pixel devices.

## License

avbroot is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
