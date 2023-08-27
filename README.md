# avbroot

avbroot is a program for patching Android A/B-style OTA images for root access while preserving AVB (Android Verified Boot) using custom signing keys. It is compatible with both Magisk and KernelSU.

Having a good understanding of how AVB and A/B OTAs work is recommended prior to using avbroot. At the very least, please make sure the [warnings and caveats](#warnings-and-caveats) are well-understood to avoid the risk of hard bricking.

**NOTE:** avbroot 2.0 has been rewritten in Rust and no longer relies on any AOSP code. The CLI is fully backwards compatible, but the old Python implementation can be found in the `python` branch if needed.

## Patches

avbroot applies two patches to the boot images:

* Magisk is applied to the `boot` or `init_boot` image, depending on device, as if it were done from the Magisk app.

* The `boot`, `recovery`, or `vendor_boot` image, depending on device, is patched to replace the OTA signature verification certificates with the custom OTA signing certificate. This allows future patched OTAs to be sideloaded after the bootloader has been locked. It also prevents accidental flashing of the original OTA package while booted into recovery.

## Warnings and Caveats

* The device must use (non-legacy-SAR) A/B partitioning. This is the case on newer Pixel and OnePlus devices. To check if a device uses this partitioning sceme, open the OTA zip file and check that:

  * `payload.bin` exists
  * `META-INF/com/android/metadata.pb` exists
  * `META-INF/com/android/metadata` contains the line: `ota-type=AB`

* The device must support using a custom public key for the bootloader's root of trust. This is normally done via the `fastboot flash avb_custom_key` command. All Pixel devices with unlockable bootloaders support this, as well as most OnePlus devices. Other devices may support it as well, but there's no easy way to check without just trying it.

* **Do not ever disable the `OEM unlocking` checkbox when using a locked bootloader with root.** This is critically important. With root access, it is possible to corrupt the running system, for example by zeroing out the boot partition. In this scenario, if the checkbox is turned off, both the OS and recovery mode will be made unbootable and `fastboot flashing unlock` will not be allowed. This effectively renders the device **_hard bricked_**.

* Any operation that causes an unsigned or differently-signed boot image to be flashed will result in the device being unbootable and unrecoverable without unlocking the bootloader again (and thus, triggering a data wipe). This includes:

    * Performing a regular (unpatched) A/B OTA update. This can be blocked via a Magisk module (see: [Blocking A/B OTA Updates](#blocking-ab-ota-updates)).

    * The `Direct install` method for updating Magisk. Magisk updates must be done by repatching as well.

## Generating Keys

avbroot signs a few components while patching an OTA zip:

* the root `vbmeta` image
* the boot image `vbmeta` footers (if the original ones were signed)
* the OTA payload
* the OTA zip itself

The boot-related components are signed with an AVB key and OTA-related components are signed with an OTA key. They can be the same RSA keypair, though the following steps show how to generate two separate keys.

1. Generate the AVB and OTA signing keys:

    ```bash
    avbroot key generate-key -o avb.key
    avbroot key generate-key -o ota.key
    ```

2. Convert the public key portion of the AVB signing key to the AVB public key metadata format. This is the format that the bootloader requires when setting the custom root of trust.

    ```bash
    avbroot key extract-avb -k avb.key -o avb_pkmd.bin
    ```

3. Generate a self-signed certificate for the OTA signing key. This is used by recovery for verifying OTA updates.

    ```bash
    avbroot key generate-cert -k ota.key -o ota.crt
    ```

The commands above are provided for convenience. avbroot is compatible with any standard PKCS8-encoded 4096-bit RSA private key and X509 certificate (eg. like those generated by openssl).

## Usage

1. Make sure the caveats listed above are understood. It is possible to hard brick by doing the wrong thing!

2. Download the latest version from the [releases page](https://github.com/chenxiaolong/avbroot/releases). To verify the digital signature, see the [verifying digital signatures](#verifying-digital-signatures) section.

3. Follow the steps to [generate signing keys](#generating-keys).

4. Patch the full OTA ZIP.

    ```bash
    avbroot ota patch \
        --input /path/to/ota.zip \
        --privkey-avb /path/to/avb.key \
        --privkey-ota /path/to/ota.key \
        --cert-ota /path/to/ota.crt \
        --magisk /path/to/magisk.apk
    ```

    If `--output` is not specified, then the output file is written to `<input>.patched`.

    **NOTE:** If you are using Magisk version >=25211, you need to know the preinit partition name (`--magisk-preinit-device <name>`). For details, see the [Magisk preinit device section](#magisk-preinit-device).

    If you prefer to use an existing boot image patched by the Magisk app or you want to use KernelSU, see the [advanced usage section](#advanced-usage).

5. **[Initial setup only]** Unlock the bootloader. This will trigger a data wipe.

6. **[Initial setup only]** Extract the patched images from the patched OTA.

    ```bash
    avbroot ota extract \
        --input /path/to/ota.zip.patched \
        --directory extracted
    ```

7. **[Initial setup only]** Flash the patched images and the AVB public key metadata. This sets up the custom root of trust. Future updates are done by simply sideloading patched OTA zips.

    ```bash
    # Flash the boot images that were extracted
    for image in extracted/*.img; do
        partition=$(basename "${image}")
        partition=${partition%.img}

        fastboot flash "${partition}" "${image}"
    done

    # Flash the AVB signing public key
    fastboot erase avb_custom_key
    fastboot flash avb_custom_key /path/to/avb_pkmd.bin
    ```

8. **[Initial setup only]** Run `dmesg | grep libfs_avb` as root to verify that AVB is working properly. A message similar to the following is expected:

    ```bash
    init: [libfs_avb]Returning avb_handle with status: Success
    ```

9. **[Initial setup only]** Lock the bootloader. This will trigger a data wipe again. **Do not uncheck `OEM unlocking`!**

    **WARNING**: If you are flashing CalyxOS, the setup wizard will [automatically turn off the `OEM unlocking` switch](https://github.com/CalyxOS/platform_packages_apps_SetupWizard/blob/7d2df25cedcbff83ddb608e628f9d97b38259c26/src/org/lineageos/setupwizard/SetupWizardApp.java#L135-L140). Make sure to manually reenable it again from Android's developer settings. Consider using [avbroot's `oemunlockonboot` Magisk module](#oemunlockonboot-enable-oem-unlocking-on-every-boot) to automatically ensure OEM unlocking is enabled on every boot.

## Updates

To update Android or Magisk:

1. Follow step 4 in [the previous section](#usage) to patch the new OTA (or an existing OTA with a newer Magisk APK).

2. Reboot to recovery mode. If stuck at a `No command` screen, press the volume up button once while holding down the power button.

3. Sideload the patched OTA.

4. Reboot.

## avbroot Magisk modules

avbroot's Magisk modules can be found on the [releases page](https://github.com/chenxiaolong/avbroot/releases) or they can be built locally by running:

```bash
python modules/build.py
```

This requires Java and the Android SDK to be installed. The `ANDROID_HOME` environment variable should be set to the Android SDK path.

### `clearotacerts`: Blocking A/B OTA Updates

Unpatched OTA updates are already blocked in recovery because the original OTA certificate has been replaced with the custom certificate. To disable automatic OTAs while booted into Android, turn off `Automatic system updates` in Android's Developer Options.

The `clearotacerts` module additionally makes A/B OTAs fail while booted into Android to prevent accidental manual updates. The module simply overrides `/system/etc/security/otacerts.zip` at runtime with an empty zip so that even if an OTA is downloaded, signature verification will fail.

Alternatively, see [Custota](https://github.com/chenxiaolong/Custota) for a custom OTA updater app that pulls from a self-hosted OTA server.

### `oemunlockonboot`: Enable OEM unlocking on every boot

To help reduce the risk of OEM unlocking being accidentally disabled (or intentionally disabled as part of some OS's initial setup wizard), this module will attempt to enable the OEM unlocking option on every boot.

The logs for this module can be found at `/data/local/tmp/avbroot_oem_unlock.log`.

## Magisk preinit device

Magisk versions 25211 and newer require a writable partition for storing custom SELinux rules that need to be accessed during early boot stages. This can only be determined on a real device, so avbroot requires the partition's block device name to be specified via `--magisk-preinit-device <name>`. To find the partition name:

1. Extract the boot image from the original/unpatched OTA:

    ```bash
    avbroot ota extract \
        --input /path/to/ota.zip \
        --directory . \
        --boot-only
    ```

2. Patch the boot image via the Magisk app. This **MUST** be done on the target device! The partition name will be incorrect if patched from Magisk on a different device.

    The Magisk app will include a line like the following in the output:

    ```
    - Pre-init storage partition device ID: <name>
    ```

    Alternatively, avbroot can print out what Magisk detected by running:

    ```bash
    avbroot ota magisk-info \
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

avbroot can replace the boot image with a prepatched image instead of applying the Magisk root patch itself. This is useful for using a boot image patched by the Magisk app or for KernelSU. To use a prepatched boot image, pass in `--prepatched <boot image>` instead of `--magisk <apk>`. When using `--prepatched`, avbroot will skip applying the Magisk root patch, but will still apply the OTA certificate patch.

For KernelSU, also pass in `--boot-partition @gki_kernel` for both the `patch` and `extract` commands. avbroot defaults to Magisk's semantics where the boot image containing the GKI ramdisk is needed, whereas KernelSU requires the boot image containing the GKI kernel. This only affects devices launching with Android 13, where the GKI kernel and ramdisk are in different partitions (`boot` vs. `init_boot`), but it is safe and recommended to always use this option for KernelSU.

Note that avbroot will validate that the prepatched image is compatible with the original. If, for example, the header fields do not match or a boot image section is missing, then the patching process will abort. The checks are not foolproof, but should help protect against accidental use of the wrong boot image. To bypass a somewhat "safe" subset of the checks, use `--ignore-prepatched-compat`. To ignore all checks (strongly discouraged!), pass it in twice.

### Skipping root patches

avbroot can be used for just resigning an OTA by specifying `--rootless` instead of `--magisk`/`--prepatched`. With this option, the patched OTA will not be rooted. The only modification applied is the replacement of the OTA verification certificate so that the OS can be upgraded with future (patched) OTAs.

### Replacing partitions

avbroot supports replacing entire partitions in the OTA, even partitions that are not boot images (eg. `vendor_dlkm`). A partition can be replaced by passing in `--replace <partition name> /path/to/partition.img`.

The only behavior this changes is where the partition is read from. When using `--replace`, instead of reading the partition image from the original OTA's `payload.bin`, it is read from the specified file. Thus, the replacement partition images must have proper vbmeta footers, like the originals.

This has no impact on what patches are applied. For example, when using Magisk, the root patch is applied to the boot partition, no matter if the partition came from the original `payload.bin` or from `--replace`.

### Clearing vbmeta flags

Some Android builds may ship with a root `vbmeta` image with the flags set such that AVB is effectively disabled. When avbroot encounters these images, the patching process will fail with a message like:

```
ValueError: vbmeta flags disable AVB: 0x3
```

To forcibly enable AVB (by clearing the flags), pass in `--clear-vbmeta-flags`.

### Non-interactive use

avbroot prompts for the private key passphrases interactively by default. To run avbroot non-interactively, either:

* Supply the passphrases via files:

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

### Extracting the entire OTA

To extract all images contained within the OTA's `payload.bin`, run:

```bash
avbroot ota extract \
    --input /path/to/ota.zip \
    --directory extracted \
    --all
```

## Building from source

Make sure the [Rust toolchain](https://www.rust-lang.org/) is installed. Then run:

```bash
cargo build --release
```

The output binary is written to `target/release/avbroot`.

Debug builds work too, but they will run significantly slower (in the sha256 computations) due to compiler optimizations being turned off.

By default, the build links to the system's bzip2 and liblzma libraries, which are the only external libraries avbroot depends on. To compile and statically link these two libraries, pass in `--features static`.

## Verifying digital signatures

First, save the public key to a file listing the keys to be trusted.

```bash
echo 'avbroot ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4' > avbroot_trusted_keys
```

Then, verify the signature of the zip file using the list of trusted keys.

```bash
ssh-keygen -Y verify -f avbroot_trusted_keys -I avbroot -n file -s <file>.zip.sig < <file>.zip
```

If the file is successfully verified, the output will be:

```
Good "file" signature for avbroot with ED25519 key SHA256:Ct0HoRyrFLrnF9W+A/BKEiJmwx7yWkgaW/JvghKrboA
```

## Contributing

Contributions are welcome! However, I'm unlikely to accept changes for supporting devices that behave significantly differently from Pixel devices.

## License

avbroot is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
