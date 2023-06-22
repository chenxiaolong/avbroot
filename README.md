# avbroot

avbroot is a program for patching Android A/B-style OTA images for root access while preserving AVB (Android Verified Boot) using custom signing keys. It is compatible with both Magisk and KernelSU.

Having a good understanding of how AVB and A/B OTAs work is recommended prior to using avbroot. At the very least, please make sure the [warnings and caveats](#warnings-and-caveats) are well-understood to avoid the risk of hard bricking.

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
    openssl genrsa 4096 | openssl pkcs8 -topk8 -scrypt -out avb.key
    openssl genrsa 4096 | openssl pkcs8 -topk8 -scrypt -out ota.key
    ```

2. Convert the public key portion of the AVB signing key to the AVB public key metadata format. This is the format that the bootloader requires when setting the custom root of trust.

    ```bash
    python /path/to/avbroot/external/avb/avbtool.py extract_public_key --key avb.key --output avb_pkmd.bin
    ```

3. Generate a self-signed certificate for the OTA signing key. This is used by recovery for verifying OTA updates.

    ```bash
    openssl req -new -x509 -sha256 -key ota.key -out ota.crt -days 10000 -subj '/CN=OTA/'
    ```

## Installing dependencies

avbroot depends on the `openssl` command line tool and the `lz4` and `protobuf` Python libraries. Also, Python 3.9 or newer is required.

### Linux

On Linux, the dependencies can be installed from the distro's package manager:

| Distro     | Command                                                    |
|------------|------------------------------------------------------------|
| Alpine     | `sudo apk add openssl py3-lz4 py3-protobuf`                |
| Arch Linux | `sudo pacman -S openssl python-lz4 python-protobuf`        |
| Debian     | `sudo apt install openssl python3-lz4 python3-protobuf`    |
| Fedora     | `sudo dnf install openssl python3-lz4 python3-protobuf`    |
| OpenSUSE   | `sudo zypper install openssl python3-lz4 python3-protobuf` |
| Ubuntu     | (Same as Debian)                                           |

### Windows

Installing openssl and python from the [Scoop package manager](https://scoop.sh/) is suggested.

```powershell
scoop install openssl python
```

Installing from other sources should work as well, but it might be necessary to manually add `openssl`'s installation directory to the `PATH` environment variable.

To install the Python dependencies:

1. Create a virtual environment (replacing `<directory>` with the path where it should be created):

    ```powershell
    python -m venv <directory>
    ```

2. Activate the virtual environment. This must be done in every new terminal session before running avbroot.

    ```powershell
    . <directory>\Scripts\Activate.ps1
    ```

3. Install the dependencies.

    ```powershell
    pip install -r requirements.txt
    ```

## Usage

1. Make sure the caveats listed above are understood. It is possible to hard brick by doing the wrong thing!

2. Clone this git repo recursively, as there are several AOSP repositories included as submodules in the `external/` directory.

    ```bash
    git clone --recursive https://github.com/chenxiaolong/avbroot.git
    ```

    If the repo is already cloned, run the following command instead to fetch the submodules:

    ```bash
    git submodule update --init --recursive
    ```

3. Follow the steps to [install dependencies](#installing-dependencies).

4. Follow the steps to [generate signing keys](#generating-keys).

5. Patch the full OTA ZIP.

    ```bash
    python avbroot.py \
        patch \
        --input /path/to/ota.zip \
        --privkey-avb /path/to/avb.key \
        --privkey-ota /path/to/ota.key \
        --cert-ota /path/to/ota.crt \
        --magisk /path/to/magisk.apk
    ```

    If `--output` is not specified, then the output file is written to `<input>.patched`.

    **NOTE:** If you are using Magisk version >=25211, you need to know the preinit partition name (`--magisk-preinit-device <name>`). For details, see the [Magisk preinit device section](#magisk-preinit-device).

    If you prefer to use an existing boot image patched by the Magisk app or you want to use KernelSU, see the [advanced usage section](#advanced-usage).

6. **[Initial setup only]** Unlock the bootloader. This will trigger a data wipe.

7. **[Initial setup only]** Extract the patched images from the patched OTA.

    ```bash
    python avbroot.py \
        extract \
        --input /path/to/ota.zip.patched \
        --directory extracted
    ```

8. **[Initial setup only]** Flash the patched images and the AVB public key metadata. This sets up the custom root of trust. Future updates are done by simply sideloading patched OTA zips.

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

9. **[Initial setup only]** Run `dmesg | grep libfs_avb` as root to verify that AVB is working properly. A message similar to the following is expected:

    ```bash
    init: [libfs_avb]Returning avb_handle with status: Success
    ```

10. **[Initial setup only]** Lock the bootloader. This will trigger a data wipe again. **Do not uncheck `OEM unlocking`!**

    **WARNING**: If you are flashing CalyxOS, the setup wizard will [automatically turn off the `OEM unlocking` switch](https://github.com/CalyxOS/platform_packages_apps_SetupWizard/blob/7d2df25cedcbff83ddb608e628f9d97b38259c26/src/org/lineageos/setupwizard/SetupWizardApp.java#L135-L140). Make sure to manually reenable it again from Android's developer settings. Consider using [avbroot's `oemunlockonboot` Magisk module](#oemunlockonboot-enable-oem-unlocking-on-every-boot) to automatically ensure OEM unlocking is enabled on every boot.

## Updates

To update Android or Magisk:

1. Follow step 5 in [the previous section](#usage) to patch the new OTA (or an existing OTA with a newer Magisk APK).

2. Reboot to recovery mode. If stuck at a `No command` screen, press the volume up button once while holding down the power button.

3. Sideload the patched OTA.

4. Reboot.

## avbroot Magisk modules

avbroot's Magisk modules can be built by running:

```bash
python modules/build.py
```

This requires Java and the Android SDK to be installed. The `ANDROID_HOME` environment variable should be set to the Android SDK path.

### `clearotacerts`: Blocking A/B OTA Updates

Unpatched OTA updates are already blocked in recovery because the original OTA certificate has been replaced with the custom certificate. To disable automatic OTAs while booted into Android, turn off `Automatic system updates` in Android's Developer Options.

The `clearotacerts` module additionally makes A/B OTAs fail while booted into Android to prevent accidental manual updates. The module simply overrides `/system/etc/security/otacerts.zip` at runtime with an empty zip so that even if an OTA is downloaded, signature verification will fail.

### `oemunlockonboot`: Enable OEM unlocking on every boot

To help reduce the risk of OEM unlocking being accidentally disabled (or intentionally disabled as part of some OS's initial setup wizard), this module will attempt to enable the OEM unlocking option on every boot.

The logs for this module can be found at `/data/local/tmp/avbroot_oem_unlock.log`.

## Magisk preinit device

Magisk versions 25211 and newer require a writable partition for storing custom SELinux rules that need to be accessed during early boot stages. This can only be determined on a real device, so avbroot requires the partition's block device name to be specified via `--magisk-preinit-device <name>`. To find the partition name:

1. Extract the boot image from the original/unpatched OTA:

    ```bash
    python avbroot.py \
        extract \
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
    python avbroot.py \
        magisk-info \
        --image magisk_patched-*.img
    ```

    The partition name will be shown as `PREINITDEVICE=<name>`.

    Now that the partition name is known, it can be passed to avbroot when patching via `--magisk-preinit-device <name>`. The partition name should be saved somewhere for future reference since it's unlikely to change across Magisk updates.

If it's not possible to run the Magisk app on the target device (eg. device is currently unbootable), patch and flash the OTA once using `--ignore-magisk-warnings`, follow these steps, and then repatch and reflash the OTA with `--magisk-preinit-device <name>`.

## Advanced Usage

### Using a prepatched boot image

avbroot can replace the boot image with a prepatched image instead of applying the Magisk root patch itself. This is useful for using a boot image patched by the Magisk app or for KernelSU. To use a prepatched boot image, pass in `--prepatched <boot image>` instead of `--magisk <apk>`. When using `--prepatched`, avbroot will skip applying the Magisk root patch, but will still apply the OTA certificate patch.

For KernelSU, also pass in `--boot-partition @gki_kernel` for both the `patch` and `extract` commands. avbroot defaults to Magisk's semantics where the boot image containing the GKI ramdisk is needed, whereas KernelSU requires the boot image containing the GKI kernel. This only affects devices launching with Android 13, where the GKI kernel and ramdisk are in different partitions (`boot` vs. `init_boot`), but it is safe and recommended to always use this option for KernelSU.

Note that avbroot will validate that the prepatched image is compatible with the original. If, for example, the header fields do not match or a boot image section is missing, then the patching process will abort. This check is not foolproof, but should help protect against accidental use of the wrong boot image.

### Skipping root patches

avbroot can be used for just resigning an OTA by specifying `--rootless` instead of `--magisk`/`--prepatched`. With this option, the patched OTA will not be rooted. The only modification applied is the replacement of the OTA verification certificate so that the OS can be upgraded with future (patched) OTAs.

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
    avbroot patch \
        --passphrase-avb-file /path/to/avb.passphrase \
        --passphrase-ota-file /path/to/ota.passphrase \
        <...>
    ```

    On Unix-like systems, the "files" can be pipes. With shells that support process substituion (bash, zsh, etc.), the passphrase can be queried from a command (eg. querying a password manager).

    ```bash
    avbroot patch \
        --passphrase-avb-file <(command to query AVB passphrase) \
        --passphrase-ota-file <(command to query OTA passphrase) \
        <...>
    ```

* Supply the passphrases via environment variables. This is less secure since any process running as the same user can see the environment variable values.

    ```bash
    export PASSPHRASE_AVB="the AVB passphrase"
    export PASSPHRASE_OTA="the OTA passphrase"

    avbroot patch \
        --passphrase-avb-env-var PASSPHRASE_AVB \
        --passphrase-ota-env-var PASSPHRASE_OTA \
        <...>
    ```

* Use unencrypted private keys. This is not recommended, but can be done by:

    ```bash
    openssl pkcs8 -in avb.key -topk8 -nocrypt -out avb.unencrypted.key
    openssl pkcs8 -in ota.key -topk8 -nocrypt -out ota.unencrypted.key
    ```

### Extracting the entire OTA

To extract all images contained within the OTA's `payload.bin`, run:

```bash
python avbroot.py \
    extract \
    --input /path/to/ota.zip \
    --directory extracted \
    --all
```

## Implementation Details

* avbroot relies on AOSP's avbtool and OTA utilities. These are collections of applications that aren't meant to be used as libraries, but avbroot shoehorns them in anyway. These tools are not called via CLI because avbroot requires more control over the operations being performed than what is provided via the CLI interfaces. This "integration" is incredibly hacky and will likely require changes whenever the submodules are updated to point to newer AOSP commits.

* AVB has two methods of handling signature verification:

    * An image can have an unsigned vbmeta footer, which causes the image's hash to be embedded in the (signed) root `vbmeta` image via vbmeta hash descriptors.
    * An image can have a signed vbmeta footer, which causes a public key for verification to be embedded in the root `vbmeta` image via vbmeta chainload descriptors. This is meant for out-of-band updates where signed images can be updated without also updating the root `vbmeta` image.

    avbroot preserves whether an image uses a chainload or hash descriptor. If a boot image was previously signed, then it will be signed with the AVB key during patching. This preserves the state of the AVB rollback indices, which makes it possible to flip between the original and patched images without a factory reset while debugging avbroot (with the bootloader unlocked).

## Contributing

Contributions are welcome! However, I'm unlikely to accept changes for supporting devices that behave significantly differently from Pixel devices.

## License

avbroot is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
