# avbroot

avbroot is a script for patching Android boot images with Magisk root while preserving AVB (Android Verified Boot) using custom keys.

I do not recommend using this project without a deep understanding of the implementation of AVB and A/B OTAs. It is meant for use with proprietary stock firmware. For folks running open-source Android firmware, I highly recommend adding Magisk to the build process and then compiling from source instead.

### Patches

avbroot applies two patches to the boot images:

* Magisk is applied to the `boot` image as if it were done from the Magisk Manager app.

* The `vendor_boot` image is patched to replace the OTA signature verification certificates with the custom OTA signing certificate. This allows future patched OTAs to be sideloaded after the bootloader has been locked. It also prevents accidental flashing of the original OTA package while booted into recovery.

### Warnings and Caveats

* This project only works with devices using (non-legacy-SAR) A/B partitioning and supporting the use of a custom public key for the bootloader's root of trust. This effectively limits the supported devices to recent Google Pixels. I've only tested with an Android 13 OTA on a Google Pixel 6 Pro.

* **Do not ever disable the `OEM unlocking` checkbox when using a locked bootloader with root.** This is critically important. With root access, it is possible to corrupt the running system, for example by zeroing out the boot partition. In this scenario, if the checkbox is turned off, both the OS and recovery mode will be made unbootable and `fastboot flashing unlock` will not be allowed. This effectively renders the device **_hard bricked_**.

* Any operation that causes an unsigned or differently-signed boot image to be flashed will result in the device being unbootable and unrecoverable without unlocking the bootloader again (and thus, triggering a data wipe). This includes:

    * Performing a regular (unpatched) A/B OTA update.

    * The `Direct install` method for updating Magisk. Magisk updates must be done by repatching as well.

### Generating Keys

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
    /path/to/avbroot/external/avb/avbtool extract_public_key --key avb.key --output avb_pkmd.bin
    ```

3. Generate a self-signed certificate for the OTA signing key. This is used by recovery for verifying OTA updates.

    ```bash
    openssl req -new -x509 -sha256 -key ota.key -out ota.crt -days 10000 -subj '/CN=OTA/'
    ```

### Usage

1. Make sure the caveats listed above are understood. It is possible to hard brick by doing the wrong thing!

2. Follow the steps to [generate signing keys](#generating-keys).

3. Compile the signapk dependency from source.

    ```bash
    pushd signapk
    ./gradlew shadowJar
    popd
    ```

4. Patch the full OTA ZIP.

    ```bash
    python avbroot.py \
        patch \
        --input /path/to/ota.zip \
        --privkey-avb /path/to/avb.key \
        --privkey-ota /path/to/ota.key \
        --cert-ota /path/to/avb.crt \
        --magisk /path/to/magisk.apk
    ```

    If the private keys are encrypted, avbroot will prompt for the passphrase every time it runs `openssl` internally.

    If `--output` is not specified, then the output file is written to `<input>.patched`.

5. **[Initial setup only]** Unlock the bootloader.

6. **[Initial setup only]** Extract the patched `boot`, `vendor_boot`, and `vbmeta` images from the patched OTA.

    ```bash
    mkdir extracted
    python avbroot.py \
        extract \
        --input /path/to/ota.zip.patched \
        --directory extracted
    ```

7. **[Initial setup only]** Flash the patched images and the AVB public key metadata. This sets up the custom root of trust. Future updates are done by simply sideloading patched OTA zips.

    ```bash
    fastboot flash boot extracted/boot.img
    fastboot flash vendor_boot extracted/vendor_boot.img
    fastboot flash vbmeta extracted/vbmeta.img
    fastboot flash avb_custom_key /path/to/avb_pkmd.bin
    ```

8. **[Initial setup only]** Run `dmesg` as root to verify that AVB is working properly. A message similar to the following is expected:

    ```bash
    init: [libfs_avb]Returning avb_handle with status: Success
    ```

9. **[Initial setup only]** Lock the bootloader. **Do not uncheck `OEM unlocking`!**

### Updates

To update Android or Magisk:

1. Follow step 4 in [the previous section](#usage) to patch the new OTA (or an existing OTA with a newer Magisk APK).

2. Reboot to recovery mode. If stuck at a `No command` screen, press the volume up button once while holding down the power button.

3. Sideload the patched OTA.

4. Reboot.

### Blocking A/B OTA Updates

Unpatched OTA updates are already blocked in recovery due to the replacing of the OTA signature verification certificates. To disable OTAs while booted into Android, turn off `Automatic system updates` in Android's Developer Options.

To intentionally make A/B OTAs fail while booted into Android (to prevent accidental manual updates), build the `clearotacerts` module:

```bash
python clearotacerts/build.py
```

and flash the `clearotacerts/dist/clearotacerts-<version>.zip` file in Magisk. The module simply overrides `/system/etc/security/otacerts.zip` at runtime with an empty zip so that even if an OTA is downloaded, signature verification will fail.

### Implementation Details

* avbroot relies on AOSP's avbtool, OTA utilities, and signapk. These are collections of applications that aren't meant to be used as libraries, but avbroot shoehorns them in anyway. Aside from signapk, these tools are not called via CLI because avbroot requires more control over the operations being performed than what is provided via the CLI interfaces. This "integration" is incredibly hacky and will likely require changes whenever the submodules are updated to point to newer AOSP commits.

* AVB has two methods of handling signature verification:

    * An image can have an unsigned vbmeta footer, which causes the image's hash to be embedded in the (signed) root `vbmeta` image via vbmeta hash descriptors.
    * An image can have a signed vbmeta footer, which causes a public key for verification to be embedded in the root `vbmeta` image via vbmeta chainload descriptors. This is meant for out-of-band updates where signed images can be updated without also updating the root `vbmeta` image.

    avbroot preserves whether an image uses a chainload or hash descriptor. If a boot image was previously signed, then it will be signed with the AVB key during patching. This preserves the state of the AVB rollback indices, which makes it possible to flip between the original and patched images without a factory reset while debugging avbroot (with the bootloader unlocked).

### Contributing

I'm currently not accepting contributions for avbroot as I only intend to maintain the minimum amount of code needed for it to work on my devices. I'd encourage others to fork and modify avbroot for their own needs.

### License

avbroot is licensed under GPLv3. Please see [`LICENSE`](./LICENSE) for the full license text.
