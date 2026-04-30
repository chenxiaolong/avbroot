<!--@nrg.languages=en,ru-->
<!--@nrg.defaultLanguage=en-->
# avbroot<!--en-->
<!--en-->
(This page is also available in: [Russian (Русский)](./README.ru.md).)<!--en-->
<!--en-->
avbroot is a tool for modifying Android A/B OTA images reproducibly and re-signing them with custom keys. It also includes a [collection of subcommands](./README.extra.md) for packing and unpacking numerous Android image formats.<!--en-->
<!--en-->
Having a good understanding of how AVB and A/B OTAs work is recommended prior to using avbroot. At the very least, please make sure the [warnings and caveats](#warnings-and-caveats) are well-understood to avoid the risk of hard bricking.<!--en-->
<!--en-->
## Requirements<!--en-->
<!--en-->
* Only devices that use modern A/B partitioning are supported. This is the case for most non-Samsung devices launched with Android 10 or newer. To check if a device uses this partitioning scheme, open the OTA zip file and check that:<!--en-->
<!--en-->
  * `payload.bin` exists<!--en-->
  * `META-INF/com/android/metadata` (Android 10-11) or `META-INF/com/android/metadata.pb` (Android 12+) exists<!--en-->
<!--en-->
* The device must support using a custom public key for the bootloader's root of trust. This is normally done via the `fastboot flash avb_custom_key` command.<!--en-->
<!--en-->
  A list of devices known to work can be found in the issue tracker at [#299](https://github.com/chenxiaolong/avbroot/issues/299).<!--en-->
<!--en-->
## Patches<!--en-->
<!--en-->
avbroot applies the following patches to the partition images:<!--en-->
<!--en-->
* The `boot` or `init_boot` image, depending on device, is patched to enable root access if requested.<!--en-->
<!--en-->
* The `boot`, `recovery`, or `vendor_boot` image, depending on device, is patched to replace the OTA signature verification certificates with the custom OTA signing certificate. This allows future patched OTAs to be sideloaded from recovery mode after the bootloader has been locked. It also prevents accidental flashing of the original unpatched OTA.<!--en-->
<!--en-->
* The `system` image is also patched to replace the OTA signature verification certificates. This prevents the OS' system updater app from installing an unpatched OTA and also allows the use of custom OTA updater apps.<!--en-->
<!--en-->
## Warnings and Caveats<!--en-->
<!--en-->
* **Always leave the `OEM unlocking` checkbox enabled when using a locked bootloader while rooted.** This is critically important. Root access allows the boot partition to potentially be overwritten, either accidentally or intentionally, with an image that is not properly signed. In this scenario, if the checkbox is turned off, both the OS and recovery mode will be made unbootable and `fastboot flashing unlock` will not be allowed. This effectively renders the device **_hard bricked_**.<!--en-->
<!--en-->
    Repeat: **_ALWAYS leave `OEM unlocking` enabled if rooted._**<!--en-->
<!--en-->
* Any operation that causes an improperly-signed boot image to be flashed will result in the device being unbootable and unrecoverable without unlocking the bootloader again (and thus, triggering a data wipe). A couple ways an improperly-signed boot image could be flashed include:<!--en-->
<!--en-->
    * The `Direct install` method for updating Magisk. Magisk updates **must** be done by repatching the OTA, not via the app.<!--en-->
<!--en-->
    * The `Uninstall Magisk` feature in Magisk. If root access is no longer needed, Magisk **must** be removed by repatching the OTA with the `--rootless` option, not via the app.<!--en-->
<!--en-->
    If the boot image is ever modified, **do not reboot**. [Open an issue](https://github.com/chenxiaolong/avbroot/issues/new) for support and be very clear about what steps were done that lead to the situation. If Android is still running and root access works, it might be possible to recover without wiping and starting over.<!--en-->
<!--en-->
## Usage<!--en-->
<!--en-->
1. Make sure the [caveats listed above](#warnings-and-caveats) are understood. It is possible to hard brick by doing the wrong thing!<!--en-->
<!--en-->
2. Download the latest version from the [releases page](https://github.com/chenxiaolong/avbroot/releases). To verify the digital signature, see the [verifying digital signatures](#verifying-digital-signatures) section.<!--en-->
<!--en-->
    avbroot is a standalone executable. It does not need to be installed and can be run from anywhere.<!--en-->
<!--en-->
3. Follow the steps to [generate signing keys](#generating-keys).<!--en-->
<!--en-->
    Skip this step if you're updating Android, Magisk, or KernelSU after you've already performed an [initial setup](#initial-setup). There's no need to generate new signing keys for [updates](#updates): any further updates must use the keys that were created during the initial setup.<!--en-->
<!--en-->
4. Patch the OTA zip. The base command is:<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota patch \<!--en-->
        --input /path/to/ota.zip \<!--en-->
        --key-avb /path/to/avb.key \<!--en-->
        --key-ota /path/to/ota.key \<!--en-->
        --cert-ota /path/to/ota.crt \<!--en-->
    ```<!--en-->
<!--en-->
    Add the following additional arguments to the end of the command depending on how you want to configure root access.<!--en-->
<!--en-->
    * To enable root access with Magisk:<!--en-->
<!--en-->
        ```bash<!--en-->
        --magisk /path/to/magisk.apk \<!--en-->
        --magisk-preinit-device <name><!--en-->
        ```<!--en-->
<!--en-->
        If you don't know the Magisk preinit partition name, see the [Magisk preinit device section](#magisk-preinit-device) for steps on how to find it.<!--en-->
<!--en-->
        If you prefer to manually patch the boot image via the Magisk app instead of letting avbroot handle it, use the following arguments instead:<!--en-->
<!--en-->
        ```bash<!--en-->
        --prepatched /path/to/magisk_patched-xxxxx_yyyyy.img<!--en-->
        ```<!--en-->
<!--en-->
    * To enable root access with KernelSU:<!--en-->
<!--en-->
        ```bash<!--en-->
        --prepatched /path/to/kernelsu/boot.img<!--en-->
        ```<!--en-->
<!--en-->
    * To leave the OS unrooted:<!--en-->
<!--en-->
        ```bash<!--en-->
        --rootless<!--en-->
        ```<!--en-->
<!--en-->
    For more details on the options above, see the [advanced usage section](#advanced-usage).<!--en-->
<!--en-->
    If `--output` is not specified, then the output file is written to `<input>.patched`.<!--en-->
<!--en-->
5. The patched OTA is ready to go! To flash it for the first time, follow the steps in the [initial setup section](#initial-setup). For updates, follow the steps in the [updates section](#updates).<!--en-->
<!--en-->
## Generating Keys<!--en-->
<!--en-->
avbroot signs several components while patching an OTA zip:<!--en-->
<!--en-->
* the boot images<!--en-->
* the vbmeta images<!--en-->
* the OTA payload<!--en-->
* the OTA zip itself<!--en-->
<!--en-->
The first two components are signed with an AVB key and latter two components are signed with an OTA key. They can be the same key, though the following steps show how to generate two separate keys.<!--en-->
<!--en-->
When patching OTAs for multiple devices, generating unique keys for each device is strongly recommended because it prevents an OTA for the wrong device being accidentally flashed.<!--en-->
<!--en-->
1. Generate the AVB and OTA signing keys.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot key generate-key -o avb.key<!--en-->
    avbroot key generate-key -o ota.key<!--en-->
    ```<!--en-->
<!--en-->
2. Convert the public key portion of the AVB signing key to the AVB public key metadata format. This is the format that the bootloader requires when setting the custom root of trust.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot key encode-avb -k avb.key -o avb_pkmd.bin<!--en-->
    ```<!--en-->
<!--en-->
3. Generate a self-signed certificate for the OTA signing key. This is used by recovery to verify OTA updates when sideloading.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot key generate-cert -k ota.key -o ota.crt<!--en-->
    ```<!--en-->
<!--en-->
The commands above are provided for convenience. avbroot is compatible with any standard PKCS#8-encoded 4096-bit RSA private key and PEM-encoded X509 certificate, like those generated by openssl.<!--en-->
<!--en-->
If you lose your AVB or OTA signing key, you will no longer be able to sign new OTA zips. You will have to generate new signing keys and unlock your bootloader again (triggering a data wipe). Follow the [Usage section](#usage) as if doing an initial setup.<!--en-->
<!--en-->
## Initial setup<!--en-->
<!--en-->
1. Make sure that the version of fastboot is 34 or newer. Older versions have bugs that prevent the `fastboot flashall` command (required later) from working properly.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot --version<!--en-->
    ```<!--en-->
<!--en-->
2. Reboot into fastboot mode and unlock the bootloader if it isn't already unlocked. This will trigger a data wipe.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot flashing unlock<!--en-->
    ```<!--en-->
<!--en-->
3. When setting things up for the first time, the device must already be running the correct OS. Flash the original unpatched OTA if needed.<!--en-->
<!--en-->
4. Extract the partition images from the patched OTA that are different from the original.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota extract \<!--en-->
        --input /path/to/ota.zip.patched \<!--en-->
        --directory extracted \<!--en-->
        --fastboot<!--en-->
    ```<!--en-->
<!--en-->
    If you prefer to extract and flash all OS partitions just to be safe, pass in `--all`.<!--en-->
<!--en-->
5. Set the `ANDROID_PRODUCT_OUT` environment variable to the directory containing the extracted files.<!--en-->
<!--en-->
    For sh/bash/zsh (Linux, macOS, WSL):<!--en-->
<!--en-->
    ```bash<!--en-->
    export ANDROID_PRODUCT_OUT=extracted<!--en-->
    ```<!--en-->
<!--en-->
    For PowerShell (Windows):<!--en-->
<!--en-->
    ```powershell<!--en-->
    $env:ANDROID_PRODUCT_OUT = "extracted"<!--en-->
    ```<!--en-->
<!--en-->
    For cmd (Windows):<!--en-->
<!--en-->
    ```bat<!--en-->
    set ANDROID_PRODUCT_OUT=extracted<!--en-->
    ```<!--en-->
<!--en-->
6. Flash the partition images that were extracted.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot flashall --skip-reboot<!--en-->
    ```<!--en-->
<!--en-->
    Note that this only flashes the OS partitions. The bootloader and modem/radio partitions are left untouched due to fastboot limitations. If they are not already up to date or if unsure, after fastboot completes, follow the steps in the [updates section](#updates) to sideload the patched OTA once. Sideloading OTAs always ensures that all partitions are up to date.<!--en-->
<!--en-->
    Alternatively, for Pixel devices, running `flash-base.sh` from the factory image will also update the bootloader and modem.<!--en-->
<!--en-->
7. Set up the custom AVB public key in the bootloader after rebooting from fastbootd to bootloader.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot reboot-bootloader<!--en-->
    fastboot erase avb_custom_key<!--en-->
    fastboot flash avb_custom_key /path/to/avb_pkmd.bin<!--en-->
    ```<!--en-->
<!--en-->
8. **[Optional]** Before locking the bootloader, reboot into Android once to confirm that everything is properly signed.<!--en-->
<!--en-->
    Install the Magisk or KernelSU app and run the following command:<!--en-->
<!--en-->
    ```bash<!--en-->
    adb shell su -c 'dmesg | grep libfs_avb'<!--en-->
    ```<!--en-->
<!--en-->
    If AVB is working properly, the following message should be printed out:<!--en-->
<!--en-->
    ```bash<!--en-->
    init: [libfs_avb]Returning avb_handle with status: Success<!--en-->
    ```<!--en-->
<!--en-->
    Alternatively, the Android build of avbroot can also be used to [verify the partitions on the device](./README.extra.md#verifying-avb-hashes-and-signatures-on-device).<!--en-->
<!--en-->
9. Reboot back into fastboot and lock the bootloader. This will trigger a data wipe again.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot flashing lock<!--en-->
    ```<!--en-->
<!--en-->
    Confirm by pressing volume down and then power. Then reboot.<!--en-->
<!--en-->
    Remember: **Do not uncheck `OEM unlocking`!**<!--en-->
<!--en-->
    **WARNING**: If you are flashing CalyxOS, the setup wizard will [automatically turn off the `OEM unlocking` switch](https://github.com/CalyxOS/platform_packages_apps_SetupWizard/blob/7d2df25cedcbff83ddb608e628f9d97b38259c26/src/org/lineageos/setupwizard/SetupWizardApp.java#L135-L140). Make sure to manually reenable it again from Android's developer settings. Consider using the [`OEMUnlockOnBoot` module](https://github.com/chenxiaolong/OEMUnlockOnBoot) to automatically ensure OEM unlocking is enabled on every boot.<!--en-->
<!--en-->
10. That's it! To update the OS, Magisk, or KernelSU see the [next section](#updates).<!--en-->
<!--en-->
## Updates<!--en-->
<!--en-->
Updates to Android, Magisk, and KernelSU are all done the same way: by patching (or repatching) the OTA.<!--en-->
<!--en-->
1. Generate a new patched OTA by following the steps in the [usage section](#usage).<!--en-->
<!--en-->
2. If Magisk or KernelSU is being updated, first install their new `.apk`. If you happen to open the app, make sure it **does not** flash the boot image. Cancel the boot image update prompts if needed.<!--en-->
<!--en-->
3. Reboot to recovery mode: `adb reboot recovery`. If the screen is stuck at a `No command` message, press the volume up button once while holding down the power button.<!--en-->
<!--en-->
4. Sideload the patched OTA with `adb sideload`.<!--en-->
<!--en-->
5. Restart your device. Note that the device will likely take longer than usual to start on the first boot after an OS update (a few minutes in some cases).<!--en-->
<!--en-->
**WARNING**: Due to how virtual A/B works, there is a snapshot merge operation that Android runs invisibly in the background after installing an OTA and rebooting. During the snapshot merge process, it's not possible to sideload another OTA from recovery mode. Avoid doing anything that could result in a boot loop (eg. installing modules) until this process is complete because there is no way to recover, aside from unlocking the bootloader (and wiping) again.<!--en-->
<!--en-->
The status can be found by running `adb logcat -v color -s update_engine`. Alternatively, if [Custota](https://github.com/chenxiaolong/Custota) is installed (even if it's not configured to point to a custom OTA server), it will show a notification until the snapshot merge operation completes.<!--en-->
<!--en-->
## Reverting to stock firmware<!--en-->
<!--en-->
To stop using avbroot and revert to the stock firmware:<!--en-->
<!--en-->
1. Reboot into fastboot mode and unlock the bootloader. This will trigger a data wipe.<!--en-->
<!--en-->
2. Erase the custom AVB public key.<!--en-->
<!--en-->
    ```bash<!--en-->
    fastboot erase avb_custom_key<!--en-->
    ```<!--en-->
<!--en-->
3. Flash the stock firmware.<!--en-->
<!--en-->
4. That's it! There are no other remnants to clean up.<!--en-->
<!--en-->
## OTA updates<!--en-->
<!--en-->
avbroot replaces `/system/etc/security/otacerts.zip` in both the system and recovery partitions with a new zip that contains the custom OTA signing certificate. This prevents an unpatched OTA from inadvertently being installed both when booted into Android and when sideloading from recovery.<!--en-->
<!--en-->
Disabling the system updater app is recommended to prevent it from even attempting to install an unpatched OTA. To do so:<!--en-->
<!--en-->
* Stock OS: Turn off `Automatic system updates` in Android's Developer Options.<!--en-->
* Custom OS: Disable the system updater app (or block its network access) from Settings -> Apps -> See all apps -> (three-dot menu) -> Show system -> (find updater app).<!--en-->
<!--en-->
This is especially important for some custom OS's because their system updater app may get stuck in an infinite loop downloading an OTA update and then retrying when signature verification fails.<!--en-->
<!--en-->
To self-host a custom OTA server, see [Custota](https://github.com/chenxiaolong/Custota).<!--en-->
<!--en-->
## Repair mode<!--en-->
<!--en-->
Some devices now ship with a Repair Mode feature that boots the system with a fresh `userdata` image so that repair technicians are able to run on-device diagnostics without needing the user's credentials to unlock the device.<!--en-->
<!--en-->
When the device is rooted, it is unsafe to use Repair Mode. Unless you are using release builds of Magisk/KernelSU signed with your own keys, it's trivial for someone to just install the Magisk/KernelSU app while in repair mode to gain root access with no authentication.<!--en-->
<!--en-->
To safely use Repair Mode:<!--en-->
<!--en-->
1. Unroot the device by repatching the OTA with the `--rootless` option (instead of `--magisk` or `--prepatched`) and flashing it.<!--en-->
<!--en-->
2. Turn on Repair Mode.<!--en-->
<!--en-->
3. After receiving the repaired device, exit Repair Mode.<!--en-->
<!--en-->
4. Flash the (rooted) patched OTA as normal.<!--en-->
<!--en-->
Because the unrooting and rooting are done by flashing OTAs, the device's data will not be wiped.<!--en-->
<!--en-->
## Magisk preinit device<!--en-->
<!--en-->
Magisk versions 25211 and newer require a writable partition for storing custom SELinux rules that need to be accessed during early boot stages. This can only be determined on a real device, so avbroot requires the partition to be explicitly specified via `--magisk-preinit-device <name>`. To find the partition name:<!--en-->
<!--en-->
1. Extract the boot image from the original/unpatched OTA:<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota extract \<!--en-->
        --input /path/to/ota.zip \<!--en-->
        --partition <name> # init_boot or boot, depending on device<!--en-->
    ```<!--en-->
<!--en-->
2. Patch the boot image via the Magisk app. This **MUST** be done on the target device or a device of the same model! The partition name will be incorrect if patched from Magisk on a different device model.<!--en-->
<!--en-->
    The Magisk app will print out a line like the following in the output:<!--en-->
<!--en-->
    ```<!--en-->
    - Pre-init storage partition device ID: <name><!--en-->
    ```<!--en-->
<!--en-->
    Alternatively, avbroot can print out what Magisk detected by running:<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot boot magisk-info \<!--en-->
        --image magisk_patched-*.img<!--en-->
    ```<!--en-->
<!--en-->
    The partition name will be shown as `PREINITDEVICE=<name>`.<!--en-->
<!--en-->
    Now that the partition name is known, it can be passed to avbroot when patching via `--magisk-preinit-device <name>`. The partition name should be saved somewhere for future reference since it's unlikely to change across Magisk updates.<!--en-->
<!--en-->
If it's not possible to run the Magisk app on the target device (eg. device is currently unbootable), patch and flash the OTA once using `--ignore-magisk-warnings`, follow these steps, and then repatch and reflash the OTA with `--magisk-preinit-device <name>`.<!--en-->
<!--en-->
## Verifying OTAs<!--en-->
<!--en-->
To verify all signatures and hashes related to the OTA installation and AVB boot process, run:<!--en-->
<!--en-->
```bash<!--en-->
avbroot ota verify \<!--en-->
    --input /path/to/ota.zip \<!--en-->
    --cert-ota /path/to/ota.crt \<!--en-->
    --public-key-avb /path/to/avb_pkmd.bin<!--en-->
```<!--en-->
<!--en-->
This command works for any OTA, regardless if it's patched or unpatched.<!--en-->
<!--en-->
If the `--cert-ota` and `--public-key-avb` options are omitted, then the signatures are only checked for validity, not that they are trusted.<!--en-->
<!--en-->
## Tab completion<!--en-->
<!--en-->
Since avbroot has tons of command line options, it may be useful to set up tab completions for the shell. These configs can be generated from avbroot itself.<!--en-->
<!--en-->
#### bash<!--en-->
<!--en-->
Add to `~/.bashrc`:<!--en-->
<!--en-->
```bash<!--en-->
eval "$(avbroot completion -s bash)"<!--en-->
```<!--en-->
<!--en-->
#### zsh<!--en-->
<!--en-->
Add to `~/.zshrc`:<!--en-->
<!--en-->
```bash<!--en-->
eval "$(avbroot completion -s zsh)"<!--en-->
```<!--en-->
<!--en-->
#### fish<!--en-->
<!--en-->
Add to `~/.config/fish/config.fish`:<!--en-->
<!--en-->
```bash<!--en-->
avbroot completion -s fish | source<!--en-->
```<!--en-->
<!--en-->
#### PowerShell<!--en-->
<!--en-->
Add to PowerShell's `profile.ps1` startup script:<!--en-->
<!--en-->
```powershell<!--en-->
Invoke-Expression (& avbroot completion -s powershell)<!--en-->
```<!--en-->
<!--en-->
## Advanced Usage<!--en-->
<!--en-->
### Using a prepatched boot image<!--en-->
<!--en-->
avbroot can replace the boot image with a prepatched image instead of applying the root patch itself. This is useful for using a boot image patched by the Magisk app or for KernelSU. To use a prepatched Magisk boot image or a KernelSU boot image, pass in `--prepatched <boot image>` instead of `--magisk <apk>`. When using `--prepatched`, avbroot will skip applying the Magisk root patch, but will still apply the OTA certificate patch.<!--en-->
<!--en-->
Note that avbroot will validate that the prepatched image is compatible with the original. If, for example, the header fields do not match or a boot image section is missing, then the patching process will abort. The checks are not foolproof, but should help protect against accidental use of the wrong boot image. To bypass a somewhat "safe" subset of the checks, use `--ignore-prepatched-compat`. To ignore all checks (strongly discouraged!), pass it in twice.<!--en-->
<!--en-->
### Skipping root patches<!--en-->
<!--en-->
avbroot can be used for just re-signing an OTA by specifying `--rootless` instead of `--magisk`/`--prepatched`. With this option, the patched OTA will not be rooted. The only modification applied is the replacement of the OTA verification certificate so that the OS can be upgraded with future (patched) OTAs.<!--en-->
<!--en-->
### Skipping OTA certificate patches<!--en-->
<!--en-->
avbroot can skip modifying `otacerts.zip` with the `--skip-system-ota-cert` and `--skip-recovery-ota-cert` options. **Do not use these unless you have a good reason to do so.**<!--en-->
<!--en-->
When `--skip-system-ota-cert` is used, the OTA certificates in the `system` partition will not be modified. This prevents custom OTA updater apps from installing further patched OTAs while booted into Android.<!--en-->
<!--en-->
When `--skip-recovery-ota-cert` is used, the OTA certificates in the `vendor_boot` or `recovery` partition will not be modified. **This prevents sideloading further patched OTAs from recovery mode.**<!--en-->
<!--en-->
If `--skip-recovery-ota-cert` is used because the OTA certificate was already manually added to the boot image, then [verifying the patched OTA](#verifying-otas) afterwards is recommended to ensure that it was properly done. The verification process is only capable of checking the boot image's copy of the OTA certificates, not the system image's copy of them.<!--en-->
<!--en-->
### Skipping all patches<!--en-->
<!--en-->
To have avbroot make the absolute minimal changes:<!--en-->
<!--en-->
* Specify `--skip-system-ota-cert`<!--en-->
* Specify `--skip-recovery-ota-cert`<!--en-->
* Specify `--rootless`<!--en-->
* Omit `--dsu`<!--en-->
<!--en-->
This will re-sign the `vbmeta` partition and the OTA with the custom keys, but leave all other partitions untouched.<!--en-->
<!--en-->
**This should only be used for advanced troubleshooting.** Without the OTA certificate patches, the resulting OTA will not be able to install further updates.<!--en-->
<!--en-->
### Replacing partitions<!--en-->
<!--en-->
avbroot supports replacing entire partitions in the OTA, even partitions that are not boot images (eg. `vendor_dlkm`). A partition can be replaced by passing in `--replace <partition name> /path/to/partition.img`.<!--en-->
<!--en-->
The only behavior this changes is where the partition is read from. When using `--replace`, instead of reading the partition image from the original OTA's `payload.bin`, it is read from the specified file. Thus, the replacement partition images must have proper vbmeta footers, like the originals.<!--en-->
<!--en-->
This has no impact on what patches are applied. For example, when using Magisk, the root patch is applied to the boot partition, no matter if the partition came from the original `payload.bin` or from `--replace`.<!--en-->
<!--en-->
### Re-signing partitions<!--en-->
<!--en-->
avbroot will automatically re-sign any partitions in the OTA that it modifies. However, partitions that are otherwise unmodified can also be re-signed with `--re-sign <partition name>`. This is useful, for example, when the OTA contains partitions signed with the public AOSP test key.<!--en-->
<!--en-->
### Booting signed GSIs<!--en-->
<!--en-->
Android's [Dynamic System Updates (DSU)](https://developer.android.com/topic/dsu) feature uses a different root of trust than the regular system. Instead of using the bootloader's `avb_custom_key`, it obtains the trusted keys from the `first_stage_ramdisk/avb/*.avbpubkey` files inside the `init_boot` or `vendor_boot` ramdisk. These files are encoded in the same binary format as `avb_pkmd.bin`.<!--en-->
<!--en-->
avbroot can add the custom AVB public key to this directory by passing in `--dsu` when patching an OTA. This allows booting [Generic System Images (GSI)](https://developer.android.com/topic/generic-system-image) signed by the custom AVB key.<!--en-->
<!--en-->
### Clearing vbmeta flags<!--en-->
<!--en-->
Some Android builds may ship with a root `vbmeta` image with the flags set such that AVB is effectively disabled. When avbroot encounters these images, the patching process will fail with a message like:<!--en-->
<!--en-->
```<!--en-->
Verified boot is disabled by vbmeta's header flags: 0x3<!--en-->
```<!--en-->
<!--en-->
To forcibly enable AVB (by clearing the flags), pass in `--clear-vbmeta-flags`.<!--en-->
<!--en-->
### Changing virtual A/B CoW compression algorithm<!--en-->
<!--en-->
The virtual A/B CoW compression algorithm can be changed by passing in `--vabc-algo <algo>` with `gz` or `lz4`. OTAs normally use an algorithm that is compatible with the initial version of Android shipped on the device.<!--en-->
<!--en-->
* Devices launching with Android 12 support `gz` and `brotli` (unsupported by avbroot)<!--en-->
* Devices launching with Android 14 support `lz4`<!--en-->
* Devices launching with Android 15 support `zstd` (unsupported by avbroot)<!--en-->
<!--en-->
Picking a fast algorithm, like lz4, can speed up OTA installation significantly when installing via a custom OTA updater app. However, there is no performance difference when sideloading an OTA from recovery mode.<!--en-->
<!--en-->
Note that the currently running version of Android must support the specified compression algorithm or else the OTA will fail to install. For example, trying to install an Android 14 OTA that uses lz4 CoW compression will fail if the running system is Android 13.<!--en-->
<!--en-->
### Non-interactive use<!--en-->
<!--en-->
avbroot prompts for the private key passphrases interactively by default. To run avbroot non-interactively, either:<!--en-->
<!--en-->
* Supply the passphrases via files.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota patch \<!--en-->
        --pass-avb-file /path/to/avb.passphrase \<!--en-->
        --pass-ota-file /path/to/ota.passphrase \<!--en-->
        <...><!--en-->
    ```<!--en-->
<!--en-->
    On Unix-like systems, the "files" can be pipes. With shells that support process substituion (bash, zsh, etc.), the passphrase can be queried from a command (eg. querying a password manager).<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota patch \<!--en-->
        --pass-avb-file <(command to query AVB passphrase) \<!--en-->
        --pass-ota-file <(command to query OTA passphrase) \<!--en-->
        <...><!--en-->
    ```<!--en-->
<!--en-->
* Supply the passphrases via environment variables. This is less secure since any process running as the same user can see the environment variable values.<!--en-->
<!--en-->
    ```bash<!--en-->
    export PASSPHRASE_AVB="the AVB passphrase"<!--en-->
    export PASSPHRASE_OTA="the OTA passphrase"<!--en-->
<!--en-->
    avbroot ota patch \<!--en-->
        --pass-avb-env-var PASSPHRASE_AVB \<!--en-->
        --pass-ota-env-var PASSPHRASE_OTA \<!--en-->
        <...><!--en-->
    ```<!--en-->
<!--en-->
* Use unencrypted private keys. This is strongly discouraged.<!--en-->
<!--en-->
### Extracting an OTA<!--en-->
<!--en-->
To extract the partition images contained within an OTA's `payload.bin`, run:<!--en-->
<!--en-->
```bash<!--en-->
avbroot ota extract \<!--en-->
    --input /path/to/ota.zip \<!--en-->
    --directory extracted<!--en-->
```<!--en-->
<!--en-->
By default, this only extracts the images that could potentially be patched by avbroot. To extract all images, use the `--all` option. To extract specific images, use the `--partition <name>` option, which can be specified multiple times.<!--en-->
<!--en-->
This command also supports extracting the embedded OTA certificate and AVB public key using the `--cert-ota` and `--public-key-avb` options. To extract only these components, pass in `--none` to skip extracting partition images.<!--en-->
<!--en-->
### Zip write mode<!--en-->
<!--en-->
By default, avbroot uses streaming writes for the output OTA during patching. This means it computes the sha256 digest for the digital signature as the file is being written. This mode causes the zip file to contain data descriptors, which is part of the zip standard and works on the vast majority of devices. However, some devices may have broken zip file parsers and fail to properly read OTA zip files containing data descriptors. If this is the case, pass in `--zip-mode seekable` when patching.<!--en-->
<!--en-->
The seekable mode writes zip files without data descriptors, but as the name implies, requires seeking around the file instead of writing it sequentially. The sha256 digest for the digital signature is computed after the zip file has been fully written.<!--en-->
<!--en-->
### Signing with an external program<!--en-->
<!--en-->
avbroot supports delegating all RSA signing operations to an external program with the `--signing-helper` option. When using this option, the `--key-avb` and `--key-ota` options must be given a public key instead of a private key.<!--en-->
<!--en-->
For each signing operation, avbroot will invoke the program with:<!--en-->
<!--en-->
```bash<!--en-->
<helper> <algorithm> <public key><!--en-->
```<!--en-->
<!--en-->
The algorithm is one of `SHA{256,512}_RSA{2048,4096}` and the public key is what was passed to avbroot. The program can use the public key to find the corresponding private key (eg. on a hardware security module). avbroot will write a PKCS#1 v1.5 padded digest to `stdin` and the helper program is expected to perform a raw RSA signing operation and write the raw signature (octet string matching key size) to `stdout`.<!--en-->
<!--en-->
By default, this behavior is compatible with the `--signing_helper` option in AOSP's avbtool. However, avbroot additionally extends the arguments to support non-interactive use. If `--pass-{avb,ota}-file` or `--pass-{avb,ota}-env-var` are used, then the helper program will be invoked with two additional arguments that point to the password file or environment variable.<!--en-->
<!--en-->
```bash<!--en-->
<helper> <algorithm> <public key> file <pass file><!--en-->
# or<!--en-->
<helper> <algorithm> <public key> env <env file><!--en-->
```<!--en-->
<!--en-->
Note that avbroot will verify the signature returned by helper program against the public key. This ensures that the patching process will fail appropriately if the wrong private key was used.<!--en-->
<!--en-->
### 16K page size developer option<!--en-->
<!--en-->
On recent devices running Android 16 and newer, there may be an option in Android's developer options to switch to a 16K page size kernel. This will not work when running an avbroot-patched OS. The switch internally works by flashing incremental OTAs:<!--en-->
<!--en-->
* `/vendor/boot_otas/boot_ota_16k.zip` to switch to the 16K page size kernel (requires the `boot` partition to be currently flashed with the 4K kernel)<!--en-->
* `/vendor/boot_otas/boot_ota_4k.zip` to switch to the 4K page size kernel (requires the `boot` partition to be currently flashed with the 16K kernel)<!--en-->
<!--en-->
These `boot_otas` are unflashable when running an avbroot-patched OS because the `payload.bin` inside of them are signed by the OEM's key. These are also not proper OTA files. They don't contain any OTA metadata and the zip file itself is not signed. It's nothing more than a plain old zip file that stores a signed `payload.bin`.<!--en-->
<!--en-->
There are no plans to add support for patching these `boot_otas`. It requires support for modifying filesystems and handling incremental OTAs, both of which are very non-trivial.<!--en-->
<!--en-->
Folks who are determined to make this work anyway can try these manual steps to sign these `boot_otas` with your own key. Since the incremental OTAs are not being regenerated, the `boot` partition must be left unmodified when running `avbroot ota patch`.<!--en-->
<!--en-->
1. Unpack `vendor.img` with avbroot and [afsr](https://github.com/chenxiaolong/afsr).<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot avb unpack -i vendor.img<!--en-->
    afsr unpack -i raw.img<!--en-->
    ```<!--en-->
<!--en-->
2. Extract `payload.bin` from `boot_otas/boot_ota_16k.zip`.<!--en-->
<!--en-->
3. Re-sign `payload.bin` with your OTA key.<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot payload repack \<!--en-->
        -i payload.bin.orig \<!--en-->
        -o payload.bin \<!--en-->
        -k ota.key \<!--en-->
        --output-properties payload_properties.txt<!--en-->
    ```<!--en-->
<!--en-->
4. Create a new zip of `payload.bin` and `payload_properties.txt`. The files must be stored uncompressed (eg. with `zip -0`).<!--en-->
<!--en-->
5. Repeat the procedure for `boot_otas/boot_ota_4k.zip`.<!--en-->
<!--en-->
6. Repack `vendor.img` and sign it with your AVB key.<!--en-->
<!--en-->
    ```bash<!--en-->
    afsr pack -o raw.img<!--en-->
    avbroot avb pack -o vendor.img -k avb.key --recompute-size<!--en-->
    ```<!--en-->
<!--en-->
7. Patch the (normal) OTA with:<!--en-->
<!--en-->
    ```bash<!--en-->
    avbroot ota patch \<!--en-->
        --replace vendor <modified vendor> \<!--en-->
        <normal arguments...><!--en-->
    ```<!--en-->
<!--en-->
## Building from source<!--en-->
<!--en-->
Make sure the [Rust toolchain](https://www.rust-lang.org/) is installed. Then run:<!--en-->
<!--en-->
```bash<!--en-->
cargo build --release<!--en-->
```<!--en-->
<!--en-->
The output binary is written to `target/release/avbroot`.<!--en-->
<!--en-->
Debug builds work too, but they will run significantly slower (in the sha256 computations) due to compiler optimizations being turned off.<!--en-->
<!--en-->
### Android cross-compilation<!--en-->
<!--en-->
To cross-compile for Android, install [cargo-android](https://github.com/chenxiaolong/cargo-android) and use the `cargo android` wrapper. To make a release build for aarch64, run:<!--en-->
<!--en-->
```bash<!--en-->
cargo android build --release --target aarch64-linux-android<!--en-->
```<!--en-->
<!--en-->
It is possible to run the tests if the host is running Linux, qemu-user-static is installed, and the executable is built with `RUSTFLAGS=-C target-feature=+crt-static` and `--features static`.<!--en-->
<!--en-->
## Verifying digital signatures<!--en-->
<!--en-->
To verify the digital signatures of the downloads, follow [the steps here](https://github.com/chenxiaolong/chenxiaolong/blob/master/VERIFY_SSH_SIGNATURES.md).<!--en-->
<!--en-->
## Contributing<!--en-->
<!--en-->
Contributions are welcome! However, I'm unlikely to accept changes for supporting devices that behave significantly differently from Pixel devices.<!--en-->
<!--en-->
## License<!--en-->
<!--en-->
avbroot is licensed under GPL-3.0-only. Please see [`LICENSE`](./LICENSE) for the full license text.<!--en-->
# avbroot<!--ru-->
<!--ru-->
avbroot – это утилита для воспроизводимой модификации OTA-образов Android A/B-формата и их переподписания пользовательскими ключами. Она также включает в себя [набор подкоманд](./README.extra.md) для упаковки и распаковки образов Android различных форматов.<!--ru-->
<!--ru-->
Прежде чем использовать avbroot, рекомендуется иметь хорошее понимание того, как работают AVB и OTA в формате A/B. Как минимум, следует ознакомиться с [разделом предостережений,](#предостережения) чтобы избежать хардбрика устройства.<!--ru-->
<!--ru-->
## Требования<!--ru-->
<!--ru-->
* Поддерживаются только устройства, использующие современную A/B-разметку. Это большинство девайсов, выпускаемых с Android 10 и новее (за исключением устройств от Samsung). Чтобы проверить, использует ли ваше устройство необходимую схему разметки, откройте zip-архив OTA и проверьте:<!--ru-->
<!--ru-->
  * наличие файла `payload.bin` (обычно находится в корне архива)<!--ru-->
  * наличие файла `META-INF/com/android/metadata` (Android 10-11) или `META-INF/com/android/metadata.pb` (Android 12+)<!--ru-->
<!--ru-->
* Устройство должно поддерживать установку пользовательского публичного ключа для подтверждения статуса доверия загрузчика. Обычно это производится с помощью команды `fastboot flash avb_custom_key`.<!--ru-->
<!--ru-->
  Список девайсов, на которых проверялась совместимость с указанным выше функционалом, находится здесь: [#299.](https://github.com/chenxiaolong/avbroot/issues/299)<!--ru-->
<!--ru-->
## Патчи<!--ru-->
<!--ru-->
avbroot модифицирует следующие образы:<!--ru-->
<!--ru-->
* `boot` или `init_boot`, в зависимости от устройства, модифицируется для получения root-доступа, если это запрашивается.<!--ru-->
<!--ru-->
* `boot`, `recovery` или `vendor_boot`, в зависимости от устройства, модифицируется для замены сертификата проверки подписи OTA на пользовательский. Это позволяет устанавливать будущие пропатченные OTA через режим Recovery уже после блокировки загрузчика, то есть в качестве обновления. Также это предотвращает случайную установку оригинального непропатченного OTA.<!--ru-->
<!--ru-->
* `system` тоже модифицируется для замены сертификата проверки подписи OTA. Это не позволит системному приложению обновлений ОС установить оригинальный непропатченный OTA и дает возможность использовать сторонние приложения для установки пропатченных OTA.<!--ru-->
<!--ru-->
## Предостережения<!--ru-->
<!--ru-->
* **Всегда оставляйте опцию `Заводской разблокировки`** (или OEM unlocking в англ.) **включенной при наличии root-прав с заблокированным загрузчиком.** Это очень важно. Доступ к root-правам потенциально позволяет перезаписать загрузочный раздел из-под системы, будь то сделано случайно или намеренно, файлом, который не был подписан должным образом. В таком случае, система и режим Recovery больше не смогут загрузиться, а команда `fastboot flashing unlock` будет недоступна, потому что параметр Заводской разблокировки отключен. То есть, это приведет к **_хардбрику устройства_**.<!--ru-->
<!--ru-->
    Повторюсь: **_ВСЕГДА оставляйте `Заводскую разблокировку` включенной при наличии root-прав._**<!--ru-->
<!--ru-->
* Любая операция, приводящая к прошивке некорректно подписанного загрузочного образа, приведет к тому, что устройство больше не сможет загрузиться в систему/режим Recovery, а для его восстановления потребуется повторная разблокировка загрузчика (и, следовательно, стирание всех пользовательских данных). К подобным операциям в том числе относятся:<!--ru-->
<!--ru-->
    * Метод `Прямой установки` для обновления Magisk. Magisk можно обновлять **только путем репатчинга OTA,** но не через его приложение.<!--ru-->
<!--ru-->
    * Функция `Удаление Magisk` в приложении Magisk. Если вам больше не нужен root-доступ, Magisk **должен быть удален путем репатчинга OTA** с использованием параметра `--rootless`, но не через его приложение.<!--ru-->
<!--ru-->
    Если в загрузочный раздел были внесены какие-либо изменения, **не перезагружайтесь**. Обратитесь за помощью, [открыв Issue,](https://github.com/chenxiaolong/avbroot/issues/new) и четко разъясните, какие конкретные действия привели к возникновению такой ситуации. Если Android всё еще работает и доступ к root-правам сохранился – вероятно, получится откатить изменения до исходного состояния, не стирая ваши данные.<!--ru-->
<!--ru-->
## Использование<!--ru-->
<!--ru-->
1. Убедитесь, что вы ознакомились и поняли указанные выше [предостережения.](#предостережения)<!--ru-->
<!--ru-->
2. Скачайте последнюю версию со страницы [релизов.](https://github.com/chenxiaolong/avbroot/releases) Чтобы сверить цифровую подпись, см. раздел [проверки цифровых подписей.](#проверка-цифровых-подписей)<!--ru-->
<!--ru-->
    avbroot – это отдельный исполняемый файл. Он не требует установки и может быть запущен из любого места на диске.<!--ru-->
<!--ru-->
3. [Сгенерируйте ключи подписи.](#генерация-ключей)<!--ru-->
<!--ru-->
Пропустите этот шаг, если вы обновляете Android, Magisk или KernelSU уже после выполнения [первоначальной настройки](#первоначальная-настройка). Повторная генерация ключей подписи для [обновлений](#обновления) не требуется: для всех последующих обновлений должны использоваться те ключи, что были созданы при первоначальной настройке.<!--ru-->
<!--ru-->
4. Пропатчите ОТА-архив с помощью команды:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot ota patch \<!--ru-->
        --input /путь/к/ota.zip \<!--ru-->
        --key-avb /путь/к/avb.key \<!--ru-->
        --key-ota /путь/к/ota.key \<!--ru-->
        --cert-ota /путь/к/ota.crt \<!--ru-->
    ```<!--ru-->
<!--ru-->
    Добавьте следующие аргументы в конец команды в зависимости от того, как вы хотите получить root-доступ.<!--ru-->
<!--ru-->
    * Для получения root-доступа с использованием Magisk:<!--ru-->
<!--ru-->
        ```bash<!--ru-->
        --magisk /путь/к/magisk.apk \<!--ru-->
        --magisk-preinit-device <имя><!--ru-->
        ```<!--ru-->
<!--ru-->
        Если вы не знаете имени раздела предварительной инициализации Magisk, следуйте инструкции [в соответствующем разделе.](#предварительная-инициализация-устройства-для-magisk)<!--ru-->
<!--ru-->
        Если вы пропатчили загрузочный образ вручную через приложение Magisk (вместо автоматического идентичного патчинга через avbroot), используйте следующий аргумент:<!--ru-->
<!--ru-->
        ```bash<!--ru-->
        --prepatched /путь/к/magisk_patched-xxxxx_yyyyy.img<!--ru-->
        ```<!--ru-->
<!--ru-->
    * Для получения root-доступа с использованием KernelSU:<!--ru-->
<!--ru-->
        ```bash<!--ru-->
        --prepatched /путь/к/kernelsu_boot.img<!--ru-->
        ```<!--ru-->
<!--ru-->
    * Без root-доступа:<!--ru-->
<!--ru-->
        ```bash<!--ru-->
        --rootless<!--ru-->
        ```<!--ru-->
<!--ru-->
    Больше информации про существующие аргументы можно найти в разделе [расширенного использования.](#расширенное-использование)<!--ru-->
<!--ru-->
    Если название для `--output` не указывается, то готовый файл будет записан как `<название-ota-zip-в-input>.patched`.<!--ru-->
<!--ru-->
5. Готово! Для прошивки пропатченного OTA следуйте инструкции в разделе [первоначальной настройки.](#первоначальная-настройка) Для последующих обновлений тоже есть соответствующий [раздел обновлений.](#обновления)<!--ru-->
<!--ru-->
## Генерация ключей<!--ru-->
<!--ru-->
Во время патчинга OTA, avbroot подписывает несколько компонентов:<!--ru-->
<!--ru-->
* загрузочный образ (boot)<!--ru-->
* образ vbmeta<!--ru-->
* payload из OTA<!--ru-->
* сам архив OTA<!--ru-->
<!--ru-->
Первые два компонента подписываются ключом AVB, а последние два – ключом OTA. Можно использовать один и тот же ключ, однако в следующих шагах описано, как сгенерировать два отдельных.<!--ru-->
<!--ru-->
Если вы патчите OTA сразу для нескольких устройств, настоятельно рекомендуется генерировать уникальные ключи для каждого девайса – так вы защитите себя от случайной прошивки неподходящего OTA.<!--ru-->
<!--ru-->
1. Сгенерируйте ключи подписи для AVB и OTA.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot key generate-key -o avb.key<!--ru-->
    avbroot key generate-key -o ota.key<!--ru-->
    ```<!--ru-->
<!--ru-->
2. Преобразуйте публичную часть ключа подписи AVB в формат метаданных публичного ключа AVB. Именно этот формат используется в загрузчике устройства для установки пользовательского ключа.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot key encode-avb -k avb.key -o avb_pkmd.bin<!--ru-->
    ```<!--ru-->
<!--ru-->
3. Сгенерируйте самоподписанный сертификат для ключа подписи OTA. Он используется режимом Recovery для проверки подписи OTA при установке обновления.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot key generate-cert -k ota.key -o ota.crt<!--ru-->
    ```<!--ru-->
<!--ru-->
avbroot совместим с любым стандартным 4096-битным приватным ключом RSA в кодировке PKCS#8 и сертификатом X509 в кодировке PEM, например с теми, которые генерируются openssl.<!--ru-->
<!--ru-->
Если вы потеряете ключ(-и) подписи AVB или OTA, вы больше не сможете подписывать новые OTA-архивы. Придется генерировать новые ключи подписи и разблокировать загрузчик (что приведет к стиранию всех данных). В таком случае возвращайтесь к инструкции в разделе [использования.](#использование)<!--ru-->
<!--ru-->
## Первоначальная настройка<!--ru-->
<!--ru-->
1. Убедитесь, что вы используете утилиту fastboot версии 34 или новее. Предыдущие версии содержат баги, что не позволяют команде `fastboot flashall` (которая понадобится по ходу инструкции) работать правильно.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot --version<!--ru-->
    ```<!--ru-->
<!--ru-->
2. Перезагрузитесь в режим fastboot и разблокируйте загрузчик, если не сделали этого ранее. Это приведет к стиранию всех пользовательских данных.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot flashing unlock<!--ru-->
    ```<!--ru-->
<!--ru-->
3. Перед первой установкой, на устройстве уже должна быть установлена в оригинальном виде та прошивка, пропатченную версию которой вы собираетесь ставить. Если это не так, сначала установите оригинальную непропатченную OTA.<!--ru-->
<!--ru-->
4. Извлекаем из пропатченного OTA модифицированные образы:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot ota extract \<!--ru-->
        --input /путь/к/ota.zip.patched \<!--ru-->
        --directory extracted \<!--ru-->
        --fastboot<!--ru-->
    ```<!--ru-->
<!--ru-->
    Если вы на всякий случай хотите прошить вообще все разделы из ОТА, извлечь их можно, указав аргумент `--all`.<!--ru-->
<!--ru-->
5. Установите переменную окружения `ANDROID_PRODUCT_OUT`, указав директорию с извлеченными файлами.<!--ru-->
<!--ru-->
    Для sh/bash/zsh (Linux, macOS, WSL):<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    export ANDROID_PRODUCT_OUT=extracted<!--ru-->
    ```<!--ru-->
<!--ru-->
    Для PowerShell (Windows):<!--ru-->
<!--ru-->
    ```powershell<!--ru-->
    $env:ANDROID_PRODUCT_OUT = "extracted"<!--ru-->
    ```<!--ru-->
<!--ru-->
    Для cmd (Командная строка или Терминал) (Windows):<!--ru-->
<!--ru-->
    ```bat<!--ru-->
    set ANDROID_PRODUCT_OUT=extracted<!--ru-->
    ```<!--ru-->
<!--ru-->
6. Прошейте извлеченные образы разделов.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot flashall --skip-reboot<!--ru-->
    ```<!--ru-->
<!--ru-->
    Обратите внимание, что так прошиваются лишь те образы, что относятся к системе. Разделы загрузчика и модема же остаются нетронутыми из-за ограничений fastboot. Если они не обновлены до необходимой версии, или вы не уверены в этом, после прошивки перейдите к пункту [обновлений](#обновления) и установите пропатченный OTA в режиме Recovery. Прошивка полного OTA гарантирует, что абсолютно все разделы будут обновлены.<!--ru-->
<!--ru-->
    Для устройств Pixel есть ещё один вариант: запуск скрипта `flash-base.sh` из папки заводских образов (factory images) обновит загрузчик и модем.<!--ru-->
<!--ru-->
7. После перезагрузки из fastbootd в загрузчик (bootloader), установите пользовательский публичный ключ AVB в загрузчик:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot reboot-bootloader<!--ru-->
    fastboot erase avb_custom_key<!--ru-->
    fastboot flash avb_custom_key /путь/к/avb_pkmd.bin<!--ru-->
    ```<!--ru-->
<!--ru-->
8. **[Опционально]** Перед блокировкой загрузчика загрузитесь в систему, дабы убедиться, что все подписано правильно.<!--ru-->
<!--ru-->
    Установите приложение Magisk или KernelSU и выполните следующую команду:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    adb shell su -c 'dmesg | grep libfs_avb'<!--ru-->
    ```<!--ru-->
<!--ru-->
    Если AVB работает корректно, будет выведено следующее сообщение:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    init: [libfs_avb]Returning avb_handle with status: Success<!--ru-->
    ```<!--ru-->
<!--ru-->
    Как ещё один вариант, Android-версию avbroot также можно использовать для [проверки разделов на устройстве](./README.extra.md#verifying-avb-hashes-and-signatures-on-device).<!--ru-->
<!--ru-->
9. Перезагрузитесь в fastboot и заблокируйте загрузчик. Это снова приведет к стиранию данных.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot flashing lock<!--ru-->
    ```<!--ru-->
<!--ru-->
    Подтвердите нажатием клавиш уменьшения громкости и включения, а после перезагрузитесь в систему.<!--ru-->
<!--ru-->
    Напоминаю: **не отключайте `Заводскую разблокировку`!**<!--ru-->
<!--ru-->
    **ПРЕДУПРЕЖДЕНИЕ**: Если вы прошили CalyxOS, мастер настройки [автоматически отключит опцию `Заводской разблокировки`.](https://github.com/CalyxOS/platform_packages_apps_SetupWizard/blob/7d2df25cedcbff83ddb608e628f9d97b38259c26/src/org/lineageos/setupwizard/SetupWizardApp.java#L135-L140) Не забудьте снова включить её вручную в настройках для разработчиков. Для перестраховки можете использовать [модуль `OEMUnlockOnBoot`,](https://github.com/chenxiaolong/OEMUnlockOnBoot) который автоматически включает пункт Заводской разблокировки при каждом запуске системы.<!--ru-->
<!--ru-->
10. Готово! Установка последующих обновлений системы, Magisk или KernelSU, описывается в [следующем разделе.](#обновления)<!--ru-->
<!--ru-->
## Обновления<!--ru-->
<!--ru-->
Обновления Android, Magisk и KernelSU выполняются одинаково – исключительно путем обновления или репатчинга того же самого OTA.<!--ru-->
<!--ru-->
1. Сгенерируйте новый пропатченный OTA согласно инструкции в разделе [использования.](#использование)<!--ru-->
<!--ru-->
2. Если обновляется Magisk или KernelSU, сначала установите их новый `.apk`. Если вы случайно открыли приложение, убедитесь, что оно **не начало** прошивать загрузочный образ. Если в самом приложении появится предложение обновить загрузочный образ, отклоните его.<!--ru-->
<!--ru-->
3. Перезагрузитесь в режим Recovery: `adb reboot recovery`. Если устройство повисло на сплеше с сообщением "No command", удерживайте кнопку питания, а затем один раз нажмите кнопку увеличения громкости.<!--ru-->
<!--ru-->
4. Обновитесь (Apply update from adb → `adb sideload <ota.zip.patched>`).<!--ru-->
<!--ru-->
5. Перезагрузите устройство. Обратите внимание, что при первом запуске после обновления ОС устройство может загружаться дольше обычного (иногда до нескольких минут).<!--ru-->
<!--ru-->
**ПРЕДУПРЕЖДЕНИЕ**: В силу специфики работы виртуального A/B в Android, сразу после установки OTA и перезагрузки, в фоновом режиме незаметно запускается операция слияния снапшотов. Во время этого процесса невозможно установить другой OTA через режим Recovery. Пока продолжается слияние снапшотов, избегайте любых действий, которые могут привести к бутлупу (например, установка модулей), поскольку в случае сбоя восстановить устройство получится только повторно разблокировав загрузчик, стирая все данные.<!--ru-->
<!--ru-->
Узнать текущий статус процесса можно, выполнив команду: `adb logcat -v color -s update_engine`. Дополнительно, если установлено [Custota](https://github.com/chenxiaolong/Custota) (даже если оно не настроено на использование пользовательского OTA-сервера), приложение будет отображать соответствующее уведомление до завершения операции слияния снапшота.<!--ru-->
<!--ru-->
## Возврат на заводскую прошивку<!--ru-->
<!--ru-->
Если вы хотите отказаться от использования avbroot и вернуться на стоковую прошивку:<!--ru-->
<!--ru-->
1. Перезагрузитесь в режим fastboot и разблокируйте загрузчик. Это приведет к стиранию всех пользовательских данных.<!--ru-->
<!--ru-->
2. Удалите пользовательский публичный ключ AVB.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    fastboot erase avb_custom_key<!--ru-->
    ```<!--ru-->
<!--ru-->
3. Прошейте стоковую прошивку. Готово.<!--ru-->
<!--ru-->
## OTA-обновления<!--ru-->
<!--ru-->
avbroot заменяет `/system/etc/security/otacerts.zip` в разделах системы и Recovery на новый архив, содержащий пользовательский сертификат подписи OTA. Это предотвращает случайную установку непропатченных OTA как из-под загруженной системы, так и при прошивке через Recovery.<!--ru-->
<!--ru-->
Рекомендуется отключить системное приложение для обновлений, чтобы оно не пыталось установить непропатченные OTA:<!--ru-->
<!--ru-->
* Стоковая (заводская) прошивка: Отключите `Автоматические обновления системы` (Automatic system updates в англ.) в настройках для разработчиков.<!--ru-->
* Кастомная прошивка: Отключите приложение обновлений системы (или запретите ему доступ к Интернету) через Настройки -> Приложения -> Все приложения -> (меню/три точки) -> Показать системные -> (найдите приложение обновлений, например Обновления системы/Updater).<!--ru-->
<!--ru-->
Это особенно важно для некоторых кастомных прошивок, поскольку их фирменное приложение для обновления системы может уйти в бесконечный цикл, загружая OTA-обновление, а затем повторяя попытку загрузки и установки при неудачной проверке подписи.<!--ru-->
<!--ru-->
Если вы хотите поднять собственный сервер для ОТА-обновлений, вам может быть интересно приложение [Custota.](https://github.com/chenxiaolong/Custota)<!--ru-->
<!--ru-->
## Режим обслуживания<!--ru-->
<!--ru-->
Некоторые устройства поставляются с режимом обслуживания, который загружает систему с чистым образом `userdata`, благодаря чему специалист по ремонту может проводить диагностику устройства, не имея доступа к пользовательским данным владельца.<!--ru-->
<!--ru-->
Если на устройстве есть root-права, использовать этот режим небезопасно. Если у вас обычная сборка Magisk/KernelSU, не подписанная вашим собственным ключом, кто угодно может установить официальное приложение Magisk/KernelSU в режиме обслуживания и запросто получить root-права без какой-либо аутентификации.<!--ru-->
<!--ru-->
Потому, чтобы безопасно использовать режим обслуживания:<!--ru-->
<!--ru-->
1. Отключите root-доступ на устройстве, пропатчив OTA с аргументом `--rootless` (вместо `--magisk` или `--prepatched`) и прошив его.<!--ru-->
<!--ru-->
2. Включите режим обслуживания.<!--ru-->
<!--ru-->
3. Получив отремонтированное устройство обратно, выйдите из режима обслуживания.<!--ru-->
<!--ru-->
4. Прошейте рутированный OTA в обычном режиме.<!--ru-->
<!--ru-->
Поскольку удаление root-прав и повторное их получение выполняются путем перепрошивки OTA, данные устройства стёрты не будут.<!--ru-->
<!--ru-->
## Предварительная инициализация устройства для Magisk<!--ru-->
<!--ru-->
Magisk версии 25211 и новее требует наличие раздела, доступного для записи пользовательских правил SELinux, к которым необходимо обращаться на ранних этапах загрузки. Его можно определить только на реальном устройстве, поэтому avbroot требует указания точного названия с помощью аргумента `--magisk-preinit-device <имя>`. Чтобы получить имя раздела:<!--ru-->
<!--ru-->
1. Извлеките загрузочный образ из оригинального, непропатченного OTA:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot ota extract \<!--ru-->
        --input /path/to/ota.zip \<!--ru-->
        --directory . \<!--ru-->
        --boot-only<!--ru-->
        --partition <название раздела> # init_boot или boot, в зависимости от устройства<!--ru-->
    ```<!--ru-->
<!--ru-->
2. Теперь нужно пропатчить загрузочный образ с помощью приложения Magisk. Это **ДОЛЖНО** быть сделано именно на целевом устройстве или устройстве той же модели! Имя раздела будет неверным и не подойдет, если пропатчить образ на устройстве иной модели.<!--ru-->
<!--ru-->
    Приложение Magisk выведет в лог строку, подобную следующей:<!--ru-->
<!--ru-->
    ```<!--ru-->
    - Pre-init storage partition device ID: <имя><!--ru-->
    ```<!--ru-->
<!--ru-->
    Также и avbroot может вывести информацию о разделе, обнаруженном Magisk, для этого выполните команду:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot boot magisk-info \<!--ru-->
        --image magisk_patched-*.img<!--ru-->
    ```<!--ru-->
<!--ru-->
    Имя раздела будет выведено как: `PREINITDEVICE=<имя>`.<!--ru-->
<!--ru-->
    Теперь, когда имя раздела известно, его нужно указать avbroot с помощью команды `--magisk-preinit-device <имя>`. Имя раздела стоит запомнить или сохранить где-нибудь на будущее, оно вряд ли изменится при обновлении Magisk.<!--ru-->
<!--ru-->
Если запустить приложение Magisk на целевом устройстве невозможно (например, оно не загружается), пропатчите OTA с аргументом `--ignore-magisk-warnings` и прошейте его. Затем выполните указанные выше шаги и повторно пропатчите OTA, но уже с указанием аргумента `--magisk-preinit-device <имя>`.<!--ru-->
<!--ru-->
## Проверка OTA<!--ru-->
<!--ru-->
Чтобы проверить все подписи и хэши, связанные с установкой OTA и процессом загрузки AVB, выполните команду:<!--ru-->
<!--ru-->
```bash<!--ru-->
avbroot ota verify \<!--ru-->
    --input /путь/к/ota.zip \<!--ru-->
    --cert-ota /путь/к/ota.crt \<!--ru-->
    --public-key-avb /путь/к/avb_pkmd.bin<!--ru-->
```<!--ru-->
<!--ru-->
Эта команда работает для любого OTA, независимо от того, пропатчено оно или нет.<!--ru-->
<!--ru-->
Если опции `--cert-ota` и `--public-key-avb` не указаны, то подписи проверяются только на корректность, не проверяя, совпадают ли они внутри всех файлов.<!--ru-->
<!--ru-->
## Подсказки через Tab<!--ru-->
<!--ru-->
Поскольку avbroot имеет множество опций, будет удобно настроить подсказки с автозаполнением для используемой оболочки. Конфигурации генерируются в самом avbroot.<!--ru-->
<!--ru-->
#### bash<!--ru-->
<!--ru-->
Добавьте в `~/.bashrc`:<!--ru-->
<!--ru-->
```bash<!--ru-->
eval "$(avbroot completion -s bash)"<!--ru-->
```<!--ru-->
<!--ru-->
#### zsh<!--ru-->
<!--ru-->
Добавьте в `~/.zshrc`:<!--ru-->
<!--ru-->
```bash<!--ru-->
eval "$(avbroot completion -s zsh)"<!--ru-->
```<!--ru-->
<!--ru-->
#### fish<!--ru-->
<!--ru-->
Добавьте в `~/.config/fish/config.fish`:<!--ru-->
<!--ru-->
```bash<!--ru-->
avbroot completion -s fish | source<!--ru-->
```<!--ru-->
<!--ru-->
#### PowerShell<!--ru-->
<!--ru-->
Добавьте в загрузочный скрипт PowerShell (`profile.ps1`):<!--ru-->
<!--ru-->
```powershell<!--ru-->
Invoke-Expression (& avbroot completion -s powershell)<!--ru-->
```<!--ru-->
<!--ru-->
## Расширенное использование<!--ru-->
<!--ru-->
### Использование заранее пропатченного boot.img<!--ru-->
<!--ru-->
avbroot может подменить используемый загрузочный образ на заранее пропатченный (вместо того, чтобы самостоятельно применять патч). Это пригодится в случае, если у вас уже имеется пропатченный через приложение Magisk образ ядра или образ с поддержкой KernelSU. Для этого используйте аргумент `--prepatched <загрузочный образ>` вместо `--magisk <apk>`. То есть, указав `--prepatched`, avbroot пропустит применение патчинга Magisk'ом, но по-прежнему применит патч OTA-сертификата.<!--ru-->
<!--ru-->
Обратите внимание, что avbroot проверяет совместимость предварительно пропатченного образа с оригинальным. Например, если поля заголовка образа не совпадают, или вовсе указан иной, незагрузочный образ, то процесс патча будет прерван. Эти проверки, конечно, ничего не гарантируют, но должны предостеречь от случайного использования некорректного образа. Чтобы обойти базовые проверки безопасности, укажите аргумент `--ignore-prepatched-compat`. Если вы хотите убрать вообще все проверки (чего делать крайне не рекомендуется), укажите его дважды.<!--ru-->
<!--ru-->
### Пропуск патча для root-доступа<!--ru-->
<!--ru-->
avbroot можно использовать для простого переподписания OTA, указав аргумент `--rootless` вместо `--magisk`/`--prepatched`. В таком случае пропатченный OTA не будет рутирован. Единственная модификация, которая будет применена – это замена сертификата проверки OTA, чтобы систему можно было обновлять с помощью будущих пропатченных OTA.<!--ru-->
<!--ru-->
### Пропуск патчинга сертификата OTA<!--ru-->
<!--ru-->
Вы можете пропустить изменение otacerts.zip, используя аргументы  `--skip-system-ota-cert` и `--skip-recovery-ota-cert`. **Не используйте их без веской причины.**<!--ru-->
<!--ru-->
При использовании `--skip-system-ota-cert`, сертификаты OTA в образе `system` изменены не будут. Это не позволит сторонним приложениям для OTA-обновлений устанавливать будущие пропатченные OTA из-под загруженной системы.<!--ru-->
<!--ru-->
При использовании `--skip-recovery-ota-cert`, сертификаты OTA в образах `vendor_boot` или `recovery` изменены не будут. **Это не позволит устанавливать будущие пропатченные OTA в режиме Recovery.**<!--ru-->
<!--ru-->
Если вы используете аргумент `--skip-recovery-ota-cert`, потому что уже добавили сертификат OTA в загрузочный образ вручную, рекомендуетcя [проверить пропатченный OTA](#проверка-ota), дабы удостовериться, что замена произведена корректно. Процесс верификации проверяет только копию сертификатов OTA в загрузочном образе, не проверяя копию в образе системы.<!--ru-->
<!--ru-->
### Пропуск всех патчей<!--ru-->
<!--ru-->
Чтобы внести самый минимум изменений, укажите аргументы:<!--ru-->
<!--ru-->
* `--skip-system-ota-cert`<!--ru-->
* `--skip-recovery-ota-cert`<!--ru-->
* `--rootless`<!--ru-->
* не используйте аргумент `--dsu`.<!--ru-->
<!--ru-->
Так, пользовательскими ключами будут переподписаны лишь образ `vbmeta` и OTA, остальные разделы останутся нетронутыми.<!--ru-->
<!--ru-->
**Это следует использовать только для устранения неполадок.** Без патчей сертификатов, поверх полученного OTA не получится установить никакие обновления.<!--ru-->
<!--ru-->
### Подмена образов<!--ru-->
<!--ru-->
avbroot поддерживает подмену целых образов в OTA, даже тех, что не являются загрузочными (например, `vendor_dlkm`). Образ можно заменить, используя аргумент `--replace <имя раздела> /путь/к/образу.img`.<!--ru-->
<!--ru-->
Единственное, что меняется – это то, откуда считывается файл. При использовании `--replace` вместо образа раздела из оригинального `payload.bin` в OTA, он берется напрямую по указанному вами пути. Заменяющие образы разделов должны иметь правильные колонтитулы vbmeta, соответствующие оригинальным.<!--ru-->
<!--ru-->
Это не влияет на ход применения пачтей. Например, при использовании Magisk, патч получения root-прав применяется к загрузочному образу одинаково, независимо от того, был ли он получен из оригинального `payload.bin` или это файл, указанный через `--replace`.<!--ru-->
<!--ru-->
### Очистка флагов vbmeta<!--ru-->
<!--ru-->
Некоторые сборки Android-прошивок могут поставляться с образом `vbmeta`, в котором флаги установлены таким образом, что AVB фактически отключен. Если avbroot сталкивается с такими образом, процесс патчинга завершается ошибкой с сообщением следующего типа:<!--ru-->
<!--ru-->
```<!--ru-->
Verified boot is disabled by vbmeta's header flags: 0x3<!--ru-->
```<!--ru-->
<!--ru-->
Чтобы принудительно включить AVB (очистив флаги), укажите аргумент `--clear-vbmeta-flags`.<!--ru-->
<!--ru-->
### Изменение алгоритма CoW сжатия для вирутального A/B<!--ru-->
<!--ru-->
Алгоритм CoW (copy-on-write) сжатия для виртуального A/B можно изменить, используя аргумент `--vabc-algo <алгоритм>`, указав `gz` или `lz4`. Как правило, по умолчанию OTA использует алгоритм, который совместим с изначальной версией Android, на которой поставлялось устройство.<!--ru-->
<!--ru-->
* Девайсы, поставляемые с Android 12, поддерживают `gz` и `brotli` (последний не поддерживается avbroot)<!--ru-->
* Девайсы, поставляемые с Android 14, поддерживают `lz4`<!--ru-->
* Девайсы, поставляемые с Android 15, поддерживают `zstd` (не поддерживается avbroot)<!--ru-->
<!--ru-->
Выбор быстрого алгоритма, такого как lz4, может значительно ускорить установку OTA из-под системы (при использованием стороннего приложения для OTA-обновлений). Однако, при установке OTA в режиме Recovery, разницы в скорости не будет.<!--ru-->
<!--ru-->
Обратите внимание, что текущая используемая версия Android должна поддерживать выбранный алгоритм сжатия. В противном случае установка завершится ошибкой. Например, попытка установить OTA-обновление с Android 14, использующее алгоритм lz4, приведет к ошибке, если установка производится из-под Android 13.<!--ru-->
<!--ru-->
### Использование в неинтерактивном режиме<!--ru-->
<!--ru-->
По умолчанию avbroot интерактивно запрашивает пароли к приватным ключам. Чтобы запустить avbroot в неинтерактивном режиме, можно:<!--ru-->
<!--ru-->
* Предоставить пароли через файлы:<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot ota patch \<!--ru-->
        --pass-avb-file /путь/к/avb.passphrase \<!--ru-->
        --pass-ota-file /путь/к/ota.passphrase \<!--ru-->
        <...><!--ru-->
    ```<!--ru-->
<!--ru-->
    На Unix-подобных системах "файлы" могут быть каналами ("pipes"). В оболочках, поддерживающих подстановку процесса (bash, zsh и т. д.), пароль можно запросить с помощью команды (например, запрашивая у менеджера паролей).<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    avbroot ota patch \<!--ru-->
        --pass-avb-file <(команда для запроса пароля AVB) \<!--ru-->
        --pass-ota-file <(команда для запроса пароля OTA) \<!--ru-->
        <...><!--ru-->
    ```<!--ru-->
<!--ru-->
* Предоставить пароли через переменные среды. Это менее безопасно, поскольку любой процесс, запущенный от имени того же пользователя, может видеть значения переменных среды.<!--ru-->
<!--ru-->
    ```bash<!--ru-->
    export PASSPHRASE_AVB="пароль AVB"<!--ru-->
    export PASSPHRASE_OTA="пароль OTA"<!--ru-->
<!--ru-->
    avbroot ota patch \<!--ru-->
        --pass-avb-env-var PASSPHRASE_AVB \<!--ru-->
        --pass-ota-env-var PASSPHRASE_OTA \<!--ru-->
        <...><!--ru-->
    ```<!--ru-->
<!--ru-->
* Использовать незашифрованные приватные ключи. Крайне не рекомендуется.<!--ru-->
<!--ru-->
### Извлечение образов из OTA<!--ru-->
<!--ru-->
Чтобы извлечь образы разделов, содержащихся в `payload.bin`, используйте команду:<!--ru-->
<!--ru-->
```bash<!--ru-->
avbroot ota extract \<!--ru-->
    --input /путь/к/ota.zip \<!--ru-->
    --directory extracted<!--ru-->
```<!--ru-->
<!--ru-->
По умолчанию извлекаются только те образы, которые потенциально могут быть пропатчены с помощью avbroot. Чтобы извлечь все образы, используйте опцию `--all`. Для извлечения конкретных образов используйте опцию `--partition <название раздела>`, которую можно указать несколько раз.<!--ru-->
<!--ru-->
Эта команда также поддерживает извлечение встроенного сертификата OTA и публичного ключа AVB с помощью опций `--cert-ota` и `--public-key-avb`. Чтобы извлечь только эти компоненты, укажите аргумент `--none`, чтобы пропустить извлечение образов разделов.<!--ru-->
<!--ru-->
### Режим записи ZIP<!--ru-->
<!--ru-->
По умолчанию, avbroot использует потоковую запись для вывода OTA во время патчинга. Это означает, что он вычисляет дайджест sha256 для цифровой подписи одновременно с записью файла. Такой режим приводит к тому, что в ZIP-файле появляются описатели данных, что является частью стандарта ZIP и работает на подавляющем большинстве устройств. Однако некоторые устройства могут иметь некорректно работающие парсеры ZIP-файлов и не смогут правильно прочитать ZIP-файлы OTA, содержащие описатели данных. Если это так, используйте опцию `--zip-mode seekable` при патчинге.<!--ru-->
<!--ru-->
Режим seekable записывает ZIP-файлы без описателей данных, но, как следует из названия, требует перемещения по файлу, вместо последовательной записи. Дайджест sha256 для цифровой подписи вычисляется после того, как ZIP-файл был полностью записан.<!--ru-->
<!--ru-->
### Подписание с использованием внешней программы<!--ru-->
<!--ru-->
avbroot поддерживает делегирование всех операций подписания RSA внешней программе с помощью опции `--signing-helper`. При использовании этой опции, для `--key-avb` и `--key-ota` должен быть указан публичный ключ вместо приватного.<!--ru-->
<!--ru-->
Для каждой операции подписания, avbroot будет вызывать программу с параметрами:<!--ru-->
<!--ru-->
```bash<!--ru-->
<helper> <algorithm> <public key><!--ru-->
```<!--ru-->
<!--ru-->
Алгоритм (`<algorithm>`) — это один из `SHA{256,512}_RSA{2048,4096}`, а публичный ключ (`<public key>`) — это тот, что был передан в avbroot. Внешняя программа может использовать публичный ключ для поиска соответствующего приватного ключа (например, на аппаратном модуле безопасности). avbroot запишет дайджест, отформатированный по PKCS#1 v1.5, в `stdin`, а внешняя программа должна выполнить операцию сырого подписания RSA и записать сырую подпись (октетная строка, соответствующая размеру ключа) в `stdout`.<!--ru-->
<!--ru-->
По умолчанию, это поведение совместимо с опцией `--signing_helper` в avbtool от AOSP. Однако avbroot дополнительно расширяет аргументы для поддержки неинтерактивного использования. Если используются опции `--pass-{avb,ota}-file` или `--pass-{avb,ota}-env-var`, то внешняя программа будет вызвана с двумя дополнительными аргументами, указывающими на файл пароля или переменную окружения.<!--ru-->
<!--ru-->
```bash<!--ru-->
<helper> <algorithm> <public key> file <pass file><!--ru-->
# или<!--ru-->
<helper> <algorithm> <public key> env <env file><!--ru-->
```<!--ru-->
<!--ru-->
Обратите внимание, что avbroot проверит подпись, возвращенную внешней программой, на соответствие с публичным ключом. Это гарантирует, что процесс патчинга завершится ошибкой, если был использован неправильный приватный ключ.<!--ru-->
<!--ru-->
### Размер страницы 16 КБ в настройках для разработчиков<!--ru-->
<!--ru-->
На современных устройствах с Android 16 и выше, в настройках для разработчиков может появиться опция переключения на ядро с размером страницы 16 КБ. Однако, эта функция не будет работать в системе, пропатченной с помощью avbroot, поскольку переключение данной настройки осуществляется путём установки инкрементальной OTA:<!--ru-->
<!--ru-->
* `/vendor/boot_otas/boot_ota_16k.zip` — используется для переключения на ядро с размером страницы 16 КБ (в разделе `boot` уже должно быть прошито ядро с размером страницы 4K)<!--ru-->
* `/vendor/boot_otas/boot_ota_4k.zip` — используется для переключения на ядро с размером страницы 4 КБ (в разделе `boot` уже должно быть прошито ядро с размером страницы 16K)<!--ru-->
<!--ru-->
Эти файлы (в `boot_otas`) невозможно прошить на системе, пропатченной avbroot, потому что `payload.bin` внутри них подписан ключом производителя. Кроме того, это неполноценные OTA-файлы: у них нет метаданных, характерных для OTA, а сам zip-файл не подписан. Это просто обычный архив, который содержит подписанный `payload.bin`.<!--ru-->
<!--ru-->
Поддержка `boot_otas` не планируется. Это потребует реализации функционала для модификации ФС в инкрементальных OTA и их дальнейшей обработки, что сделать очень непросто.<!--ru-->
<!--ru-->
Если вы всё же хотите завести эту функцию, можно попробовать вручную подписать файлы в `boot_otas` собственным ключом. Поскольку инкрементальные OTA не пересоздаются, раздел `boot` должен оставаться без изменений во время выполнения команды `avbroot ota patch`.<!--ru-->
<!--ru-->
1. Распакуйте `vendor.img` с помощью avbroot и [afsr](https://github.com/chenxiaolong/afsr):<!--ru-->
    ```bash<!--ru-->
    avbroot avb unpack -i vendor.img<!--ru-->
    afsr unpack -i raw.img<!--ru-->
    ```<!--ru-->
<!--ru-->
2. Извлеките `payload.bin` из `boot_otas/boot_ota_16k.zip`.<!--ru-->
<!--ru-->
3. Переподпишите `payload.bin` вашим OTA-ключом:<!--ru-->
    ```bash<!--ru-->
    avbroot payload repack \<!--ru-->
        -i payload.bin.orig \<!--ru-->
        -o payload.bin \<!--ru-->
        -k ota.key \<!--ru-->
        --output-properties payload_properties.txt<!--ru-->
    ```<!--ru-->
<!--ru-->
4. Создайте новый zip, включающий `payload.bin` и `payload_properties.txt`. Файлы должны быть добавлены без сжатия (например, с помощью `zip -0`).<!--ru-->
<!--ru-->
5. Повторите эту процедуру для `boot_otas/boot_ota_4k.zip`.<!--ru-->
<!--ru-->
6. Соберите `vendor.img` обратно и подпишите его вашим AVB-ключом:<!--ru-->
    ```bash<!--ru-->
    afsr pack -o raw.img<!--ru-->
    avbroot avb pack -o vendor.img -k avb.key --recompute-size<!--ru-->
    ```<!--ru-->
<!--ru-->
7. Пропатчите обычный OTA-архив с прошивкой, подменив `vendor` на модифицированный образ:<!--ru-->
    ```bash<!--ru-->
    avbroot ota patch \<!--ru-->
        --replace vendor <модифицированный vendor.img> \<!--ru-->
        <дальше указываются аргументы, как при обычном патчинге><!--ru-->
    ```<!--ru-->
<!--ru-->
## Сборка из исходного кода<!--ru-->
<!--ru-->
Убедитесь, что у вас установлен [набор инструментов Rust.](https://www.rust-lang.org/ru/) Затем выполните:<!--ru-->
<!--ru-->
```bash<!--ru-->
cargo build --release<!--ru-->
```<!--ru-->
<!--ru-->
Исполняемый файл будет записан в `target/release/avbroot`.<!--ru-->
<!--ru-->
Дебаг-сборки тоже работают, но они будут работать значительно медленнее (в вычислениях sha256), потому что оптимизации компилятора отключены.<!--ru-->
<!--ru-->
### Кросс-компиляция на Android<!--ru-->
<!--ru-->
Чтобы использовать кросс-компиляцию на Android, установите [cargo-android](https://github.com/chenxiaolong/cargo-android) и воспользуйтесь оболочкой `cargo android`. Чтобы создать релизную сборку для aarch64, выполните:<!--ru-->
<!--ru-->
```bash<!--ru-->
cargo android build --release --target aarch64-linux-android<!--ru-->
```<!--ru-->
<!--ru-->
Возможно выполнение тестов, если хост работает под управлением Linux, установлен qemu-user-static, а исполняемый файл собран с `RUSTFLAGS=-C target-feature=+crt-static` и `--features static`.<!--ru-->
<!--ru-->
## Проверка цифровых подписей<!--ru-->
<!--ru-->
Чтобы проверить цифровые подписи, [следуйте этой инструкции.](https://github.com/chenxiaolong/chenxiaolong/blob/master/VERIFY_SSH_SIGNATURES.md)<!--ru-->
<!--ru-->
## Вклад<!--ru-->
<!--ru-->
Буду рад вашему вкладу в разработку! Однако я вряд ли приму изменения для поддержки устройств, которые ведут себя значительно иначе, чем устройства Pixel.<!--ru-->
<!--ru-->
## Лицензия<!--ru-->
<!--ru-->
avbroot распространяется по лицензии GPLv3. Полный текст лицензии см. в [`LICENSE`.](./LICENSE)<!--ru-->
<!--ru-->
