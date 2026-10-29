# First Windows USB preparation test

> **Super experimental — pending human hardware testing.** Windows preparation writes a real device after explicit confirmation. Automated tests use disposable virtual disks; they do not establish physical USB or OS installation compatibility.

Use a spare USB drive or SD card whose entire contents may be erased. Back up anything needed first. macOS and Linux builds provide inspection and local image hashing only.

## Before starting

- Run the Windows x64 installer; it installs, upgrades or repairs the fixed machine location, `Program Files\IsoHopper`. From `v0.1.0-experimental.5`, you do not need to uninstall an earlier release first. Saved settings, the image library and cached engine remain in your user profile. Close Studio after any active preparation finishes, then retry if setup reports that files are in use.
- Sign in with an administrator account and UAC enabled. Launch Studio normally, not **Run as administrator**; approve the bundled helper's UAC request using that same account. Portable copies and elevation under a different account are unsupported. **Check elevated helper** tests the connection without accessing disks.
- Keep at least **2 × the target's exact capacity + 256 MiB** free on the installation volume for temporary staging. This budget is based on the whole device, not the size of selected images; other applications may consume additional space.
- Target support is limited to USB/SD devices with 512-byte logical sectors and 512- or 4096-byte physical sectors. Listing a candidate does not establish eligibility. The helper requires complete native identity, partition, storage-pool, encryption, protected-storage and locking evidence. Unknown or conflicting evidence blocks preparation; do not bypass a refusal. Some USB/SD devices may be refused when Windows reports partial storage use or incomplete safety evidence.

In the current source build, **Install ISOHopper** downloads the pinned engine automatically when needed, verifies its size and SHA-256, and reuses a verified local cache. Manual download and offline archive selection are under **Advanced**. Older releases expose these controls directly. Downloading never runs upstream scripts or writes a device; it never selects a newer engine automatically.

For offline use, or with `v0.1.0-experimental.2`, download the unchanged [Ventoy 1.1.18 Linux archive](https://github.com/ventoy/Ventoy/releases/download/v1.1.18/ventoy-1.1.18-linux.tar.gz) from the [upstream release](https://github.com/ventoy/Ventoy/releases/tag/v1.1.18), even though Studio runs on Windows. IsoHopper does not bundle the archive or OS images. Leave it compressed and do not run its installer scripts.

```text
File:   ventoy-1.1.18-linux.tar.gz
Bytes:  20320548
SHA256: d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54
```

Studio checks both the exact size and SHA-256. For an independent check, use `Get-FileHash .\ventoy-1.1.18-linux.tar.gz -Algorithm SHA256` in PowerShell.

These builds remember the engine, image library and Studio preferences between sessions. Restored images are reopened and rehashed; missing or changed files produce warnings and must be selected again. Removing an image from the library removes its saved selection, not the original file. Target preferences are matched against fresh device observations; saved selections never authorize a write.

## Install an empty bootable drive

1. Open **Prepare drive** and choose the USB or SD device. Check its model, device ID, serial, exact capacity and sector sizes. Refresh and select again if the selection expires.
2. Select **Install ISOHopper**. Studio gets the verified engine if needed, then requests Windows elevation. The helper checks the target and builds a private GPT image with an exFAT data partition, the boot-menu theme and no OS images. Staging does not write the physical target. The **Image library is independent**: imported, missing or failed images are not included in this installation.
3. At **Review & confirm**, inspect the **Helper-bound target**, image SHA-256 and description digest. These identify the retained device and staged image. No ISO is required.
4. Enter or paste **`ENABLE_WRITE`**, then click **Install ISOHopper** again. The confirmation applies only to this device and this installation job. This authorizes replacement of the entire selected device, including every existing partition and file. The helper rechecks readiness and acquires all required volume locks before writing.
5. Wait for writing, flushing and full readback verification to finish. Then copy your image files onto the drive's data partition using File Explorer. Subdirectories such as `Windows\Win11.iso` and `Mac\MacOS.img` are supported; file format support does not guarantee that a particular operating system boots.

The separate **Image library** supports native file/folder import and SHA-256 inspection. Native pickers stream large files without an artificial size cap. Copy buttons preserve complete checksums and device identifiers. A checksum fingerprints bytes, not their publisher or boot compatibility.

Candidates larger than 256 GiB are hidden by default; use **Show large drives** to reveal them. Studio prefers a unique suitable small USB/SD device labelled **IsoHopper**, or the only suitable small candidate. Review its ID, serial and capacity even when selected automatically. The helper can still refuse a suggested candidate after its full checks.

Progress byte counts are local to the current phase. The phase field reports work such as `verifying_sources`, `verifying_archive`, `checking_target`, `building_seed`, `formatting_data`, `copying_sources`, `verifying_sources`, `exporting_raw`, then `await_confirmation`. After confirmation, expect `checking_readiness`, `locking_target`, `writing_target`, `flushing_target` and `verifying_target`.

## Completion, cancellation and boot test

A successful result has phase **`succeeded`**, **Written / verified** byte counts equal to the target's exact capacity, and **Target may be incomplete: false**. **Activity → Export activity** saves a JSON test receipt containing the latest preparation snapshot (job ID, helper-bound target, image SHA-256, description digest, counts, retained source manifest and final message), runtime capabilities and session events. Capability enabled does not mean a write occurred; check the snapshot outcome and byte counts. This file is exported on request, not written automatically.

**Cancel preparation** requests cooperative cancellation. Wait for the final result: an in-flight operating-system read, UAC prompt or Windows formatting call can delay cleanup. Cancellation does not forcibly interrupt those operations. Do not disconnect the target or kill Studio/helper during a job. After writing starts, cancellation, failure or a lost connection can leave the target incomplete; there is no rollback. A pending or disconnected job is not a successful write.

After a successful write and helper cleanup, safely eject the device. For the initial boot test, use a spare **x64 UEFI** PC with Secure Boot off and choose its UEFI USB entry. After copying images to the drive, check that the engine menu lists the expected nested paths, then test one known image without installing over the PC's disks. Secure Boot, arbitrary OS images and installation compatibility are not established by a successful write or checksum.

Newly prepared drives include the fixed IsoHopper boot-menu theme under `ventoy/isohopper/`, configured by `ventoy/ventoy.json`. The menu lists the images actually on the drive and retains the engine's tools and F7 text fallback. Existing USB drives are not updated automatically.

Studio's editable launcher settings and power-action previews are **not applied to the engine USB menu**. They do not reboot, shut down or enter firmware setup on the Windows host.
