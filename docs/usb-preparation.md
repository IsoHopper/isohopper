# First Windows USB preparation test

> **Super experimental — pending human hardware testing.** Windows preparation writes a real device after explicit confirmation. Automated tests use disposable virtual disks; they do not establish physical USB or OS installation compatibility.

Use a spare USB drive or SD card whose entire contents may be erased. Back up anything needed first. macOS and Linux builds provide inspection and local image hashing only.

## Before starting

- Run the Windows x64 installer; it installs, upgrades or repairs the fixed machine location, `Program Files\IsoHopper`. From `v0.1.0-experimental.4`, you do not need to uninstall an earlier release first. Saved settings, the image library and cached engine remain in your user profile. Close Studio after any active preparation finishes, then retry if setup reports that files are in use.
- Sign in with an administrator account and UAC enabled. Launch Studio normally, not **Run as administrator**; approve the bundled helper's UAC request using that same account. Portable copies and elevation under a different account are unsupported. **Check elevated helper** tests the connection without accessing disks.
- Keep at least **2 × the target's exact capacity + 256 MiB** free on the installation volume for temporary staging. This budget is based on the whole device, not the size of selected images; other applications may consume additional space.
- Target support is limited to USB/SD devices with 512-byte logical sectors and 512- or 4096-byte physical sectors. Listing a candidate does not establish eligibility. The helper requires complete native identity, partition, storage-pool, encryption, protected-storage and locking evidence. Unknown or conflicting evidence blocks preparation; do not bypass a refusal. Some USB/SD devices may be refused when Windows reports partial storage use or incomplete safety evidence.

Starting with `v0.1.0-experimental.3`, builds offer **Download engine** under **Prepare device**. This downloads the exact supported archive from the official GitHub release, reports byte progress and SHA-256, verifies it, and selects it for preparation. A verified copy is cached locally and rechecked when reused. **Cancel download** requests cleanup; wait for its final state. Downloading does not request elevation, run upstream scripts or write a device. It never selects a newer engine automatically.

For offline use, or with `v0.1.0-experimental.2`, download the unchanged [Ventoy 1.1.18 Linux archive](https://github.com/ventoy/Ventoy/releases/download/v1.1.18/ventoy-1.1.18-linux.tar.gz) from the [upstream release](https://github.com/ventoy/Ventoy/releases/tag/v1.1.18), even though Studio runs on Windows. IsoHopper does not bundle the archive or OS images. Leave it compressed and do not run its installer scripts.

```text
File:   ventoy-1.1.18-linux.tar.gz
Bytes:  20320548
SHA256: d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54
```

Studio checks both the exact size and SHA-256. For an independent check, use `Get-FileHash .\ventoy-1.1.18-linux.tar.gz -Algorithm SHA256` in PowerShell.

These builds remember the engine, image library and Studio preferences between sessions. Restored images are reopened and rehashed; missing or changed files produce warnings and must be selected again. Removing an image from the library removes its saved selection, not the original file. Target preferences are matched against fresh device observations; saved selections never authorize a write.

## Prepare and review

1. Open **Prepare drive**. Images are optional: leave the library empty to prepare the engine and an empty exFAT data partition, then copy images onto it later. Otherwise use **Add images** for individual files or **Import folder** for a directory tree. All imported rows are included. Folder paths are relative to the selected directory: importing a parent containing `Windows\Win11.iso` and `Mac\MacOS.img` preserves those subdirectories. Duplicate destination paths, including case-only collisions, are refused.
2. Wait for hashing and review each relative path, exact byte count and full SHA-256. Use the native pickers for preparation; they stream large files. Browser drag-and-drop is a 512 MiB-per-file preview and cannot supply a native preparation job. A checksum fingerprints bytes; it does not verify the publisher or establish that an image can boot.
3. Under **Prepare device**, use **Download engine** and wait for `ready`, or **Choose engine archive** for a local copy. Then choose the target under **Target candidate (helper revalidates)**. Review **Candidate device fields**, especially the device ID, serial, size and sector geometry. Refresh devices and select again if the selection expires.
4. Select **Build preparation image**. Studio rechecks every source and the engine archive, reporting bytes and allowing cancellation, then requests UAC. The helper checks the target, builds a private GPT image, formats its staged data volume as exFAT, copies the selected files, verifies them, and seals a complete raw image. The physical target is not written during staging.
5. At `await_confirmation`, review **Helper-bound target**, **Image SHA-256**, **Description digest** and the retained **Job source manifest**, including every path, size and SHA-256. These identify the actual retained target and complete staged image. **Source handles released: true** means the original imports were closed after staging; their files were not deleted. For a later job, reimport them or restart Studio to restore the saved library.
6. Type the displayed challenge exactly, then click **Write device**. It is case-sensitive; paste is disabled and Enter does not submit. This authorizes replacement of the **entire target device**, including every existing partition and file. The helper rechecks readiness and acquires all required volume locks before writing.

Candidates larger than 256 GiB are hidden by default; use **Show large drives** to reveal them. Studio prefers a unique suitable small USB/SD device labelled **IsoHopper**, or the only suitable small candidate. Review its ID, serial and capacity even when selected automatically. The helper can still refuse a suggested candidate after its full checks.

Progress byte counts are local to the current phase. The phase field reports work such as `verifying_sources`, `verifying_archive`, `checking_target`, `building_seed`, `formatting_data`, `copying_sources`, `verifying_sources`, `exporting_raw`, then `await_confirmation`. After confirmation, expect `checking_readiness`, `locking_target`, `writing_target`, `flushing_target` and `verifying_target`.

## Completion, cancellation and boot test

A successful result has phase **`succeeded`**, **Written / verified** byte counts equal to the target's exact capacity, and **Target may be incomplete: false**. **Activity → Export activity** saves a JSON test receipt containing the latest preparation snapshot (job ID, helper-bound target, image SHA-256, description digest, counts, retained source manifest and final message), runtime capabilities and session events. Capability enabled does not mean a write occurred; check the snapshot outcome and byte counts. This file is exported on request, not written automatically.

**Cancel preparation** requests cooperative cancellation. Wait for the final result: an in-flight operating-system read, UAC prompt or Windows formatting call can delay cleanup. Cancellation does not forcibly interrupt those operations. Do not disconnect the target or kill Studio/helper during a job. After writing starts, cancellation, failure or a lost connection can leave the target incomplete; there is no rollback. A pending or disconnected job is not a successful write.

After a successful write and helper cleanup, safely eject the device. For the initial boot test, use a spare **x64 UEFI** PC with Secure Boot off and choose its UEFI USB entry. Check that the engine menu lists the expected nested images, then test one known image without installing over the PC's disks. Secure Boot, arbitrary OS images and installation compatibility are not established by a successful write or checksum.

Studio's custom launcher settings and power-action previews are **not applied to the current engine USB menu**. They do not reboot, shut down or enter firmware setup on the Windows host.
