# IsoHopper

> **SUPER EXPERIMENTAL — pending human testing.**
> Physical disk writes are disabled. Hardware and operating-system boot compatibility have not been established.

IsoHopper is a Rust toolkit for image inspection, device safety checks and experimental multiboot media. Studio is its Tauri desktop interface.

Public releases are on hold until real USB preparation and operating-system boot tests pass. The first human-test target is the Windows app preparing a USB for an x64 UEFI PC. Current CI packages are development artifacts, not a working multiboot release.

![IsoHopper Studio: image library, device details and partition plan](docs/screenshots/studio.jpg)

*Screenshot uses a simulated target and tiny local test files with real checksums.*

## Current capabilities

- Rust CLI: recursive image inspection, streaming checksums, YAML/TOML configuration, supplied-key signed-manifest validation, and partition planning.
- Studio: native file and folder selection, streaming SHA-256, full checksums, relative folder paths, configuration editing, and operation logs. Browser-only intake is limited to 512 MiB per file.
- Read-only macOS, Linux and Windows device inspection. Host devices remain blocked from preparation.
- Labelled mock devices, preparation simulation and typed confirmation; no disk writes.
- New GPT test images with verified primary/backup metadata and FAT32 A/B boot slots. Existing files are refused; the data partition remains unformatted.
- `image engine`: offline import of the exact Ventoy 1.1.18 Linux archive, bounded decoding and verified GPT/engine image creation. Data remains unformatted; this is not USB preparation.
- An x64 UEFI launcher with confirmed EFI utility handoff and configurable reboot/shutdown/firmware-setup actions. Firmware security policy applies. Studio power controls are inert previews.

Image inspection and checksum calculation do not prove publisher authenticity or boot compatibility. Physical-device preparation, an end-to-end OS boot workflow, and production Secure Boot signing remain unavailable.

## Build and run

Use the pinned Rust toolchain in `rust-toolchain.toml` and Node.js 22.12 or newer. Native Studio builds also need the [Tauri 2 platform prerequisites](https://v2.tauri.app/start/prerequisites/).

From the repository root:

```sh
cargo run -p isohopper-cli --locked -- --help
cargo run -p isohopper-cli --locked -- devices --json
cargo run -p isohopper-cli --locked -- list --demo
npm --prefix studio/frontend ci
npm --prefix studio/frontend run build
```

Build a local macOS app bundle with the pinned Tauri CLI:

```sh
(cd studio/src-tauri && npx --yes @tauri-apps/cli@2.12.4 build --bundles app)
```

This builds locally. The packaging workflow can build development artifacts manually or when an experimental tag is pushed; publication is disabled while the real USB workflow is incomplete.

For the browser demo, run `npm --prefix studio/frontend run dev` and append `/?demo=1` to the local origin printed by Vite. Demo mode uses labelled fixtures. Native Studio uses real file selection and host inspection; it never falls back to fixtures.

## Checks

```sh
./scripts/check.sh --install-browser
cargo test --manifest-path studio/src-tauri/Cargo.toml --locked
```

The shared script checks Rust, frontend code, and Chromium at desktop and compact widths. Native Studio tests are separate. See [CONTRIBUTING.md](CONTRIBUTING.md) for local development, browser-test discovery without execution, and the optional QEMU firmware smoke test. A passing firmware-entry test is not evidence of OS boot compatibility.

Validation on 28 October 2026:

- **437 Rust workspace tests and 32 native Studio tests passed locally for `1ad036b`.** Four workspace fixture tests were skipped by default; pinned archive import and CLI image creation also passed separately against the real archive. Unchanged frontend/tooling checks passed 36 frontend tests, 48 Python tests and 64 Chromium cases. The workspace includes 23 catalogue tests also covered by native tests. Browser bridge tests use mocks; filesystem tests use real temporary files. Hosted results are in [Actions](https://github.com/IsoHopper/isohopper/actions).
- [Windows storage integration](https://github.com/IsoHopper/isohopper/actions/runs/40723017082) passed source-handle protection, authenticated cross-process file transfer, retained target checks, volume locks, and a 256 MiB VHD write/readback. Three nested files copied to an unlettered exFAT volume matched their SHA-256 hashes after read-only reattachment; GPT and both boot slots were preserved. Source-change, read-only disk, deadline and cancellation refusals also passed. These are real Windows API tests on disposable virtual disks, not USB hardware tests.
- [Windows Studio integration](https://github.com/IsoHopper/isohopper/actions/runs/40724726404) passed 31 native tests, fresh NSIS installation, installed helper permissions/checksum and process-role checks, and repeated silent/passive installer refusal with unchanged files and permissions. Interactive UAC remains untested; the helper connection check does not enable preparation.
- Windows CI cannot retain active pagefile handles (Win32 32). The low-level executable backing query also fails there, but the protected-path WOF API successfully reports both installed files as inline. Full preflight integration remains under development; neither result enables physical preparation.
- The Rust-built GPT engine image booted Alpine 3.24.3 in QEMU to a live root shell; the running guest verified its mounted ISO checksum. Data was populated by the test harness, not the production Windows staging pipeline.
- QEMU passed firmware entry, EFI utility handoff/return, and confirmed guest power requests. The next firmware setup screen was not inspected.
- An Ubuntu 6.8.0-147 kernel reached PID 1 in a tiny diagnostic initramfs and shut down cleanly. With disposable Secure Boot keys, its signed unified kernel image booted; unsigned, tampered and revoked copies were refused. The smaller EFI test utility passed the same four cases.

The diagnostic is not an Ubuntu installer. General ISO booting, installation compatibility, physical hardware and production signing remain unvalidated. Test recipes and mocks are included; generated images and keys are not.

![Memtest86+ 9.00 running after IsoHopper EFI handoff in QEMU](docs/screenshots/memtest-qemu.png)

*[Memtest86+ 9.00](https://memtest.org/) reached its testing screen through IsoHopper in QEMU using the checksum-verified official EFI binary. This proves that utility handoff, not a completed memory test, hardware compatibility, or Secure Boot enforcement.*

## Relation to Ventoy

[Ventoy](https://www.ventoy.net/en/index.html) provides direct image booting and extensive compatibility coverage. IsoHopper's experimental engine-image builder uses its pinned, externally supplied boot components; that compatibility work belongs to Ventoy and its contributors. IsoHopper adds a Rust preparation layer and desktop interface focused on inspectable metadata and explicit device authorization. It does not yet offer a complete replacement. See [third-party components](THIRD_PARTY.md).

## License and contact

Original source © 2026 S33G, licensed under [GPL-3.0-or-later](LICENSE). See [contributors](CONTRIBUTORS.md), [contribution guidance](CONTRIBUTING.md), and [security reporting](SECURITY.md).
