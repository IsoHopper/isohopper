# IsoHopper

> **SUPER EXPERIMENTAL — pending human testing.**
> Physical disk writes are disabled. Hardware and operating-system boot compatibility have not been established.

IsoHopper is an independent Rust toolkit for inspecting image libraries, reviewing device safety, and developing multiboot media. Studio is a Tauri desktop interface for the same work.

![IsoHopper Studio: image library, device details and partition plan](docs/screenshots/studio.jpg)

*Screenshot uses a simulated target and tiny local test files with real checksums.*

## Current capabilities

- Rust CLI: recursive image inspection, streaming checksums, YAML/TOML configuration, supplied-key signed-manifest validation, and partition planning.
- Studio: native file and folder selection, streaming SHA-256, full checksums, relative folder paths, configuration editing, and operation logs. Browser-only intake is limited to 512 MiB per file.
- Read-only macOS, Linux and Windows host-device inspection. Unknown safety information remains unknown; inspected host devices cannot be selected for preparation.
- Explicitly labelled fixture devices for preparation simulation and typed risk confirmation. Simulation performs no disk writes.
- New regular-file GPT images with primary/backup metadata and optional FAT32 A/B slots containing an x64 EFI application. Existing output files are refused; the data partition remains unformatted.
- An x64 UEFI launcher with configurable, confirmed reboot/shutdown/firmware-setup actions. Studio power buttons are inert previews, not host power controls.
- Optional supplied x64 EFI utility in both boot slots, launched through firmware `LoadImage`/`StartImage` after confirmation. Firmware security rejections are preserved.

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

This is a development build, not a tested release.

For the browser preview, run `npm --prefix studio/frontend run dev` and open the local URL printed by Vite. This uses a labelled fixture adapter; native file selection and host inspection require Studio.

## Checks

```sh
./scripts/check.sh --install-browser
cargo test --manifest-path studio/src-tauri/Cargo.toml --locked
```

The shared script checks Rust, frontend code, and Chromium at desktop and compact widths. Native Studio tests are separate. See [CONTRIBUTING.md](CONTRIBUTING.md) for local development, browser-test discovery without execution, and the optional QEMU firmware smoke test. A passing firmware-entry test is not evidence of OS boot compatibility.

Local validation on 28 October 2026: **164 Rust workspace tests, 4 firmware-handoff tests, 2 native tests, 15 frontend tests and 20 firmware-harness tests passed**. The opt-in 600 MiB native import also passed. QEMU passed firmware entry, EFI test-utility handoff/return, and confirmed guest power requests; the next firmware setup screen was not inspected. A separate QEMU suite passed four Secure Boot cases with disposable keys: signed utility accepted; unsigned, tampered and revoked copies rejected. Windows inventory passed fixtures and cross-compilation; native Windows checks run in a manual workflow. Chromium has 32 automated cases; current CI status is shown in [Actions](https://github.com/IsoHopper/isohopper/actions). No physical-device or operating-system boot tests have passed yet.

![Memtest86+ 9.00 running after IsoHopper EFI handoff in QEMU](docs/screenshots/memtest-qemu.png)

*[Memtest86+ 9.00](https://memtest.org/) reached its testing screen through IsoHopper in QEMU using the checksum-verified official EFI binary. This proves that utility handoff, not a completed memory test, hardware compatibility, or Secure Boot enforcement.*

## Relation to Ventoy

[Ventoy](https://www.ventoy.net/en/index.html) provides direct booting of image files and publishes an extensive compatibility list. IsoHopper is a separate implementation at an early stage, with an emphasis on inspectable metadata and explicit device authorization. It does not yet provide equivalent boot coverage or serve as a drop-in replacement.

## License and contact

Original source © 2026 S33G, licensed under [GPL-3.0-or-later](LICENSE). See [contributors](CONTRIBUTORS.md), [contribution guidance](CONTRIBUTING.md), and [security reporting](SECURITY.md).
