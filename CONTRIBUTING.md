# Contributing

IsoHopper is **super experimental and pending human testing**. Keep changes small enough to review and describe the concrete behavior they change.

## Development

Use the Rust version in `rust-toolchain.toml`, Node.js 22.12 or newer, and the [Tauri 2 platform prerequisites](https://v2.tauri.app/start/prerequisites/) for native Studio work. Install frontend dependencies with `npm --prefix studio/frontend ci`.

Run the shared checks from the repository root:

```sh
./scripts/check.sh --install-browser
```

This runs Rust formatting, clippy, workspace tests, Python firmware-harness tests, a locked frontend install, unit tests, the production build, and Chromium tests at desktop and compact widths. Once Chromium is installed, `./scripts/check.sh` runs the same checks without reinstalling it. `./scripts/check.sh --no-browser` lists browser cases but does not execute them; report that distinction.

The native Studio crate is separate from the workspace. After building the frontend, check it explicitly:

```sh
npm --prefix studio/frontend run build
cargo test --manifest-path studio/src-tauri/Cargo.toml --locked
```

## Firmware tests

These optional commands create a new regular-file image and test firmware entry in QEMU. They require the pinned Rust UEFI target, QEMU, and matching x64 OVMF/EDK2 code and variable-template files. Replace the firmware paths below with your installed files; choose a new output-image path on each run.

```sh
cargo build -p isohopper-launcher --features firmware --target x86_64-unknown-uefi --release --locked
cargo run -p isohopper-cli --locked -- image create /tmp/isohopper-test.img --size-mib 256 --efi target/x86_64-unknown-uefi/release/isohopper-launcher.efi
cargo run -p isohopper-cli --locked -- image verify /tmp/isohopper-test.img --efi target/x86_64-unknown-uefi/release/isohopper-launcher.efi
python3 scripts/firmware-smoke.py --image /tmp/isohopper-test.img --code /path/to/OVMF_CODE.fd --vars /path/to/OVMF_VARS.fd
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Add `--utility /path/to/tool.efi` to both image commands to embed and verify a supplied x64 EFI application. The launcher offers it with `U`, then requires `Y`. Its firmware loader preserves security-policy rejections.

The smoke test checks a firmware-entry marker. Add `--action shutdown`, `--action reboot`, or `--action firmware-setup` to exercise confirmed guest power requests. Firmware setup checks the request and reset, not the next setup screen. `--action utility` requires the source-built `isohopper-test-utility` (feature `test-utility`); it checks ordered start/entry/return markers. These tests establish neither OS compatibility nor Secure Boot enforcement. They attach no physical disk. Native and firmware workflows run only when manually dispatched.

## Review expectations

- Add a regression test for a bug, including its failure case. Use synthetic image files and mocked device inventories.
- Preserve exclusive file creation, retained file handles, checked bounds, and fail-closed device authorization. Do not turn fixtures or read-only host inventory into writable targets.
- Preserve relative image paths and report skipped entries or incomplete inspection explicitly.
- Separate checksum calculation, publisher authentication, firmware execution, and operating-system boot evidence in code, UI, and test reports.
- Include commands run and their results. For UI changes, include desktop and compact screenshots without personal data.
- Keep secrets, generated binaries, local test media, and environment-specific logs out of changes. Preserve GPL-3.0-or-later source notices.

For sensitive findings, use the contact in [SECURITY.md](SECURITY.md).
