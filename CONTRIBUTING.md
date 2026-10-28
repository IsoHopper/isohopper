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

On Windows, first build and stage the matching helper from the repository root:

```sh
cargo build --locked -p isohopper-helper
python scripts/stage-windows-helper.py --source target/debug/isohopper-helper.exe
```

Stage the release helper instead when packaging a release build. Studio embeds its checksum. The experimental elevation check requires a fresh machine-wide NSIS installation in `Program Files\IsoHopper` on the Windows system drive; portable builds cannot run it. It performs a read-only connection test, never disk preparation. Interactive UAC remains unvalidated. Windows Studio CI tests installation and existing-install refusal only on a disposable runner.

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

The manual firmware workflow has an optional `secure_boot` checkbox, off by default. It tests acceptance of a utility signed with a disposable certificate and rejection of unsigned, tampered, and certificate-revoked copies. Each case must also report that firmware Secure Boot is enabled. These are QEMU tests with local test keys, not production signing or physical hardware qualification.

For the same test locally on Ubuntu 24.04, install `qemu-system-x86`, `ovmf`, `openssl`, [`sbsigntool`](https://packages.ubuntu.com/noble/sbsigntool), and `python3-venv`. Use a virtual environment for the pinned [`virt-firmware` 26.9](https://pypi.org/project/virt-firmware/26.9/) tool. After the launcher build above:

```sh
python3 -m venv .local/secure-boot-venv
.local/secure-boot-venv/bin/python -m pip install 'virt-firmware==26.9'
cargo build -p isohopper-cli --release --locked
cargo build -p isohopper-launcher --features test-utility --bin isohopper-test-utility --target x86_64-unknown-uefi --release --locked
PATH="$PWD/.local/secure-boot-venv/bin:$PATH" python3 scripts/secure-boot-smoke.py \
  --cli target/release/isohopper \
  --launcher target/x86_64-unknown-uefi/release/isohopper-launcher.efi \
  --utility target/x86_64-unknown-uefi/release/isohopper-test-utility.efi \
  --code /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --output .local/secure-boot-evidence
```

Choose a new evidence directory for each run. The script accepts only bounded regular-file inputs, uses no host firmware interface, and generates keys, signed copies, images, and variable stores in private temporary storage outside the evidence directory. It removes that storage on exit. Evidence contains logs, results, and public hashes only. Each guest has a 90-second default limit; the full run is bounded to nine minutes. Do not upload temporary storage or reuse these test keys for releases.

For a Linux handoff test, `tests/linux-diagnostic` builds a small unified kernel image from pinned official Ubuntu packages: kernel `6.8.0-147-generic` (`6.8.0-147.147`), the systemd EFI stub, and static BusyBox. It uses a pinned Ubuntu base and package snapshot, normalizes the initramfs, and exports package provenance, hashes, and upstream license notices. Docker needs network access to Ubuntu while building; the build context contains only the fixture sources. After building the launcher above, run from the repository root:

```sh
mkdir -p .local
diagnostic_output="$(mktemp -d "$PWD/.local/linux-diagnostic.XXXXXX")"
docker build --platform linux/amd64 \
  --output "type=local,dest=$diagnostic_output" tests/linux-diagnostic
cargo run -p isohopper-cli --locked -- image create "$diagnostic_output/usb.img" \
  --size-mib 256 --efi target/x86_64-unknown-uefi/release/isohopper-launcher.efi \
  --utility "$diagnostic_output/diagnostic.efi"
cargo run -p isohopper-cli --locked -- image verify "$diagnostic_output/usb.img" \
  --efi target/x86_64-unknown-uefi/release/isohopper-launcher.efi \
  --utility "$diagnostic_output/diagnostic.efi"
python3 scripts/firmware-smoke.py --image "$diagnostic_output/usb.img" \
  --code /path/to/OVMF_CODE.fd --vars /path/to/OVMF_VARS.fd \
  --action linux-diagnostic --log "$diagnostic_output/serial.log"
```

Success requires the launcher entry, utility start, Linux version banner, diagnostic PID 1 marker, and clean guest power-off in order, followed by QEMU exit status zero. This tests only the custom diagnostic kernel/initramfs; it establishes no installer or general distribution compatibility. To run its four Secure Boot cases, use the `secure-boot-smoke.py` command above with `--utility "$diagnostic_output/diagnostic.efi"`, add `--utility-kind linux-diagnostic`, and choose a fresh evidence directory. The default EFI utility mode is unchanged. Keep generated binaries and logs local; the combined binary contains separately licensed upstream components, whose notices are exported with it.

The manual Windows inventory workflow runs fixture tests and read-only discovery on `windows-2022`. Its live smoke test reports counts only. This validates the inventory provider; it does not establish broader Windows or Studio compatibility.

## Review expectations

- Add a regression test for a bug, including its failure case. Use synthetic image files and mocked device inventories.
- Preserve exclusive file creation, retained file handles, checked bounds, and fail-closed device authorization. Do not turn fixtures or read-only host inventory into writable targets.
- Preserve relative image paths and report skipped entries or incomplete inspection explicitly.
- Separate checksum calculation, publisher authentication, firmware execution, and operating-system boot evidence in code, UI, and test reports.
- Include commands run and their results. For UI changes, include desktop and compact screenshots without personal data.
- Keep secrets, generated binaries, local test media, and environment-specific logs out of changes. Preserve GPL-3.0-or-later source notices.

For sensitive findings, use the contact in [SECURITY.md](SECURITY.md).
