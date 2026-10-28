#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 S33G
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/check.sh [--install-browser | --no-browser]

Run locked Rust and frontend checks, including both Chromium viewports.
  --install-browser  Install Chromium and its OS dependencies before browser tests.
  --no-browser       Check browser test discovery without launching a browser.
USAGE
}

browser_mode=run
for argument in "$@"; do
  case "$argument" in
    --install-browser) browser_mode=install ;;
    --no-browser) browser_mode=skip ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_directory="$(cd -- "$script_directory/.." && pwd)"
cd "$repository_directory"

for required_tool in cargo rustc node npm python3; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    printf 'Required tool unavailable: %s\n' "$required_tool" >&2
    exit 2
  fi
done

printf '\nRust toolchain\n'
rustc --version
required_rust_version="$(awk -F '"' '$1 ~ /^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' rust-toolchain.toml)"
actual_rust_version="$(rustc --version)"
if [[ "$actual_rust_version" != "rustc $required_rust_version "* ]]; then
  printf 'Use Rust %s from rust-toolchain.toml; current compiler: %s\n' "$required_rust_version" "$actual_rust_version" >&2
  exit 2
fi
printf '\nRust formatting\n'
cargo fmt --all -- --check
printf '\nRust lint\n'
cargo clippy --workspace --all-targets --locked -- -D warnings
printf '\nRust tests\n'
cargo test --workspace --all-targets --locked
printf '\nFirmware handoff policy tests\n'
cargo test --locked -p isohopper-launcher --features firmware --bin isohopper-launcher
printf '\nFirmware harness tests\n'
python3 -m unittest discover -s scripts -p 'test_*.py'

cd "$repository_directory/studio/frontend"
printf '\nFrontend dependency install\n'
npm ci --no-audit --no-fund
printf '\nFrontend unit tests\n'
npm test
printf '\nFrontend production build\n'
npm run build

if [[ "$browser_mode" == skip ]]; then
  printf '\nBrowser test discovery (execution explicitly skipped)\n'
  npm run test:e2e -- --list
else
  if [[ "$browser_mode" == install ]]; then
    printf '\nInstall Chromium and required OS libraries\n'
    npm exec -- playwright install --with-deps chromium
  fi
  printf '\nChromium integration tests\n'
  npm run test:e2e
fi
