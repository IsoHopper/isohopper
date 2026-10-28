#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
"""Fail closed before publishing a complete, same-revision release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

PLATFORMS = {
    "linux-x64": (".deb", ".AppImage"),
    "windows-x64": ("-setup.exe",),
    "macos-arm64": (".dmg",),
    "macos-x64": (".dmg",),
}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def verify(directory, tag, revision):
    if not re.fullmatch(r"v\d+\.\d+\.\d+-experimental\.[1-9]\d*", tag):
        raise ValueError("Invalid experimental tag")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full source revision")
    expected_files = set()
    for platform, suffixes in PLATFORMS.items():
        manifest_name = f"manifest-{platform}.json"
        manifest_path = directory / manifest_name
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError(f"Missing regular manifest: {manifest_name}")
        manifest = json.loads(manifest_path.read_text())
        if (manifest.get("schema_version"), manifest.get("tag"),
                manifest.get("platform"), manifest.get("source_revision")) != (1, tag, platform, revision):
            raise ValueError(f"Release identity mismatch: {manifest_name}")
        expected_names = {f"IsoHopper-{tag}-{platform}{suffix}" for suffix in suffixes}
        archive = ".zip" if platform == "windows-x64" else ".tar.gz"
        expected_names.add(f"isohopper-cli-{tag}-{platform}{archive}")
        artifacts = manifest["artifacts"]
        names = [item["name"] for item in artifacts]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise ValueError(f"Incomplete or unexpected packages: {platform}")
        for item in artifacts:
            path = directory / item["name"]
            if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
                raise ValueError(f"Missing regular package: {path.name}")
            if path.stat().st_size != item["size"] or digest(path) != item["sha256"]:
                raise ValueError(f"Package checksum mismatch: {path.name}")
        expected_files.update(expected_names)
        expected_files.add(manifest_name)
    if {path.name for path in directory.iterdir()} != expected_files:
        raise ValueError("Unexpected files in release directory")
    lines = [f"{digest(directory / name)}  {name}\n" for name in sorted(expected_files)]
    (directory / "SHA256SUMS.txt").write_text("".join(lines))


def notes(tag, revision, run_url):
    return f"""> **SUPER EXPERIMENTAL — pending human testing.** Physical disk writes are disabled. General ISO booting and OS installation compatibility are not established.

Rust CLI and native Tauri Studio for inspecting image libraries, streaming checksums, read-only device details, configuration and simulated media preparation. Nested folders are supported.

| Download | Platform |
| --- | --- |
| `windows-x64-setup.exe` | Windows x64 installer; WebView2 may be downloaded during setup |
| `macos-arm64.dmg` | Apple Silicon Mac |
| `macos-x64.dmg` | Intel Mac |
| `linux-x64.AppImage` / `.deb` | Linux x64, built on Ubuntu 22.04 |
| `isohopper-cli-*` | Standalone CLI archives with license and build information |

Pick the asset containing your platform name. Linux still needs a compatible graphics/WebKit runtime; AppImage portability across distributions is untested. The macOS deployment target is 11.0; the oldest supported OS has not been tested.

**Signing:** Windows packages have no Authenticode signature. macOS apps have an ad-hoc signature, not Developer ID signing or Apple notarization. System trust warnings are expected. SHA-256 verifies file integrity, not publisher identity.

**Checks for this release:** all four native builds passed the Rust workspace tests with mocks, native backend tests and CLI version/help/demo smoke checks. Frontend tests passed on Linux. These checks do not exercise interactive installers or establish Windows/Linux desktop usability, physical-device safety, hardware boot compatibility, or production Secure Boot support.

[Build and test logs]({run_url}) · [Exact source](https://github.com/IsoHopper/isohopper/tree/{revision}) · [GPL-3.0-or-later](https://github.com/IsoHopper/isohopper/blob/{revision}/LICENSE)

Source revision: `{revision}`. Tag: `{tag}`. Platform manifests record file sizes and SHA-256 values. `SHA256SUMS.txt` also covers those manifests.

Verify downloads with `sha256sum -c SHA256SUMS.txt` on Linux, `shasum -a 256 <file>` on macOS, or `Get-FileHash <file> -Algorithm SHA256` in PowerShell. Compare the result with the matching line in `SHA256SUMS.txt` (checking the full list requires all assets).
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    verify(args.directory, args.tag, args.source_revision)
    run_url = "https://github.com/IsoHopper/isohopper/actions/runs/" + os.environ["GITHUB_RUN_ID"]
    (args.directory.parent / "release-notes.md").write_text(notes(args.tag, args.source_revision, run_url))
    print("Verified all four platforms, package identities and SHA-256 checksums.")


if __name__ == "__main__":
    main()
