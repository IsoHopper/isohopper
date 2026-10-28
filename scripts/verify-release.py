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
import stat

from release_metadata import capabilities, scope_description

PLATFORMS = {
    "linux-x64": (".deb", ".AppImage"),
    "windows-x64": ("-setup.exe",),
    "macos-arm64": (".dmg",),
    "macos-x64": (".dmg",),
}
MAX_ASSET = 2 * 1024 * 1024 * 1024


def regular(path, maximum=MAX_ASSET):
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"Missing regular package or manifest: {path.name}") from error
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError(f"Expected bounded regular package or manifest: {path.name}")
    return info


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def read_manifest(path):
    regular(path, 32 * 1024)
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("Expected manifest object")
    return value


def check_artifact(directory, item, kind):
    if (not isinstance(item, dict) or set(item) != {"name", "kind", "size", "sha256"}
            or item["kind"] != kind or type(item["size"]) is not int
            or not 0 < item["size"] <= MAX_ASSET or not isinstance(item["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
        raise ValueError("Invalid artifact metadata")
    path = directory / item["name"]
    before = regular(path)
    actual = digest(path)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError(f"Package changed during verification: {path.name}")
    if before.st_size != item["size"] or actual != item["sha256"]:
        raise ValueError(f"Package checksum mismatch: {path.name}")


def verify(directory, tag, revision, source_root=None):
    directory = Path(directory)
    source_root = source_root or Path(__file__).resolve().parent.parent
    if not re.fullmatch(r"v\d+\.\d+\.\d+-experimental\.[1-9]\d*", tag):
        raise ValueError("Invalid experimental tag")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full source revision")
    expected_files = set()
    scopes = {}
    for platform, suffixes in PLATFORMS.items():
        manifest_name = f"manifest-{platform}.json"
        manifest = read_manifest(directory / manifest_name)
        if (type(manifest.get("schema_version")) is not int or set(manifest) != {"schema_version", "tag", "platform", "source_revision", "capabilities", "artifacts"}
                or (manifest.get("schema_version"), manifest.get("tag"), manifest.get("platform"),
                    manifest.get("source_revision")) != (2, tag, platform, revision)):
            raise ValueError(f"Release identity mismatch: {manifest_name}")
        scope = capabilities(source_root, platform)
        if (manifest["capabilities"] != scope or not isinstance(manifest["capabilities"], dict)
                or any(type(value) is not bool for value in manifest["capabilities"].values())):
            raise ValueError(f"Release capabilities mismatch: {platform}")
        scopes[platform] = scope
        expected_names = {f"IsoHopper-{tag}-{platform}{suffix}" for suffix in suffixes}
        archive = ".zip" if platform == "windows-x64" else ".tar.gz"
        cli_name = f"isohopper-cli-{tag}-{platform}{archive}"
        expected_names.add(cli_name)
        artifacts = manifest["artifacts"]
        if not isinstance(artifacts, list) or any(not isinstance(item, dict) for item in artifacts):
            raise ValueError("Invalid artifact metadata")
        names = [item.get("name") for item in artifacts]
        if (any(not isinstance(name, str) for name in names) or len(names) != len(set(names))
                or set(names) != expected_names):
            raise ValueError(f"Incomplete or unexpected packages: {platform}")
        for item in artifacts:
            check_artifact(directory, item, "cli" if item["name"] == cli_name else "studio-installer")
        expected_files.update(expected_names)
        expected_files.add(manifest_name)
    source = read_manifest(directory / "manifest-source.json")
    source_name = f"isohopper-source-{tag}.tar.gz"
    if (type(source.get("schema_version")) is not int or set(source) != {"schema_version", "tag", "source_revision", "artifact"}
            or (source.get("schema_version"), source.get("tag"), source.get("source_revision")) != (2, tag, revision)
            or not isinstance(source["artifact"], dict) or source["artifact"].get("name") != source_name):
        raise ValueError("Source release identity mismatch")
    check_artifact(directory, source["artifact"], "project-source")
    expected_files.update({source_name, "manifest-source.json"})
    if {path.name for path in directory.iterdir()} - {"SHA256SUMS.txt"} != expected_files:
        raise ValueError("Unexpected files in release directory")
    assets = {name: {"size": regular(directory / name).st_size, "sha256": digest(directory / name)}
              for name in sorted(expected_files)}
    sums = "".join(f"{item['sha256']}  {name}\n" for name, item in assets.items())
    checksum_path = directory / "SHA256SUMS.txt"
    if os.path.lexists(checksum_path):
        regular(checksum_path, 32 * 1024)
        if checksum_path.read_text(encoding="ascii") != sums:
            raise ValueError("Existing checksums do not match verified release")
    else:
        with checksum_path.open("x", encoding="ascii", newline="\n") as output:
            output.write(sums)
    assets["SHA256SUMS.txt"] = {"size": checksum_path.stat().st_size, "sha256": digest(checksum_path)}
    return {"assets": assets, "capabilities": scopes}


def notes(tag, revision, run_url, scopes):
    windows = scope_description(scopes["windows-x64"]).strip()
    return f"""> **SUPER EXPERIMENTAL — pending human hardware testing.** General OS installation, physical hardware compatibility and production Secure Boot support are not established.

{windows}
macOS and Linux provide local image imports, streaming SHA-256 and read-only device inspection. They cannot prepare physical USB devices. Nested image paths are retained.

| Download | Scope |
| --- | --- |
| `windows-x64-setup.exe` | Windows x64; fresh machine installation in Program Files required for the privileged helper. WebView2 may download during setup. |
| `macos-arm64.dmg` / `macos-x64.dmg` | Apple Silicon / Intel Mac inspection and local hashing. |
| `linux-x64.AppImage` / `.deb` | Linux x64 inspection and local hashing; built on Ubuntu 22.04. |
| `isohopper-cli-*` | Standalone CLI, license and build information. |
| `isohopper-source-*` | Project source at the exact revision below, including build scripts and dependency lockfiles. |

No upstream boot-engine binaries, engine archives or OS images are included. Follow the [Windows preparation guide](https://github.com/IsoHopper/isohopper/blob/{revision}/docs/usb-preparation.md) for the pinned engine archive, staging-space requirements and first boot test. Launcher configuration and power-action previews are not applied to the engine USB menu.

**Signing:** Windows packages are not Authenticode-signed. macOS apps are ad-hoc signed, not Developer ID signed or notarized. SHA-256 checks integrity, not publisher identity. Linux graphics/WebKit compatibility and the oldest advertised macOS version remain untested.

**Build checks:** all four packages require native backend tests and CLI smoke checks. Host-neutral workspace and frontend tests run once on Linux. Publication additionally requires successful Windows Studio and disposable-VHD workflow runs for this exact source revision. Those checks do not establish interactive UAC behavior or real USB boot compatibility.

[Build logs]({run_url}) · [Exact source](https://github.com/IsoHopper/isohopper/tree/{revision}) · [GPL-3.0-or-later](https://github.com/IsoHopper/isohopper/blob/{revision}/LICENSE)

Source revision: `{revision}`. Tag: `{tag}`. Platform manifests state capabilities, sizes and SHA-256. `SHA256SUMS.txt` covers every package, source archive and manifest.

Verify with `sha256sum -c SHA256SUMS.txt` on Linux, or compare `shasum -a 256 <file>` / PowerShell `Get-FileHash <file> -Algorithm SHA256` with the matching checksum entry. Checking the full list requires all assets.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    report = verify(args.directory, args.tag, args.source_revision)
    run_url = "https://github.com/IsoHopper/isohopper/actions/runs/" + os.environ["GITHUB_RUN_ID"]
    (args.directory.parent / "release-notes.md").write_text(
        notes(args.tag, args.source_revision, run_url, report["capabilities"]), encoding="utf-8")
    print("Verified all four platforms, project source and SHA-256 checksums.")


if __name__ == "__main__":
    main()
