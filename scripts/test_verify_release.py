# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify_release", Path(__file__).with_name("verify-release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'source'
        native = self.source / 'studio/src-tauri/src/main.rs'
        native.parent.mkdir(parents=True)
        native.write_text('const PHYSICAL_PREPARATION_ENABLED: bool = false;\n')
        self.root = Path(self.temp.name) / 'assets'
        self.root.mkdir()
        self.tag = "v0.1.0-experimental.1"
        self.revision = "a" * 40
        for platform, suffixes in release.PLATFORMS.items():
            names = [f"IsoHopper-{self.tag}-{platform}{suffix}" for suffix in suffixes]
            archive = ".zip" if platform == "windows-x64" else ".tar.gz"
            names.append(f"isohopper-cli-{self.tag}-{platform}{archive}")
            artifacts = []
            for name in names:
                path = self.root / name
                path.write_bytes(b"mock package")
                artifacts.append({"name": name, "kind": "cli" if name.startswith("isohopper-cli-") else "studio-installer", "size": path.stat().st_size, "sha256": release.digest(path)})
            (self.root / f"manifest-{platform}.json").write_text(json.dumps({
                "schema_version": 2, "tag": self.tag, "source_revision": self.revision,
                "capabilities": {"native_file_import": True, "read_only_device_inventory": True, "preparation_staging": platform == "windows-x64", "physical_preparation": False, "engine_payloads_bundled": False},
                "platform": platform, "artifacts": artifacts,
            }))

        name = f'isohopper-source-{self.tag}.tar.gz'
        (self.root / name).write_bytes(b'source fixture')
        (self.root / 'manifest-source.json').write_text(json.dumps({
            'schema_version': 2, 'tag': self.tag, 'source_revision': self.revision,
            'artifact': {'name': name, 'kind': 'project-source', 'size': (self.root / name).stat().st_size, 'sha256': release.digest(self.root / name)},
        }))

    def verify(self):
        return release.verify(self.root, self.tag, self.revision, source_root=self.source)

    def test_complete_release_writes_fifteen_checksums(self):
        self.verify()
        self.assertEqual(len((self.root / "SHA256SUMS.txt").read_text().splitlines()), 15)

    def test_existing_checksums_are_verified_not_replaced(self):
        self.verify()
        path = self.root / 'SHA256SUMS.txt'
        original = path.read_bytes()
        self.verify()
        self.assertEqual(path.read_bytes(), original)
        path.write_bytes(b'false checksums')
        with self.assertRaisesRegex(ValueError, 'checksums'):
            self.verify()
        self.assertEqual(path.read_bytes(), b'false checksums')

    def test_missing_source_archive_blocks_verification(self):
        (self.root / f'isohopper-source-{self.tag}.tar.gz').unlink()
        with self.assertRaisesRegex(ValueError, 'package'):
            self.verify()

    def test_platform_capability_claims_must_match_current_native_gate(self):
        for platform in ['windows-x64', 'macos-arm64', 'linux-x64']:
            path = self.root / f'manifest-{platform}.json'
            original = path.read_text()
            value = json.loads(original)
            value['capabilities']['physical_preparation'] = True
            path.write_text(json.dumps(value))
            with self.subTest(platform=platform), self.assertRaisesRegex(ValueError, 'capabilities'):
                self.verify()
            path.write_text(original)

    def test_duplicate_manifest_keys_and_boolean_size_are_rejected(self):
        path = self.root / 'manifest-macos-x64.json'
        original = path.read_text()
        path.write_text(original.replace('"schema_version": 2', '"schema_version": 2, "schema_version": 2'))
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            self.verify()
        value = json.loads(original)
        value['artifacts'][0]['size'] = True
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'metadata'):
            self.verify()

    def test_rejects_missing_platform(self):
        (self.root / "manifest-windows-x64.json").unlink()
        with self.assertRaisesRegex(ValueError, "manifest"):
            self.verify()

    def test_rejects_tampered_package(self):
        next(self.root.glob("*.deb")).write_bytes(b"bad content!")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()

    def test_rejects_mixed_source_revisions(self):
        path = self.root / "manifest-macos-x64.json"
        data = json.loads(path.read_text())
        data["source_revision"] = "b" * 40
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.verify()

    def test_rejects_unlisted_files(self):
        (self.root / "unexpected.txt").write_text("not an asset")
        with self.assertRaisesRegex(ValueError, "Unexpected files"):
            self.verify()

    def test_rejects_path_traversal(self):
        path = self.root / "manifest-macos-x64.json"
        data = json.loads(path.read_text())
        data["artifacts"][0]["name"] = "../outside"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "unexpected packages"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
