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
        self.root = Path(self.temp.name)
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
                artifacts.append({"name": name, "size": path.stat().st_size, "sha256": release.digest(path)})
            (self.root / f"manifest-{platform}.json").write_text(json.dumps({
                "schema_version": 1, "tag": self.tag, "source_revision": self.revision,
                "platform": platform, "artifacts": artifacts,
            }))

    def verify(self):
        release.verify(self.root, self.tag, self.revision)

    def test_complete_release_writes_thirteen_checksums(self):
        self.verify()
        self.assertEqual(len((self.root / "SHA256SUMS.txt").read_text().splitlines()), 13)

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
