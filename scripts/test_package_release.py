# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('package_release', Path(__file__).with_name('package-release.py'))
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)

TAG = 'v0.1.0-experimental.1'
REVISION = 'a' * 40


class PackageReleaseTests(unittest.TestCase):
    def fixture(self, root, platform):
        for name in ['LICENSE', 'CONTRIBUTORS.md']:
            (root / name).write_text(f'{name} fixture\n')
        binary = root / 'target/release' / ('isohopper.exe' if platform == 'windows-x64' else 'isohopper')
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'cli fixture\x00\xff')
        formats = {'linux-x64': [('deb', 'fixture.deb'), ('appimage', 'fixture.AppImage')],
                   'windows-x64': [('nsis', 'fixture-setup.exe')],
                   'macos-arm64': [('dmg', 'fixture.dmg')],
                   'macos-x64': [('dmg', 'fixture.dmg')]}[platform]
        for folder, name in formats:
            path = root / 'studio/src-tauri/target/release/bundle' / folder / name
            path.parent.mkdir(parents=True)
            path.write_bytes(f'installer {folder}'.encode())
        return binary

    def test_all_platforms_package_expected_files_and_verified_manifests(self):
        for platform in ['linux-x64', 'windows-x64', 'macos-arm64', 'macos-x64']:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = self.fixture(root, platform)
                output = root / 'dist/release'
                manifest = package.package_release(root, output, platform, TAG, REVISION)
                self.assertEqual(manifest['source_revision'], REVISION)
                self.assertEqual(manifest['platform'], platform)
                self.assertEqual(manifest['tag'], TAG)
                self.assertEqual(manifest['schema_version'], 1)
                self.assertEqual(len(manifest['artifacts']), 3 if platform == 'linux-x64' else 2)
                self.assertEqual(json.loads((output / f'manifest-{platform}.json').read_text()), manifest)
                for item in manifest['artifacts']:
                    path = output / item['name']
                    self.assertEqual(path.stat().st_size, item['size'])
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item['sha256'])
                    self.assertIn(TAG, item['name'])
                    self.assertIn(platform, item['name'])
                    if item['name'].endswith('.AppImage'):
                        self.assertTrue(path.stat().st_mode & 0o111)
                archive = output / next(item['name'] for item in manifest['artifacts'] if item['kind'] == 'cli')
                if platform == 'windows-x64':
                    with zipfile.ZipFile(archive) as bundle:
                        contents = {name: bundle.read(name) for name in bundle.namelist()}
                else:
                    with tarfile.open(archive, 'r:gz') as bundle:
                        contents = {item.name: bundle.extractfile(item).read() for item in bundle.getmembers()}
                        self.assertEqual(bundle.getmember('isohopper').mode, 0o755)
                self.assertEqual(set(contents), {binary.name, 'LICENSE', 'CONTRIBUTORS.md', 'BUILD-INFO.txt'})
                self.assertEqual(contents[binary.name], binary.read_bytes())
                self.assertIn(REVISION.encode(), contents['BUILD-INFO.txt'])
                self.assertIn(b'Physical disk writes are disabled', contents['BUILD-INFO.txt'])
                self.assertIn(b'not publisher authentication', contents['BUILD-INFO.txt'])

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, 'linux-x64')
            output = root / 'dist'
            output.mkdir()
            existing = output / f'IsoHopper-{TAG}-linux-x64.deb'
            existing.write_bytes(b'keep existing')
            with self.assertRaises(FileExistsError):
                package.package_release(root, output, 'linux-x64', TAG, REVISION)
            self.assertEqual(existing.read_bytes(), b'keep existing')
            self.assertEqual(list(output.iterdir()), [existing])

    def test_missing_or_ambiguous_installers_fail_before_output(self):
        for ambiguous in [False, True]:
            with self.subTest(ambiguous=ambiguous), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, 'macos-arm64')
                installer = root / 'studio/src-tauri/target/release/bundle/dmg/fixture.dmg'
                if ambiguous:
                    installer.with_name('extra.dmg').write_bytes(b'extra')
                else:
                    installer.unlink()
                with self.assertRaises(ValueError):
                    package.package_release(root, root / 'dist', 'macos-arm64', TAG, REVISION)
                self.assertFalse((root / 'dist').exists())

    def test_invalid_release_identity_cannot_become_a_path(self):
        for tag, revision in [('../escape', REVISION), ('v1.0.0\nprivate', REVISION),
                              (TAG, 'HEAD'), (TAG, '../escape')]:
            with self.subTest(tag=tag, revision=revision), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(ValueError):
                    package.package_release(root, root / 'dist', 'linux-x64', tag, revision)
                self.assertFalse((root / 'dist').exists())

    def test_regular_files_are_bounded_and_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'abc')
            with self.assertRaises(ValueError):
                package.OpenedFile(path, max_size=2)
            for changed in [b'abcd', b'ab']:
                path.write_bytes(b'abc')
                with self.subTest(changed=changed), package.OpenedFile(path, max_size=10) as opened:
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        opened.copy_to(io.BytesIO())

    def test_publish_race_preserves_competing_file_and_removes_only_own_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, 'linux-x64')
            output = root / 'dist'
            original_link = package.os.link
            calls = 0

            def competing_link(source, destination):
                nonlocal calls
                calls += 1
                if calls == 2:
                    Path(destination).write_bytes(b'competing publisher')
                original_link(source, destination)

            with patch.object(package.os, 'link', side_effect=competing_link):
                with self.assertRaises(FileExistsError):
                    package.package_release(root, output, 'linux-x64', TAG, REVISION)
            files = list(output.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b'competing publisher')

    def test_symlink_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture(root, 'linux-x64')
            target = binary.with_name('actual')
            binary.rename(target)
            try:
                binary.symlink_to(target)
            except OSError:
                self.skipTest('symlink creation is unavailable')
            with self.assertRaises((OSError, ValueError)):
                package.package_release(root, root / 'dist', 'linux-x64', TAG, REVISION)
            self.assertFalse((root / 'dist').exists())


if __name__ == '__main__':
    unittest.main()
