# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'stage_windows_helper', Path(__file__).with_name('stage-windows-helper.py'))
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


def image(machine=0x8664, magic=0x20b, characteristics=0x22, subsystem=3):
    data = bytearray(512)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, machine, 1, 0, 0, 0, 0xf0, characteristics)
    struct.pack_into('<H', data, 0x98, magic)
    struct.pack_into('<H', data, 0xdc, subsystem)
    return bytes(data)


class StageWindowsHelperTests(unittest.TestCase):
    def fixture(self, root, data=None):
        source = root / 'build with spaces' / 'helper.exe'
        source.parent.mkdir()
        source.write_bytes(image() if data is None else data)
        return source

    def test_stages_exact_bytes_and_digest_at_tauri_target_path(self):
        with tempfile.TemporaryDirectory(prefix='helper-λ-') as directory:
            root = Path(directory)
            source = self.fixture(root)
            info = stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            expected = root / 'studio/src-tauri/binaries/isohopper-helper-x86_64-pc-windows-msvc.exe'
            self.assertEqual(expected.read_bytes(), source.read_bytes())
            self.assertEqual(info['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(info['size'], 512)
            self.assertEqual(info['path'], expected.relative_to(root).as_posix())

    def test_replaces_only_the_generated_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            first = stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            source.write_bytes(image() + b'new build')
            second = stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            self.assertNotEqual(first['sha256'], second['sha256'])
            self.assertEqual((root / second['path']).read_bytes(), source.read_bytes())
            self.assertEqual(len(list((root / second['path']).parent.iterdir())), 1)

    def test_refuses_invalid_executable_before_creating_destination(self):
        bad_offset = bytearray(image())
        struct.pack_into('<I', bad_offset, 0x3c, 0xfffffff0)
        for data in [b'', b'not PE', image(0x14c), image(magic=0x10b),
                     image(characteristics=0x2022), image(characteristics=0),
                     image(subsystem=1), image(subsystem=10),
                     image()[:200], bytes(bad_offset)]:
            with self.subTest(length=len(data)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = self.fixture(root, data)
                with self.assertRaises(ValueError):
                    stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
                self.assertFalse((root / 'studio').exists())

    def test_rejects_arbitrary_target_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            for target in ['../elsewhere', 'aarch64-pc-windows-msvc', '', 'x86_64-pc-windows-msvc.exe']:
                with self.subTest(target=target), self.assertRaises(ValueError):
                    stage.stage_helper(root, source, target)
            self.assertFalse((root / 'studio').exists())

    def test_rejects_source_and_destination_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            link = root / 'source-link.exe'
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest('symlink creation unavailable')
            with self.assertRaises(ValueError):
                stage.stage_helper(root, link, 'x86_64-pc-windows-msvc')
            destination = root / 'studio/src-tauri/binaries/isohopper-helper-x86_64-pc-windows-msvc.exe'
            destination.parent.mkdir(parents=True)
            destination.symlink_to(source)
            with self.assertRaises(ValueError):
                stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            self.assertTrue(destination.is_symlink())
            self.assertEqual(source.read_bytes(), image())

    def test_rejects_a_symlinked_staging_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            outside = root / 'elsewhere'
            outside.mkdir()
            parent = root / 'studio/src-tauri'
            parent.mkdir(parents=True)
            try:
                (parent / 'binaries').symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest('symlink creation unavailable')
            with self.assertRaises(ValueError):
                stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            self.assertEqual(list(outside.iterdir()), [])

    def test_refuses_windows_directory_junction_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.fixture(root)
            junction = root / 'studio'
            original = Path.lstat

            def observe(path, *args, **kwargs):
                if path == junction:
                    return SimpleNamespace(st_mode=0o040755, st_file_attributes=0x410)
                return original(path, *args, **kwargs)

            with patch.object(Path, 'lstat', observe), self.assertRaises(ValueError):
                stage.stage_helper(root, source, 'x86_64-pc-windows-msvc')
            self.assertFalse(junction.exists())


if __name__ == '__main__':
    unittest.main()
