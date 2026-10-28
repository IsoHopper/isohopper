# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
import importlib.util
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('source_release', Path(__file__).with_name('source-release.py'))
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        for name in ('LICENSE', 'Cargo.lock', 'Cargo.toml', 'README.md'):
            (self.root / name).write_text(name + ' original')
        self.git('add', '.')
        self.revision = self.snapshot()
        self.tag = 'v0.1.0-experimental.1'
        self.output = self.root / 'release'

    def git(self, *args, **kwargs):
        return subprocess.check_output(['git', '-C', str(self.root), *args], **kwargs).decode().strip()

    def snapshot(self):
        tree = self.git('write-tree')
        revision = self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit-tree', tree, input=b'Fixture\n\nCo-Author: Charlie\'s Agent\n')
        self.git('update-ref', 'HEAD', revision)
        return revision

    def test_archive_is_exact_revision_not_working_tree_or_untracked_payload(self):
        (self.root / 'README.md').write_text('modified')
        (self.root / 'not-shipped.iso').write_bytes(b'private image')
        report = source.package_source(self.root, self.output, self.tag, self.revision)
        with tarfile.open(self.output / report['artifact']['name']) as archive:
            names = archive.getnames()
            self.assertNotIn(f'isohopper-{self.tag}/not-shipped.iso', names)
            self.assertEqual(archive.extractfile(f'isohopper-{self.tag}/README.md').read(), b'README.md original')
        self.assertEqual(report['source_revision'], self.revision)
        with self.assertRaises(FileExistsError):
            source.package_source(self.root, self.output, self.tag, self.revision)

    def test_tracked_payload_is_refused_before_output(self):
        (self.root / 'boot.efi').write_bytes(b'not a distributable source')
        self.git('add', 'boot.efi')
        revision = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'payload'):
            source.package_source(self.root, self.output, self.tag, revision)
        self.assertFalse(self.output.exists())

    def test_wrong_revision_and_symlink_refused(self):
        with self.assertRaisesRegex(ValueError, 'revision'):
            source.package_source(self.root, self.output, self.tag, 'a' * 40)
        (self.root / 'link').symlink_to('README.md')
        self.git('add', 'link')
        revision = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'regular'):
            source.package_source(self.root, self.output, self.tag, revision)


if __name__ == '__main__':
    unittest.main()
