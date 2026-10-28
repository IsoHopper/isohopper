# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
import importlib.util
import json
from pathlib import Path
import unittest

import test_verify_release as verification_tests

spec = importlib.util.spec_from_file_location('publish_release', Path(__file__).with_name('publish-release.py'))
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


class FakeApi:
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.assets = []
        self.release_exists = False
        self.draft_exists = False
        self.created = False
        self.tag_exists = False
        self.tag_revision = fixture.revision
        self.absence_status = 404
        self.native_conclusion = 'success'
        self.native_sha = fixture.revision
        self.corrupt_remote = False
        self.fail_upload = False
        self.newer_failed_run = False

    def request(self, method, path, body=None, upload=None):
        self.calls.append((method, path, body))
        if '/actions/workflows/' in path:
            workflow = path.split('/workflows/')[1].split('/')[0]
            runs = [{'id': 123, 'run_number': 10,
                'head_sha': self.native_sha, 'head_branch': 'main', 'event': 'push',
                'head_repository': {'full_name': 'IsoHopper/isohopper'},
                'path': '.github/workflows/' + workflow,
                'status': 'completed', 'conclusion': self.native_conclusion}]
            if self.newer_failed_run:
                runs.append({**runs[0], 'id': 124, 'conclusion': 'failure'})
            return 200, {'workflow_runs': runs, 'total_count': len(runs)}
        if method == 'GET' and '/releases?per_page=' in path:
            values = []
            if self.draft_exists:
                values.append({'id': 7, 'tag_name': self.fixture.tag})
            if self.created:
                values.append({'id': 42, 'tag_name': self.fixture.tag})
            return 200, values
        if '/releases/tags/' in path:
            return (200, {'id': 7}) if self.release_exists else (self.absence_status, {})
        if '/git/ref/' in path:
            return (200, {'object': {'type': 'commit', 'sha': self.tag_revision}}) if self.tag_exists else (self.absence_status, {})
        if path.endswith('/git/refs'):
            self.tag_exists = True
            return 201, {'ref': body['ref'], 'object': {'type': 'commit', 'sha': body['sha']}}
        if method == 'POST' and path.endswith('/releases'):
            self.created = True
            return 201, {'id': 42, 'tag_name': self.fixture.tag, 'draft': True, 'prerelease': True}
        if method == 'POST' and '/assets?' in path:
            if self.fail_upload:
                return 503, None
            name = upload.name
            asset = {'name': name, 'size': upload.stat().st_size, 'state': 'uploaded',
                     'digest': 'sha256:' + publish.verify_module.digest(upload)}
            self.assets.append(asset)
            return 201, asset
        if method == 'GET' and '/assets?' in path:
            if self.corrupt_remote:
                self.assets[0]['digest'] = 'sha256:' + '0' * 64
            return 200, self.assets
        if method == 'PATCH':
            return 200, {'id': 42, 'tag_name': self.fixture.tag, 'draft': False, 'prerelease': True}
        raise AssertionError((method, path, body))


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        # Share only the fixture, not its test methods.
        self.fixture = verification_tests.VerifyReleaseTests(methodName='test_complete_release_writes_fifteen_checksums')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.native = self.fixture.source / 'studio/src-tauri/src/main.rs'
        self.native.write_text('const PHYSICAL_PREPARATION_ENABLED: bool = true;\n')
        path = self.fixture.root / 'manifest-windows-x64.json'
        value = json.loads(path.read_text())
        value['capabilities']['physical_preparation'] = True
        path.write_text(json.dumps(value))
        self.fixture.verify()
        self.api = FakeApi(self.fixture)

    def run_publish(self, event='workflow_dispatch'):
        return publish.publish_release(self.api, self.fixture.root, self.fixture.tag,
            self.fixture.revision, event, 'Release fixture', source_root=self.fixture.source)

    def assert_no_write(self):
        self.assertFalse(any(method != 'GET' for method, _, _ in self.api.calls))

    def test_publish_last_only_after_every_remote_digest_matches(self):
        self.run_publish()
        self.assertEqual(len(self.api.assets), 16)
        self.assertEqual(self.api.calls[-1], ('PATCH', '/repos/IsoHopper/isohopper/releases/42',
            {'draft': False, 'prerelease': True, 'make_latest': 'false'}))
        create = next(body for method, path, body in self.api.calls if method == 'POST' and path.endswith('/releases'))
        self.assertTrue(create['draft'])
        self.assertTrue(create['prerelease'])
        self.assertEqual(create['target_commitish'], self.fixture.revision)
        self.assertIn('actions/runs/123', create['body'])

    def test_disabled_runtime_or_missing_asset_never_mutates_remote(self):
        self.native.write_text('const PHYSICAL_PREPARATION_ENABLED: bool = false;\n')
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assert_no_write()

    def test_existing_release_or_dispatch_tag_is_not_overwritten(self):
        for which in ('release_exists', 'draft_exists', 'tag_exists'):
            setattr(self.api, which, True)
            with self.subTest(which=which), self.assertRaisesRegex(ValueError, 'existing'):
                self.run_publish()
            self.assert_no_write()
            setattr(self.api, which, False)

    def test_forbidden_is_not_interpreted_as_absence(self):
        self.api.absence_status = 403
        with self.assertRaisesRegex(ValueError, '403'):
            self.run_publish()
        self.assert_no_write()

    def test_native_failure_or_other_sha_never_mutates_remote(self):
        for conclusion, sha in [('failure', self.fixture.revision), ('success', 'b' * 40)]:
            self.api.native_conclusion, self.api.native_sha = conclusion, sha
            with self.subTest(conclusion=conclusion, sha=sha), self.assertRaisesRegex(ValueError, 'native'):
                self.run_publish()
            self.assert_no_write()

    def test_newer_failed_native_run_cannot_hide_behind_older_success(self):
        self.api.newer_failed_run = True
        with self.assertRaisesRegex(ValueError, 'native'):
            self.run_publish()
        self.assert_no_write()

    def test_incomplete_assets_fail_before_api_mutations(self):
        next(self.fixture.root.glob('*.deb')).unlink()
        with self.assertRaisesRegex(ValueError, 'package'):
            self.run_publish()
        self.assert_no_write()

    def test_remote_digest_mismatch_leaves_draft_unpublished(self):
        self.api.corrupt_remote = True
        with self.assertRaisesRegex(ValueError, 'remote asset'):
            self.run_publish()
        self.assertFalse(any(method == 'PATCH' for method, _, _ in self.api.calls))

    def test_failed_upload_reports_owned_draft_and_rerun_refuses_it(self):
        self.api.fail_upload = True
        with self.assertRaisesRegex(ValueError, 'release 42.*503'):
            self.run_publish()
        self.assertFalse(any(method == 'PATCH' for method, _, _ in self.api.calls))
        self.api.calls.clear()
        self.api.fail_upload = False
        with self.assertRaisesRegex(ValueError, 'existing release'):
            self.run_publish()
        self.assert_no_write()

    def test_tag_push_requires_existing_exact_revision_and_never_updates_ref(self):
        self.api.tag_exists = True
        self.api.tag_revision = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'revision'):
            self.run_publish('push')
        self.assert_no_write()
        self.api.tag_revision = self.fixture.revision
        self.run_publish('push')
        self.assertFalse(any(method != 'GET' and '/git/' in path for method, path, _ in self.api.calls))

    def test_checksum_file_required_before_publisher_starts(self):
        (self.fixture.root / 'SHA256SUMS.txt').unlink()
        with self.assertRaisesRegex(ValueError, 'checksums'):
            self.run_publish()
        self.assert_no_write()


if __name__ == '__main__':
    unittest.main()
