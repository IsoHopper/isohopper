#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
"""Publish a new verified prerelease; never replace a tag, release, or asset."""
import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from release_metadata import REPOSITORY, capabilities

spec = importlib.util.spec_from_file_location('verify_release', Path(__file__).with_name('verify-release.py'))
verify_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_module)
BASE = '/repos/' + REPOSITORY
NATIVE_WORKFLOWS = ('studio-windows.yml', 'writer-windows-vhd.yml')


class GitHub:
    """Fixed GitHub hosts, bounded replies, no redirect or mutation retry."""
    def __init__(self, token):
        if not token or '\r' in token or '\n' in token:
            raise ValueError('A valid GitHub token is required')
        self.token = token

    def request(self, method, path, body=None, upload=None):
        if not path.startswith(BASE + '/'):
            raise ValueError('Unexpected API repository')
        host = 'uploads.github.com' if upload is not None else 'api.github.com'
        connection = http.client.HTTPSConnection(host, timeout=60)
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'IsoHopper-release'}
        try:
            if upload is None:
                data = None if body is None else json.dumps(body).encode('utf-8')
                if data is not None:
                    headers['Content-Type'] = 'application/json'
                connection.request(method, path, body=data, headers=headers)
            else:
                size = verify_module.regular(upload).st_size
                with upload.open('rb') as stream:
                    connection.putrequest(method, path)
                    for key, value in headers.items():
                        connection.putheader(key, value)
                    connection.putheader('Content-Type', 'application/octet-stream')
                    connection.putheader('Content-Length', str(size))
                    connection.endheaders()
                    remaining = size
                    while remaining:
                        data = stream.read(min(remaining, 1024 * 1024))
                        if not data:
                            raise ValueError('Asset changed during upload')
                        connection.send(data)
                        remaining -= len(data)
                    if stream.read(1):
                        raise ValueError('Asset grew during upload')
            response = connection.getresponse()
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError('API response exceeds size bound')
            # Error bodies are intentionally not printed (and need not be JSON).
            value = json.loads(data) if 200 <= response.status < 300 else None
            return response.status, value
        finally:
            connection.close()


def expected(api, method, path, status, **kwargs):
    actual, value = api.request(method, path, **kwargs)
    if actual != status:
        raise ValueError(f'GitHub {method} request returned {actual}; expected {status}')
    return value


def identity(tag, revision, event):
    if (not re.fullmatch(r'v\d+\.\d+\.\d+-experimental\.[1-9]\d*', tag)
            or not re.fullmatch(r'[0-9a-f]{40}', revision) or event not in ('push', 'workflow_dispatch')):
        raise ValueError('Invalid release identity or event')


def require_absent(api, path, label):
    status, _ = api.request('GET', path)
    if status == 200:
        raise ValueError(f'Refusing existing {label}')
    if status != 404:
        raise ValueError(f'Cannot establish absent {label}: GitHub returned {status}')


def require_tag_revision(api, tag, revision):
    value = expected(api, 'GET', BASE + '/git/ref/tags/' + quote(tag, safe=''), 200)
    obj = value.get('object', {})
    for _ in range(4):
        if obj.get('type') == 'commit' and obj.get('sha') == revision:
            return
        if obj.get('type') != 'tag' or not re.fullmatch(r'[0-9a-f]{40}', str(obj.get('sha'))):
            break
        value = expected(api, 'GET', BASE + '/git/tags/' + obj['sha'], 200)
        obj = value.get('object', {})
    raise ValueError('Release tag does not resolve to the exact source revision')


def no_other_releases(api, tag, own=None):
    # The tag endpoint describes published releases. List with the publishing
    # token too, so an existing draft never becomes an accidental duplicate.
    found_own = False
    for page in range(1, 11):
        rows = expected(api, 'GET', BASE + f'/releases?per_page=100&page={page}', 200)
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError('Invalid release listing')
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('Invalid release listing')
            if row.get('tag_name') == tag:
                if own is None or row.get('id') != own:
                    raise ValueError('Refusing existing release, including drafts')
                found_own = True
        if len(rows) < 100:
            if own is not None and not found_own:
                raise ValueError('New draft disappeared before publication')
            return
    raise ValueError('Release listing exceeds bound; cannot establish absence')


def preflight(api, tag, revision, event):
    identity(tag, revision, event)
    require_absent(api, BASE + '/releases/tags/' + quote(tag, safe=''), 'release')
    no_other_releases(api, tag)
    if event == 'workflow_dispatch':
        require_absent(api, BASE + '/git/ref/tags/' + quote(tag, safe=''), 'release tag')
    else:
        require_tag_revision(api, tag, revision)


def native_evidence(api, revision):
    links = []
    for workflow in NATIVE_WORKFLOWS:
        value = expected(api, 'GET', BASE + f'/actions/workflows/{workflow}/runs?head_sha={revision}&per_page=100', 200)
        runs = value.get('workflow_runs')
        count = value.get('total_count')
        if (type(count) is not int or not 0 <= count <= 100
                or not isinstance(runs, list) or len(runs) != count):
            raise ValueError('Invalid native workflow evidence')
        matching = [run for run in runs if isinstance(run, dict) and run.get('head_sha') == revision]
        if not matching or any(type(run.get('id')) is not int for run in matching):
            raise ValueError(f'Missing native evidence for exact revision: {workflow}')
        latest = max(matching, key=lambda run: run['id'])
        if (latest.get('status') != 'completed' or latest.get('conclusion') != 'success'
                or latest.get('head_branch') != 'main' or latest.get('event') not in ('push', 'workflow_dispatch')
                or latest.get('path') != '.github/workflows/' + workflow
                or latest.get('head_repository', {}).get('full_name', '').lower() != REPOSITORY.lower()
                or latest['id'] <= 0):
            raise ValueError(f'Latest exact-revision native workflow did not pass: {workflow}')
        links.append(f'[{workflow}](https://github.com/{REPOSITORY}/actions/runs/{latest["id"]})')
    return links


def publish_release(api, directory, tag, revision, event, notes, source_root=None):
    identity(tag, revision, event)
    directory = Path(directory)
    if not (directory / 'SHA256SUMS.txt').is_file():
        raise ValueError('Verified checksums must already exist before publishing')
    report = verify_module.verify(directory, tag, revision, source_root=source_root)
    if not report['capabilities']['windows-x64']['physical_preparation']:
        raise ValueError('Native physical preparation remains disabled; publishing is blocked')
    preflight(api, tag, revision, event)
    evidence = native_evidence(api, revision)
    # No mutation occurs until the whole local set and both native runs pass.
    if event == 'workflow_dispatch':
        expected(api, 'POST', BASE + '/git/refs', 201,
                 body={'ref': 'refs/tags/' + tag, 'sha': revision})
    release = expected(api, 'POST', BASE + '/releases', 201, body={
        'tag_name': tag, 'target_commitish': revision, 'name': 'IsoHopper ' + tag,
        'body': notes + '\n\nExact-revision Windows evidence: ' + ' · '.join(evidence) + '\n',
        'draft': True, 'prerelease': True, 'make_latest': 'false'})
    release_id = release.get('id')
    if (type(release_id) is not int or release_id <= 0 or release.get('tag_name') != tag
            or release.get('draft') is not True or release.get('prerelease') is not True):
        raise ValueError('Unexpected new draft release response')
    path = BASE + f'/releases/{release_id}'
    try:
        for name in report['assets']:
            expected(api, 'POST', path + '/assets?name=' + quote(name, safe=''), 201, upload=directory / name)
        remote = expected(api, 'GET', path + '/assets?per_page=100', 200)
        if (not isinstance(remote, list) or len(remote) != len(report['assets'])
                or any(not isinstance(item, dict) for item in remote)):
            raise ValueError('Incomplete remote asset set; draft remains unpublished')
        seen = set()
        for item in remote:
            name = item.get('name')
            local = report['assets'].get(name) if isinstance(name, str) else None
            if (local is None or name in seen or item.get('state') != 'uploaded'
                    or type(item.get('size')) is not int or item['size'] != local['size']
                    or item.get('digest') != 'sha256:' + local['sha256']):
                raise ValueError('Mismatched remote asset; draft remains unpublished')
            seen.add(name)
        # Recheck mutable remote evidence immediately before making our own draft public.
        require_tag_revision(api, tag, revision)
        native_evidence(api, revision)
        no_other_releases(api, tag, own=release_id)
        result = expected(api, 'PATCH', path, 200,
                          body={'draft': False, 'prerelease': True, 'make_latest': 'false'})
        if (result.get('id') != release_id or result.get('tag_name') != tag
                or result.get('draft') is not False or result.get('prerelease') is not True):
            raise ValueError('Publication response was ambiguous; inspect the new release manually')
        return release_id
    except (ValueError, OSError, http.client.HTTPException) as error:
        # Preserve evidence. Never delete a partial draft, replace assets, or
        # retry a mutation whose server-side outcome may be unknown.
        raise ValueError(
            f'Inspect new release {release_id} and tag {tag} before recovery; '
            f'no cleanup or retry was attempted, publication may be incomplete: {error}'
        ) from error



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--event', choices=('push', 'workflow_dispatch'), required=True)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--require-ready', action='store_true',
                        help='Also require runtime activation and exact-revision native checks before building')
    args = parser.parse_args()
    api = GitHub(os.environ.get('GH_TOKEN'))
    if args.preflight_only:
        preflight(api, args.tag, args.source_revision, args.event)
        if args.require_ready:
            if not capabilities(Path(__file__).resolve().parent.parent, 'windows-x64')['physical_preparation']:
                raise ValueError('Native physical preparation remains disabled; publishing is blocked')
            native_evidence(api, args.source_revision)
        print('Release identity is available; no remote changes made.')
        return
    if args.directory is None:
        parser.error('--directory is required for publishing')
    if not (args.directory / 'SHA256SUMS.txt').is_file():
        raise ValueError('Verified checksums must already exist before publishing')
    report = verify_module.verify(args.directory, args.tag, args.source_revision)
    run_id = os.environ['GITHUB_RUN_ID']
    if not re.fullmatch(r'[1-9]\d*', run_id):
        raise ValueError('Invalid release workflow run ID')
    notes = verify_module.notes(args.tag, args.source_revision,
        f'https://github.com/{REPOSITORY}/actions/runs/{run_id}', report['capabilities'])
    release_id = publish_release(api, args.directory, args.tag, args.source_revision, args.event, notes)
    print(f'Published new prerelease {release_id}; no existing release was modified.')


if __name__ == '__main__':
    main()
