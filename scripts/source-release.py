#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 S33G
"""Package only tracked project source at an exact revision, never local payloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

MAX_SOURCE = 256 * 1024 * 1024
PAYLOAD_SUFFIXES = ('.iso', '.img', '.vhd', '.vhdx', '.qcow2', '.efi', '.bin', '.wim',
                    '.esd', '.exe', '.dll', '.zip', '.tar', '.tar.gz', '.tgz', '.xz')


def package_source(root, output, tag, revision):
    root, output = Path(root), Path(output)
    if not re.fullmatch(r'v\d+\.\d+\.\d+-experimental\.[1-9]\d*', tag):
        raise ValueError('Invalid experimental tag')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Expected exact source revision')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args])
    if git('rev-parse', 'HEAD').decode().strip() != revision:
        raise ValueError('Checkout differs from requested source revision')
    files = set()
    records = git('ls-tree', '-r', '-z', revision).split(b'\0')
    if len(records) > 10001:
        raise ValueError('Source tree exceeds file count bound')
    for record in records:
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, _ = metadata.split(b' ')
        name = name.decode('utf-8')
        parts = PurePosixPath(name).parts
        if (mode not in (b'100644', b'100755') or kind != b'blob'
                or not parts or any(part in ('.', '..') for part in parts) or name.startswith('/')):
            raise ValueError('Source archive accepts regular tracked files only')
        if name.lower().endswith(PAYLOAD_SUFFIXES) or parts[0] in ('.local', 'target', 'dist', 'node_modules'):
            raise ValueError(f'Refusing binary payload or generated source entry: {name}')
        files.add(name)
    if not {'LICENSE', 'Cargo.toml', 'Cargo.lock'} <= files:
        raise ValueError('Missing corresponding source build files or license')
    name = f'isohopper-source-{tag}.tar.gz'
    names = [name, 'manifest-source.json']
    if output.is_symlink():
        raise ValueError('Output must not be a symlink')
    if any(os.path.lexists(output / item) for item in names):
        raise FileExistsError('Source release output already exists')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.isohopper-source-', dir=output) as directory:
        stage = Path(directory)
        archive = stage / name
        prefix = f'isohopper-{tag}/'
        subprocess.run(['git', '-C', str(root), 'archive', '--format=tar.gz',
                        f'--prefix={prefix}', f'--output={archive.resolve()}', revision], check=True)
        if not 0 < archive.stat().st_size <= MAX_SOURCE:
            raise ValueError('Source archive exceeds size bound')
        # Reject export-ignore/export-subst surprises: archived names and bytes
        # must equal the immutable Git tree, not the caller working directory.
        total = 0
        seen = set()
        with tarfile.open(archive, 'r:gz') as content:
            for member in content:
                if member.isdir():
                    continue
                relative = member.name.removeprefix(prefix)
                if not member.isfile() or not member.name.startswith(prefix) or relative not in files or relative in seen:
                    raise ValueError('Unexpected source archive member')
                total += member.size
                if total > MAX_SOURCE:
                    raise ValueError('Expanded source exceeds size bound')
                data = content.extractfile(member).read()
                if data != git('show', f'{revision}:{relative}'):
                    raise ValueError('Archived source differs from exact revision')
                seen.add(relative)
        if seen != files:
            raise ValueError('Source archive omitted tracked build inputs')
        artifact = {'name': name, 'kind': 'project-source', 'size': archive.stat().st_size,
                    'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
        manifest = {'schema_version': 2, 'tag': tag, 'source_revision': revision, 'artifact': artifact}
        (stage / names[1]).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        published = []
        try:
            for item in names:
                os.link(stage / item, output / item)
                published.append(item)
        except BaseException:
            for item in published:
                if os.path.samestat((output / item).lstat(), (stage / item).stat()):
                    (output / item).unlink()
            raise
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    print(json.dumps(package_source(args.root, args.output, args.tag, args.source_revision), indent=2))


if __name__ == '__main__':
    main()
