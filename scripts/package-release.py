#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Collect already-tested native builds into bounded, checksummed release assets."""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import zipfile

MAX_BINARY = 2 * 1024 * 1024 * 1024
MAX_DOCUMENT = 2 * 1024 * 1024
PLATFORMS = {
    'linux-x64': [('deb', '*.deb', '.deb'), ('appimage', '*.AppImage', '.AppImage')],
    'windows-x64': [('nsis', '*.exe', '-setup.exe')],
    'macos-arm64': [('dmg', '*.dmg', '.dmg')],
    'macos-x64': [('dmg', '*.dmg', '.dmg')],
}


def metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def opening_metadata(info):
    if os.name != 'nt':
        return metadata(info)
    # Windows CPython can return birth time in lstat().st_ctime_ns but change
    # time in fstat().st_ctime_ns (cpython#157671). Compare compatible fields
    # across these APIs; finish() still compares full fstat metadata.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            getattr(info, 'st_birthtime_ns', None))


class OpenedFile:
    """Retain the checked inode and reject changes while collecting its bytes."""
    def __init__(self, path, max_size=MAX_BINARY):
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= max_size:
            raise ValueError(f'Expected a nonempty bounded regular file: {path.name}')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opening_metadata(before) != opening_metadata(opened):
                raise ValueError(f'Source changed while opening: {path.name}')
            self.file = os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise
        self.before = opened
        self.size = opened.st_size

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.file.close()

    def finish(self):
        if self.file.read(1) or metadata(os.fstat(self.file.fileno())) != metadata(self.before):
            raise ValueError('Source grew or changed during packaging')

    def copy_to(self, writer):
        remaining = self.size
        while remaining:
            block = self.file.read(min(remaining, 1024 * 1024))
            if not block:
                raise ValueError('Source shrank during packaging')
            writer.write(block)
            remaining -= len(block)
        self.finish()


def build_info(platform, tag, revision):
    runtime = {
        'linux-x64': 'Linux x64. Studio needs compatible glibc, GTK 3 and WebKitGTK 4.1; distribution compatibility is not guaranteed.',
        'windows-x64': 'Windows x64. Studio needs WebView2 Runtime; its installer may download that runtime. Windows artifacts are not publisher-signed.',
        'macos-arm64': 'macOS Apple Silicon. Studio uses ad-hoc signing, not Developer ID signing or notarization; macOS may block downloaded applications.',
        'macos-x64': 'macOS Intel. Studio uses ad-hoc signing, not Developer ID signing or notarization; macOS may block downloaded applications.',
    }[platform]
    return (f'IsoHopper {tag}\nPlatform: {platform}\nSource revision: {revision}\n'
            f'Source: https://github.com/IsoHopper/isohopper/tree/{revision}\n\n'
            'Experimental build, pending human hardware testing.\n'
            'Physical disk writes are disabled. Host disk inventory is read-only.\n'
            'General OS installation and physical hardware compatibility are unvalidated.\n'
            'Production Secure Boot signing is unavailable.\n'
            f'{runtime}\n\n'
            'Checksums detect changed bytes; they are not publisher authentication.\n'
            'Original project source: GPL-3.0-or-later. See LICENSE and CONTRIBUTORS.md.\n'
            'Dependencies retain their respective upstream licenses.\n').encode()


def cli_archive(path, platform, binary, documents, info):
    binary_name = 'isohopper.exe' if platform == 'windows-x64' else 'isohopper'
    entries = [(binary_name, binary, 0o755)] + [(name, value, 0o644) for name, value in documents.items()]
    with path.open('xb') as output:
        if platform == 'windows-x64':
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name, source, mode in entries + [('BUILD-INFO.txt', info, 0o644)]:
                    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    entry.create_system = 3
                    entry.external_attr = (stat.S_IFREG | mode) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    with archive.open(entry, 'w', force_zip64=True) as target:
                        if isinstance(source, OpenedFile):
                            source.copy_to(target)
                        else:
                            target.write(source)
        else:
            with gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                    for name, source, mode in entries + [('BUILD-INFO.txt', info, 0o644)]:
                        entry = tarfile.TarInfo(name)
                        entry.mode = mode
                        entry.mtime = 0
                        entry.size = source.size if isinstance(source, OpenedFile) else len(source)
                        archive.addfile(entry, source.file if isinstance(source, OpenedFile) else io.BytesIO(source))
                        if isinstance(source, OpenedFile):
                            source.finish()


def inventory(path, kind):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return {'name': path.name, 'kind': kind, 'size': path.stat().st_size,
            'sha256': digest.hexdigest()}


def package_release(root, output, platform, tag, revision):
    if platform not in PLATFORMS:
        raise ValueError('Unsupported release platform')
    if len(tag) > 80 or re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?', tag) is None:
        raise ValueError('Expected a bounded version tag such as v0.1.0-experimental.1')
    if re.fullmatch(r'[0-9a-fA-F]{40}', revision) is None:
        raise ValueError('Expected the full 40-character source revision')
    revision = revision.lower()
    root, output = Path(root), Path(output)
    bundle = root / 'studio/src-tauri/target/release/bundle'
    sources = []
    for folder, pattern, suffix in PLATFORMS[platform]:
        candidates = list((bundle / folder).glob(pattern))
        if len(candidates) != 1:
            raise ValueError(f'Expected exactly one {folder} installer, found {len(candidates)}')
        sources.append((candidates[0], f'IsoHopper-{tag}-{platform}{suffix}'))
    archive_name = f'isohopper-cli-{tag}-{platform}' + ('.zip' if platform == 'windows-x64' else '.tar.gz')
    manifest_name = f'manifest-{platform}.json'
    names = [name for _, name in sources] + [archive_name, manifest_name]
    if output.is_symlink():
        raise ValueError('Release output directory must not be a symlink')
    for name in names:
        if os.path.lexists(output / name):
            raise FileExistsError(f'Release output already exists: {name}')
    with ExitStack() as stack:
        # Open and validate every input before creating release output.
        installers = [(stack.enter_context(OpenedFile(path)), name) for path, name in sources]
        binary_name = 'isohopper.exe' if platform == 'windows-x64' else 'isohopper'
        binary = stack.enter_context(OpenedFile(root / 'target/release' / binary_name))
        documents = {name: stack.enter_context(OpenedFile(root / name, MAX_DOCUMENT))
                     for name in ['LICENSE', 'CONTRIBUTORS.md']}
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.isohopper-package-', dir=output) as directory:
            stage = Path(directory)
            artifacts = []
            for source, name in installers:
                with (stage / name).open('xb') as target:
                    source.copy_to(target)
                if name.endswith('.AppImage'):
                    (stage / name).chmod(0o755)
                artifacts.append(inventory(stage / name, 'studio-installer'))
            cli_archive(stage / archive_name, platform, binary, documents,
                        build_info(platform, tag, revision))
            artifacts.append(inventory(stage / archive_name, 'cli'))
            manifest = {'schema_version': 1, 'tag': tag, 'platform': platform,
                        'source_revision': revision, 'artifacts': sorted(artifacts, key=lambda item: item['name'])}
            (stage / manifest_name).write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
            published = []
            try:
                # Same-directory hard links publish complete files without an
                # overwrite race. No partially written asset becomes visible.
                for name in names:
                    os.link(stage / name, output / name)
                    published.append(name)
            except BaseException:
                for name in published:
                    candidate = output / name
                    if candidate.exists() and os.path.samestat(candidate.lstat(), (stage / name).stat()):
                        candidate.unlink()
                raise
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=PLATFORMS)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist/release'))
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        manifest = package_release(args.root, args.output, args.platform, args.tag, args.source_revision)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f'Packaging failed: {error}\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
