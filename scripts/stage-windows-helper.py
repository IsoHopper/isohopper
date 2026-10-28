#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage a built x64 Windows helper for Tauri; this does not sign or authenticate it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

TARGETS = ('x86_64-pc-windows-msvc', 'x86_64-pc-windows-gnu')
MAX_HELPER_BYTES = 256 * 1024 * 1024


def metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def redirected(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def validate_image(data):
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('Helper is not a Windows executable')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if pe < 64 or pe + 26 > len(data) or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Helper has an invalid PE header')
    machine, _, _, _, _, optional_size, characteristics = struct.unpack_from('<HHIIIHH', data, pe + 4)
    if (machine != 0x8664 or optional_size < 0xf0 or pe + 24 + optional_size > len(data)
            or struct.unpack_from('<H', data, pe + 24)[0] != 0x20b
            or struct.unpack_from('<H', data, pe + 24 + 68)[0] not in (2, 3)
            or not characteristics & 0x2 or characteristics & 0x2000):
        raise ValueError('Helper must be an x64 Windows GUI/console executable, not a DLL or firmware')


def stage_helper(root, source, target):
    if target not in TARGETS:
        raise ValueError('Unsupported Windows helper target')
    root, source = Path(root), Path(source)
    before = source.lstat()
    if redirected(before) or not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_HELPER_BYTES:
        raise ValueError('Helper must be a nonempty bounded regular file')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(source, flags), 'rb') as opened:
        start = os.fstat(opened.fileno())
        if not stat.S_ISREG(start.st_mode) or metadata(start) != metadata(before):
            raise ValueError('Helper changed while opening')
        data = opened.read(MAX_HELPER_BYTES + 1)
        if len(data) != start.st_size or metadata(os.fstat(opened.fileno())) != metadata(start):
            raise ValueError('Helper changed while reading')
    validate_image(data)
    # The repository is trusted build input; reject accidental redirected output.
    relative = Path('studio/src-tauri/binaries')
    current = root
    for part in relative.parts:
        current /= part
        try:
            if redirected(current.lstat()):
                raise ValueError('Helper staging directory must not be a reparse point or symlink')
        except FileNotFoundError:
            pass
    current.mkdir(parents=True, exist_ok=True)
    destination = current / f'isohopper-helper-{target}.exe'
    try:
        info = destination.lstat()
        if redirected(info) or not stat.S_ISREG(info.st_mode):
            raise ValueError('Helper staging output must be a regular file')
    except FileNotFoundError:
        pass
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.helper-', dir=current, delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {'path': destination.relative_to(root).as_posix(), 'target': target,
            'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--target', choices=TARGETS, default=TARGETS[0])
    args = parser.parse_args()
    try:
        result = stage_helper(args.root, args.source, args.target)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Helper staging failed: {error}\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
