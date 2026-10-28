#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test disposable Secure Boot keys in QEMU; never access host firmware or disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
X509_GUID = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le


def copy_regular(source, target, limit=MAX_INPUT):
    """Copy only the bounded inode opened, rejecting final symlinks and changes."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as reader:
        before = os.fstat(reader.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('Input must be a nonempty bounded regular file')
        digest = hashlib.sha256()
        with Path(target).open('xb') as writer:
            remaining = before.st_size
            while remaining:
                block = reader.read(min(remaining, 128 * 1024))
                if not block:
                    raise ValueError('Input shrank during copy')
                writer.write(block)
                digest.update(block)
                remaining -= len(block)
            if reader.read(1):
                raise ValueError('Input grew during copy')
            after = os.fstat(reader.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Input changed during copy')
        return digest.hexdigest()


def run(command, deadline, timeout=30, allowed=(0,), max_output=MAX_OUTPUT):
    """Bound output and wall time; terminate the entire child process group."""
    end = min(deadline, time.monotonic() + timeout)
    if end <= time.monotonic():
        raise TimeoutError('Test deadline exceeded')
    process = subprocess.Popen([str(arg) for arg in command], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    output, errors = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Command deadline exceeded')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(65536, max_output + 1))
                    if chunk:
                        key.data.extend(chunk)
                        if len(output) + len(errors) > max_output:
                            raise RuntimeError('Command output limit exceeded')
                    else:
                        selector.unregister(key.fileobj)
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Command deadline exceeded')
            code = process.wait(timeout=remaining)
        if code not in allowed:
            # Never include command arguments or subprocess output: openssl
            # arguments name private key files, and tools may print their input.
            raise RuntimeError(f'{Path(command[0]).name} returned unexpected exit {code}')
        return code, bytes(output), bytes(errors)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def tamper_pe(data):
    """Change one authenticated section byte, preserving headers and certificate."""
    bad = ValueError('Expected a bounded signed x64 EFI test application')
    if not 64 <= len(data) <= MAX_INPUT or data[:2] != b'MZ':
        raise bad
    pe = struct.unpack_from('<I', data, 60)[0]
    if pe < 64 or pe + 24 > len(data) or data[pe:pe + 4] != b'PE\0\0':
        raise bad
    machine, sections = struct.unpack_from('<HH', data, pe + 4)
    optional = pe + 24
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    table = optional + optional_size
    table_end = table + 40 * sections
    if (machine != 0x8664 or not 1 <= sections <= 96 or optional_size < 152
            or table_end > len(data)):
        raise bad
    if (struct.unpack_from('<H', data, optional)[0] != 0x20b
            or struct.unpack_from('<H', data, optional + 68)[0] != 10
            or struct.unpack_from('<I', data, optional + 108)[0] < 5):
        raise bad
    certificate, certificate_size = struct.unpack_from('<II', data, optional + 144)
    if certificate < table_end or certificate_size < 8 or certificate + certificate_size > len(data):
        raise bad
    for offset in range(table, table_end, 40):
        size, start = struct.unpack_from('<II', data, offset + 16)
        flags = struct.unpack_from('<I', data, offset + 36)[0]
        if flags & 0x20000000 and size:
            if start < table_end or start + size > certificate:
                raise bad
            changed = bytearray(data)
            index = start + size - 1
            changed[index] ^= 1
            return changed, index
    raise bad


def certificate_hashes(data, allow_empty_hash=False):
    """Decode bounded X.509 EFI signature lists for enrollment assertions."""
    if len(data) > 128 * 1024:
        raise ValueError('Signature database exceeds test limit')
    result = []
    at = 0
    while at < len(data):
        if at + 28 > len(data):
            raise ValueError('Unexpected signature database type')
        size, header, signature = struct.unpack_from('<III', data, at + 16)
        if (header != 0 or signature <= 16 or size < 28 + signature
                or at + size > len(data) or (size - 28) % signature):
            raise ValueError('Invalid signature database bounds')
        kind = data[at:at + 16]
        # virt-fw-vars --secure-boot initializes an empty dbx with the SHA256
        # of an empty file. Accept only that exact non-certificate placeholder.
        if (allow_empty_hash and kind == uuid.UUID('c1c41626-504c-4092-aca9-41f936934328').bytes_le
                and size == 76 and signature == 48
                and data[at + 44:at + 76] == hashlib.sha256(b'').digest()):
            at += size
            continue
        if kind != X509_GUID:
            raise ValueError('Unexpected signature database type')
        for entry in range(at + 28, at + size, signature):
            result.append(hashlib.sha256(data[entry + 16:entry + signature]).hexdigest())
        at += size
    return sorted(result)


def check_enrollment(path, launcher_hash, utility_hash, revoked):
    if path.stat().st_size > MAX_OUTPUT:
        raise ValueError('Enrollment JSON exceeds test limit')
    document = json.loads(path.read_bytes())
    expected = {'PK': [launcher_hash], 'KEK': [launcher_hash],
                'db': sorted([launcher_hash, utility_hash]),
                'dbx': [utility_hash] if revoked else []}
    observed = {name: [] for name in expected}
    seen = set()
    if document.get('version') != 2 or not isinstance(document.get('variables'), list):
        raise ValueError('Unsupported enrollment JSON')
    for variable in document['variables']:
        name = variable.get('name')
        if name not in expected:
            continue
        vendor = ('8be4df61-93ca-11d2-aa0d-00e098032b8c' if name in ('PK', 'KEK')
                  else 'd719b2cb-3d3a-4596-a3bc-dad00e67656f')
        if name in seen or variable.get('guid') != vendor:
            raise ValueError('Duplicate or unexpected enrollment variable')
        seen.add(name)
        observed[name] = certificate_hashes(bytes.fromhex(variable['data']),
                                            allow_empty_hash=name == 'dbx' and not revoked)
    if observed != expected:
        raise ValueError('Enrollment contains missing or unexpected certificates')
    return observed


def write_json(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def exercise(args, private, output, deadline):
    inputs = {}
    for name in ('launcher', 'utility', 'code', 'vars'):
        inputs[name] = copy_regular(getattr(args, name), private / name)
    write_json(output / 'input-sha256.json', inputs)
    cert_hashes = {}
    for name in ('launcher', 'utility'):
        run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-sha256', '-days', '2', '-subj', f'/CN=IsoHopper disposable {name} test/',
             '-keyout', private / f'{name}.key', '-out', private / f'{name}.crt'], deadline, timeout=60)
        run(['openssl', 'x509', '-in', private / f'{name}.crt', '-outform', 'DER',
             '-out', private / f'{name}.der'], deadline)
        cert_hashes[name] = hashlib.sha256((private / f'{name}.der').read_bytes()).hexdigest()
        run(['sbsign', '--key', private / f'{name}.key', '--cert', private / f'{name}.crt',
             '--output', private / f'{name}.signed', private / name], deadline)
        run(['sbverify', '--cert', private / f'{name}.crt', private / f'{name}.signed'], deadline)
    write_json(output / 'certificate-sha256.json', cert_hashes)
    changed, offset = tamper_pe((private / 'utility.signed').read_bytes())
    (private / 'utility.tampered').write_bytes(changed)
    for name in ('utility', 'utility.tampered'):
        run(['sbverify', '--cert', private / 'utility.crt', private / name], deadline, allowed=(1,))
    write_json(output / 'tamper.json', {'section_byte_offset': offset,
                                      'signed_sha256': hashlib.sha256((private / 'utility.signed').read_bytes()).hexdigest(),
                                      'tampered_sha256': hashlib.sha256(changed).hexdigest()})
    owner = str(uuid.uuid4())
    for revoked in (False, True):
        stem = 'revoked' if revoked else 'enrolled'
        command = ['virt-fw-vars', '--input', private / 'vars',
                   '--delete', 'PK', '--delete', 'KEK', '--delete', 'db', '--delete', 'dbx',
                   '--microsoft-db', 'none', '--microsoft-kek', 'none',
                   '--set-pk', owner, private / 'launcher.crt',
                   '--add-kek', owner, private / 'launcher.crt',
                   '--add-db', owner, private / 'launcher.crt',
                   '--add-db', owner, private / 'utility.crt', '--secure-boot',
                   '--output', private / f'{stem}.fd', '--output-json', private / f'{stem}.json']
        if revoked:
            command.extend(['--add-dbx-cert', owner, private / 'utility.crt'])
        run(command, deadline)
        observed = check_enrollment(private / f'{stem}.json', cert_hashes['launcher'],
                                    cert_hashes['utility'], revoked)
        write_json(output / f'{stem}-certificates.json', observed)
    results = {}
    accepted_action = 'linux-diagnostic' if args.utility_kind == 'linux-diagnostic' else 'utility'
    for name, utility, variables, action in [
            ('signed', 'utility.signed', 'enrolled', accepted_action),
            ('unsigned', 'utility', 'enrolled', 'utility-reject'),
            ('tampered', 'utility.tampered', 'enrolled', 'utility-reject'),
            ('revoked', 'utility.signed', 'revoked', 'utility-reject')]:
        image = private / f'{name}.img'
        common = ['--efi', private / 'launcher.signed', '--utility', private / utility]
        run([args.cli, 'image', 'create', image, '--size-mib', '256', *common], deadline)
        run([args.cli, 'image', 'verify', image, *common], deadline)
        code, stdout, stderr = run([sys.executable, Path(__file__).with_name('firmware-smoke.py'),
                '--image', image, '--code', private / 'code', '--vars', private / f'{variables}.fd',
                '--qemu', args.qemu, '--action', action, '--require-secure-boot',
                '--timeout', str(args.timeout), '--log', output / f'{name}.log'],
                deadline, timeout=args.timeout + 15, allowed=(0, 1, 2))
        (output / f'{name}.json').write_bytes(stdout)
        (output / f'{name}.stderr').write_bytes(stderr)
        results[name] = 'passed' if code == 0 else 'failed'
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cli', 'launcher', 'utility', 'code', 'vars', 'output'):
        parser.add_argument(f'--{name}', required=True, type=Path)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--utility-kind', choices=['returning-efi', 'linux-diagnostic'],
                        default='returning-efi',
                        help='Accepted payload: returning EFI utility or custom Linux diagnostic')
    parser.add_argument('--timeout', type=int, default=90, help='Seconds per guest (1..90)')
    args = parser.parse_args()
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        parser.error('This isolated test requires Linux or macOS')
    if not 1 <= args.timeout <= 90:
        parser.error('timeout must be 1..90 seconds per guest')
    args.cli = args.cli.absolute()
    args.output = args.output.absolute()
    previous_mask = os.umask(0o077)
    started = time.monotonic()
    try:
        args.output.mkdir(mode=0o700)
        try:
            # Never place secrets, images, or variable stores under the evidence directory.
            with tempfile.TemporaryDirectory(prefix='isohopper-secure-boot-') as private:
                if Path(private).is_relative_to(args.output):
                    raise ValueError('Temporary storage must be outside the evidence directory')
                results = exercise(args, Path(private), args.output,
                                   started + 120 + 4 * (args.timeout + 15))
            summary = {'status': 'passed' if all(v == 'passed' for v in results.values()) else 'failed',
                       'cases': results, 'keys': 'disposable-test-only',
                       'physical_devices_attached': False, 'host_firmware_modified': False,
                       'production_signing_tested': False, 'os_boot_tested': False}
            if args.utility_kind == 'linux-diagnostic':
                summary['os_boot_tested'] = results.get('signed') == 'passed'
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            summary = {'status': 'failed', 'reason': str(error)}
        if args.utility_kind == 'linux-diagnostic':
            summary.update(utility_kind='linux-diagnostic',
                           os_boot_scope='custom-linux-diagnostic')
            summary.setdefault('os_boot_tested', False)
        summary['elapsed_seconds'] = round(time.monotonic() - started, 2)
        write_json(args.output / 'summary.json', summary)
        print(json.dumps(summary, indent=2))
        return 0 if summary['status'] == 'passed' else 1
    finally:
        os.umask(previous_mask)


if __name__ == '__main__':
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
