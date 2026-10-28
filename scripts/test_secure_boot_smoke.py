# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location('secure_smoke', Path(__file__).with_name('secure-boot-smoke.py'))
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def signed_pe():
    data = bytearray(1152)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<HH', data, 132, 0x8664, 1)
    struct.pack_into('<H', data, 148, 240)
    struct.pack_into('<H', data, 152, 0x20b)
    struct.pack_into('<H', data, 220, 10)
    struct.pack_into('<I', data, 260, 16)
    struct.pack_into('<II', data, 296, 1024, 128)
    struct.pack_into('<II', data, 408, 512, 512)
    struct.pack_into('<I', data, 428, 0x60000020)
    return data


class SecureBootSmokeTests(unittest.TestCase):
    def test_utility_kind_changes_only_the_signed_case_action(self):
        for kind, accepted_action in [('returning-efi', 'utility'),
                                      ('linux-diagnostic', 'linux-diagnostic')]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, output = root / 'private', root / 'output'
                private.mkdir()
                output.mkdir()
                args = SimpleNamespace(cli=Path('/test/isohopper'), qemu='test-qemu',
                                       timeout=30, utility_kind=kind)
                for name in ('launcher', 'utility', 'code', 'vars'):
                    source = root / name
                    source.write_bytes(b'test input')
                    setattr(args, name, source)
                actions = []

                def fake_run(command, _deadline, **kwargs):
                    if command[0] == 'openssl':
                        Path(command[command.index('-out') + 1]).write_bytes(b'test certificate')
                        if '-keyout' in command:
                            Path(command[command.index('-keyout') + 1]).write_bytes(b'test key')
                    elif command[0] == 'sbsign':
                        Path(command[command.index('--output') + 1]).write_bytes(signed_pe())
                    elif len(command) > 1 and Path(command[1]).name == 'firmware-smoke.py':
                        case = Path(command[command.index('--log') + 1]).stem
                        actions.append((case, command[command.index('--action') + 1]))
                        self.assertIn('--require-secure-boot', command)
                    return kwargs.get('allowed', (0,))[0], b'{}', b''

                with patch.object(smoke, 'run', side_effect=fake_run), \
                        patch.object(smoke, 'check_enrollment', return_value={}):
                    results = smoke.exercise(args, private, output, time.monotonic() + 10)
                self.assertEqual(actions, [('signed', accepted_action),
                                           ('unsigned', 'utility-reject'),
                                           ('tampered', 'utility-reject'),
                                           ('revoked', 'utility-reject')])
                self.assertEqual(results, dict.fromkeys(['signed', 'unsigned', 'tampered', 'revoked'], 'passed'))

    def test_utility_kind_default_and_diagnostic_summary_scope(self):
        for kind, signed in [(None, 'passed'), ('linux-diagnostic', 'passed'),
                             ('linux-diagnostic', 'failed')]:
            with self.subTest(kind=kind, signed=signed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'evidence'
                command = [str(Path(smoke.__file__))]
                for name in ('cli', 'launcher', 'utility', 'code', 'vars'):
                    command += [f'--{name}', '/not-used']
                command += ['--output', str(output)]
                if kind is not None:
                    command += ['--utility-kind', kind]
                cases = {'signed': signed, 'unsigned': 'passed',
                         'tampered': 'passed', 'revoked': 'passed'}
                with patch.object(sys, 'argv', command), \
                        patch.object(smoke, 'exercise', return_value=cases) as exercise, \
                        redirect_stdout(io.StringIO()):
                    code = smoke.main()
                summary = json.loads((output / 'summary.json').read_text())
                self.assertEqual(code, 0 if signed == 'passed' else 1)
                self.assertEqual(getattr(exercise.call_args.args[0], 'utility_kind', None),
                                 kind or 'returning-efi')
                if kind is None:
                    self.assertFalse(summary['os_boot_tested'])
                    self.assertNotIn('os_boot_scope', summary)
                    self.assertNotIn('utility_kind', summary)
                else:
                    self.assertEqual(summary['utility_kind'], 'linux-diagnostic')
                    self.assertEqual(summary['os_boot_scope'], 'custom-linux-diagnostic')
                    self.assertEqual(summary['os_boot_tested'], signed == 'passed')

    def test_failed_diagnostic_setup_preserves_scope_without_claiming_a_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence'
            command = [str(Path(smoke.__file__))]
            for name in ('cli', 'launcher', 'utility', 'code', 'vars'):
                command += [f'--{name}', '/not-used']
            command += ['--output', str(output), '--utility-kind', 'linux-diagnostic']
            with patch.object(sys, 'argv', command), \
                    patch.object(smoke, 'exercise', side_effect=ValueError('test setup failure')), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.main(), 1)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary.get('utility_kind'), 'linux-diagnostic')
            self.assertEqual(summary.get('os_boot_scope'), 'custom-linux-diagnostic')
            self.assertIs(summary.get('os_boot_tested'), False)

    def test_enrollment_accepts_only_exact_test_certificates_and_known_empty_dbx(self):
        def siglist(kind, content):
            return (uuid.UUID(kind).bytes_le + struct.pack('<III', 44 + len(content), 0, 16 + len(content))
                    + bytes(16) + content).hex()
        variables = []
        for name, contents in [('PK', [b'launcher']), ('KEK', [b'launcher']), ('db', [b'launcher', b'utility'])]:
            variables.append({'name': name, 'guid': ('8be4df61-93ca-11d2-aa0d-00e098032b8c' if name != 'db'
                                                   else 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'),
                              'data': ''.join(siglist('a5c059a1-94e4-4aa7-87b5-ab155c2bf072', c) for c in contents)})
        variables.append({'name': 'dbx', 'guid': 'd719b2cb-3d3a-4596-a3bc-dad00e67656f',
                          'data': siglist('c1c41626-504c-4092-aca9-41f936934328', hashlib.sha256(b'').digest())})
        launcher, utility = [hashlib.sha256(s).hexdigest() for s in (b'launcher', b'utility')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vars.json'
            def save():
                path.write_text(json.dumps({'version': 2, 'variables': variables}))
            save()
            self.assertEqual(smoke.check_enrollment(path, launcher, utility, False)['dbx'], [])
            variables[2]['data'] += siglist('a5c059a1-94e4-4aa7-87b5-ab155c2bf072', b'foreign')
            save()
            with self.assertRaisesRegex(ValueError, 'unexpected certificates'):
                smoke.check_enrollment(path, launcher, utility, False)

    def test_tamper_changes_exactly_one_signed_section_byte(self):
        original = signed_pe()
        changed, offset = smoke.tamper_pe(original)
        self.assertEqual(offset, 1023)
        self.assertEqual([i for i, (a, b) in enumerate(zip(original, changed)) if a != b], [offset])
        self.assertEqual(changed[:512], original[:512])
        self.assertEqual(changed[1024:], original[1024:])

    def test_tamper_rejects_missing_or_invalid_certificate_and_section_extents(self):
        for offset, value in [(60, 0xffffffff), (296, 700), (300, 0), (408, 0xffffffff), (412, 0), (428, 0)]:
            data = signed_pe()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                smoke.tamper_pe(data)
        for data in [b'', b'MZ', signed_pe()[:500]]:
            with self.assertRaises(ValueError):
                smoke.tamper_pe(data)

    def test_copy_refuses_symlinks_special_files_overflow_and_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'abc')
            self.assertEqual(smoke.copy_regular(source, root / 'copied', 3),
                             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
            link = root / 'link'
            link.symlink_to(source)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            for bad in [link, fifo, root]:
                with self.subTest(path=bad), self.assertRaises((OSError, ValueError)):
                    smoke.copy_regular(bad, root / 'bad', 3)
            with self.assertRaises(ValueError):
                smoke.copy_regular(source, root / 'oversize', 2)
            with self.assertRaises(FileExistsError):
                smoke.copy_regular(source, root / 'copied', 3)
            self.assertEqual((root / 'copied').read_bytes(), b'abc')

    def test_runner_bounds_output_and_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'output limit'):
            smoke.run([sys.executable, '-c', 'import os; os.write(1, b"x"*100000)'],
                      time.monotonic() + 2, max_output=1024)
        with self.assertRaises(TimeoutError):
            smoke.run([sys.executable, '-c', 'import time; time.sleep(30)'],
                      time.monotonic() + 0.06)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_runner_preserves_return_code_and_rejects_unexpected_failure(self):
        code, out, err = smoke.run([sys.executable, '-c', 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(1)'],
                                   time.monotonic() + 2, allowed=(0, 1))
        self.assertEqual((code, out, err), (1, b'out\n', b'err\n'))
        with self.assertRaisesRegex(RuntimeError, 'exit 2'):
            smoke.run([sys.executable, '-c', 'raise SystemExit(2)'], time.monotonic() + 2)

    def test_timeout_kills_descendant_processes_before_they_can_write(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'escaped-child'
            child = f'import time, pathlib; time.sleep(0.3); pathlib.Path({str(marker)!r}).write_text("escaped")'
            parent = f'import subprocess, sys, time; subprocess.Popen([sys.executable, "-c", {child!r}]); time.sleep(30)'
            with self.assertRaises(TimeoutError):
                smoke.run([sys.executable, '-c', parent], time.monotonic() + 0.1)
            time.sleep(0.35)
            self.assertFalse(marker.exists())

    def test_existing_evidence_directory_is_never_reused(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'keep'
            marker.write_text('original')
            command = [sys.executable, str(Path(smoke.__file__))]
            for name in ('cli', 'launcher', 'utility', 'code', 'vars'):
                command += [f'--{name}', '/not-used']
            command += ['--output', str(root)]
            result = subprocess.run(command, capture_output=True, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(root.iterdir()), [marker])
            self.assertEqual(marker.read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
