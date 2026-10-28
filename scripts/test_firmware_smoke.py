# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('firmware-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

class UtilityEvidence(unittest.TestCase):
    def test_linux_diagnostic_requires_ordered_boot_userspace_and_clean_poweroff(self):
        stages = [smoke.MARKER, b'ISOHOPPER:UTILITY:START', b'[    0.000000] Linux version 6.8.0-test (builder)',
                  b'ISOHOPPER:LINUX:INIT_PID1', b'[    1.000000] reboot: Power down']
        complete = b'\n'.join(stages)
        self.assertTrue(smoke.linux_diagnostic_completed(complete, 0))
        self.assertFalse(smoke.linux_diagnostic_completed(complete, 1))
        for index in range(len(stages)):
            with self.subTest(missing=index):
                self.assertFalse(smoke.linux_diagnostic_completed(b'\n'.join(stages[:index] + stages[index + 1:]), 0))
        self.assertFalse(smoke.linux_diagnostic_completed(b'\n'.join(reversed(stages)), 0))
        for failure in [b'Kernel panic - not syncing', b'ISOHOPPER:UTILITY:RETURN',
                        b'ISOHOPPER:UTILITY:SECURITY_VIOLATION', b'ISOHOPPER:UTILITY:ACCESS_DENIED',
                        b'ISOHOPPER:LINUX:FAIL']:
            with self.subTest(failure=failure):
                self.assertFalse(smoke.linux_diagnostic_completed(complete + b'\n' + failure, 0))

    def test_linux_mode_waits_for_process_exit_and_limits_os_claim(self):
        real_popen = subprocess.Popen
        serial = '\n'.join(['ISOHOPPER:SMOKE:ENTRY', 'ISOHOPPER:UTILITY:START',
                            'Linux version 6.8.0-test (builder)', 'ISOHOPPER:LINUX:INIT_PID1',
                            'reboot: Power down'])
        for exit_code in [0, 1]:
            def fake_qemu(command, **kwargs):
                return real_popen([sys.executable, '-c', f'print({serial!r}, flush=True); raise SystemExit({exit_code})'], **kwargs)
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ['image', 'code', 'vars']:
                    (root/name).write_bytes(b'fixture')
                argv = ['firmware-smoke.py', '--image', str(root/'image'), '--code', str(root/'code'),
                        '--vars', str(root/'vars'), '--log', str(root/'serial.log'),
                        '--action', 'linux-diagnostic', '--timeout', '2']
                output = io.StringIO()
                with patch.object(sys, 'argv', argv), patch.object(smoke.subprocess, 'Popen', side_effect=fake_qemu), \
                     patch.object(smoke.socket, 'socket', return_value=MagicMock()), \
                     patch.object(smoke, 'read_qmp_line', side_effect=[b'{"QMP":{}}', b'{"return":{}}', b'{"return":{}}', b'{"return":{}}']), \
                     patch.object(smoke.time, 'sleep'), redirect_stdout(output):
                    result = smoke.main()
                evidence = json.loads(output.getvalue())
                self.assertEqual(result, exit_code)
                self.assertEqual(evidence['os_boot_tested'], exit_code == 0)
                self.assertEqual(evidence['os_boot_scope'], 'custom-linux-diagnostic')

    def test_power_marker_without_entry_cannot_pass_main(self):
        real_popen = subprocess.Popen
        # Exercise the real selector/EOF path using a child that only emits a
        # power marker. It never starts QEMU or executes the input fixtures.
        def fake_qemu(command, **kwargs):
            return real_popen([sys.executable, '-c',
                "print('ISOHOPPER:POWER:SHUTDOWN', flush=True)"], **kwargs)
        for require_secure in [False, True]:
            with self.subTest(require_secure=require_secure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ['image', 'code', 'vars']:
                    (root/name).write_bytes(b'fixture')
                argv = ['firmware-smoke.py', '--image', str(root/'image'),
                    '--code', str(root/'code'), '--vars', str(root/'vars'),
                    '--log', str(root/'serial.log'), '--action', 'shutdown', '--timeout', '2']
                if require_secure:
                    argv.append('--require-secure-boot')
                output = io.StringIO()
                with patch.object(sys, 'argv', argv), patch.object(smoke.subprocess, 'Popen', side_effect=fake_qemu), redirect_stdout(output):
                    result = smoke.main()
                self.assertEqual(result, 1)
                evidence = json.loads(output.getvalue())
                self.assertEqual(evidence['status'], 'failed')
                self.assertFalse(evidence['secure_boot_reported_enabled'])

    def test_secure_boot_requires_explicit_enabled_state(self):
        enabled = b'ISOHOPPER:SECURE_BOOT:ENABLED'
        self.assertTrue(smoke.secure_boot_enabled(enabled + smoke.MARKER))
        for state in [b'', b'ISOHOPPER:SECURE_BOOT:UNKNOWN', b'ISOHOPPER:SECURE_BOOT:DISABLED', enabled + b'ISOHOPPER:SECURE_BOOT:DISABLED']:
            self.assertFalse(smoke.secure_boot_enabled(state + smoke.MARKER))

    def test_rejection_requires_security_violation_without_child_start(self):
        rejected = b'ISOHOPPER:UTILITY:SECURITY_VIOLATION'
        self.assertTrue(smoke.utility_rejected(rejected))
        self.assertTrue(smoke.utility_rejected(b'ISOHOPPER:UTILITY:ACCESS_DENIED'))
        for invalid in [b'', b'not found', b'ISOHOPPER:UTILITY:START' + rejected, rejected + b'ISOHOPPER:TEST_UTILITY:ENTRY', rejected + b'ISOHOPPER:UTILITY:RETURN']:
            self.assertFalse(smoke.utility_rejected(invalid))

    def test_utility_requires_start_child_entry_and_return(self):
        start = b'ISOHOPPER:UTILITY:START'
        child = b'ISOHOPPER:TEST_UTILITY:ENTRY'
        returned = b'ISOHOPPER:UTILITY:RETURN'
        self.assertTrue(smoke.utility_returned(start + child + returned))
        for partial in [b'', start, start + returned, child + returned, returned + child + start]:
            self.assertFalse(smoke.utility_returned(partial))

class InputSafety(unittest.TestCase):
    def test_retained_file_survives_path_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'image.img'
            path.write_bytes(b'original')
            with smoke.open_regular(path) as retained:
                path.unlink()
                path.symlink_to('/dev/zero')
                self.assertEqual(retained.read(), b'original')
            with self.assertRaises(OSError): smoke.open_regular(path)

    def test_fifo_and_directory_are_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'fifo'
            os.mkfifo(path)
            for value in [path, Path(root)]:
                with self.assertRaises(ValueError): smoke.open_regular(value)

    def test_output_never_overwrites_existing_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'log'
            target = Path(root)/'valuable'
            target.write_bytes(b'original')
            path.symlink_to(target)
            with self.assertRaises(FileExistsError): smoke.exclusive_log(path)
            with self.assertRaises(FileExistsError): smoke.exclusive_log(target)
            self.assertEqual(target.read_bytes(), b'original')

class QmpReadSafety(unittest.TestCase):
    def test_continuous_partial_line_still_hits_absolute_deadline(self):
        stopped = threading.Event()
        receiver, sender = socket.socketpair()
        def trickle():
            try:
                for _ in range(20):
                    sender.sendall(b'x')
                    if stopped.wait(0.015):
                        return
                sender.sendall(b'\n')
            except OSError:
                return
        with receiver, sender:
            writer = threading.Thread(target=trickle)
            writer.start()
            started = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    smoke.read_qmp_line(receiver, bytearray(), started + 0.06)
                self.assertLess(time.monotonic() - started, 0.75)
            finally:
                stopped.set()
                writer.join(timeout=0.5)
            self.assertFalse(writer.is_alive())

    def test_oversized_line_is_rejected(self):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.settimeout(0.25)
            def oversized():
                try:
                    sender.sendall(b'x' * 65537 + b'\n')
                except OSError:
                    return
            writer = threading.Thread(target=oversized)
            writer.start()
            try:
                with self.assertRaisesRegex(RuntimeError, 'oversized'):
                    smoke.read_qmp_line(receiver, bytearray(), time.monotonic() + 0.5)
            finally:
                receiver.shutdown(socket.SHUT_RD)
                writer.join(timeout=0.5)
            self.assertFalse(writer.is_alive())

    def test_coalesced_messages_preserve_the_next_line(self):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(b'{"QMP":{}}\r\n{"return":{}}\r\n')
            pending = bytearray()
            deadline = time.monotonic() + 0.5
            self.assertEqual(smoke.read_qmp_line(receiver, pending, deadline), b'{"QMP":{}}\r\n')
            self.assertEqual(smoke.read_qmp_line(receiver, pending, deadline), b'{"return":{}}\r\n')

    def test_closed_partial_line_is_rejected(self):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(b'{"QMP":')
            sender.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(RuntimeError, 'closed'):
                smoke.read_qmp_line(receiver, bytearray(), time.monotonic() + 0.5)

    def test_buffered_line_cannot_bypass_expired_deadline(self):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            with self.assertRaises(TimeoutError):
                smoke.read_qmp_line(receiver, bytearray(b'{}\n'), time.monotonic() - 1)

if __name__ == '__main__': unittest.main()
