# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
from pathlib import Path
import os
import socket
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('firmware-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

class UtilityEvidence(unittest.TestCase):
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
