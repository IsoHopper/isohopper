#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Boot a retained regular-file image in QEMU. No host block device is attached."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import subprocess
import tempfile
import time

MAX_OUTPUT = 4 * 1024 * 1024
MAX_QMP_LINE = 65536
MARKER = b'ISOHOPPER:SMOKE:ENTRY'


def open_regular(path):
    """Keep the validated inode open; do not ask QEMU to reopen the source path."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f'Expected a regular file: {path}')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def exclusive_log(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open('xb')


def qmp_remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('QMP response deadline exceeded')
    return remaining


def read_qmp_line(monitor, pending, deadline):
    """Read one bounded line, retaining coalesced messages and an absolute deadline."""
    while True:
        remaining = qmp_remaining(deadline)
        newline = pending.find(b'\n')
        if newline >= 0:
            if newline >= MAX_QMP_LINE:
                raise RuntimeError('Invalid or oversized QMP response')
            line = bytes(pending[:newline + 1])
            del pending[:newline + 1]
            return line
        if len(pending) >= MAX_QMP_LINE:
            raise RuntimeError('Invalid or oversized QMP response')
        monitor.settimeout(remaining)
        chunk = monitor.recv(min(4096, MAX_QMP_LINE - len(pending)))
        if not chunk:
            raise RuntimeError('QMP connection closed before a complete response')
        pending.extend(chunk)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--code', required=True, type=Path, help='OVMF/EDK2 x64 code image')
    parser.add_argument('--vars', required=True, type=Path, help='Matching clean vars template')
    parser.add_argument('--action', choices=['shutdown', 'reboot', 'firmware-setup'], help='Exercise a confirmed power action inside QEMU only')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--timeout', type=int, default=45)
    parser.add_argument('--log', type=Path, help='New log file; existing files are refused')
    args = parser.parse_args()
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        parser.error('This descriptor-bound test harness requires Linux or macOS')
    if not 1 <= args.timeout <= 300:
        parser.error('timeout must be 1..300 seconds')
    with ExitStack() as stack:
        try:
            inputs = [stack.enter_context(open_regular(path)) for path in [args.image, args.code, args.vars]]
            if args.log is None:
                Path('.local').mkdir(exist_ok=True)
                log = stack.enter_context(tempfile.NamedTemporaryFile(mode='wb', prefix='firmware-', suffix='.log', dir='.local', delete=False))
                args.log = Path(log.name)
            else:
                log = stack.enter_context(exclusive_log(args.log))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        temp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='isohopper-qemu-')))
        var_path = temp / 'vars.fd'
        with var_path.open('xb') as var_copy:
            before = os.fstat(inputs[2].fileno())
            if before.st_size > 64 * 1024 * 1024:
                parser.error('Firmware vars template exceeds 64 MiB')
            remaining = before.st_size
            while remaining:
                block = inputs[2].read(min(remaining, 128 * 1024))
                if not block:
                    parser.error('Firmware vars template shrank during copy')
                var_copy.write(block)
                remaining -= len(block)
            after = os.fstat(inputs[2].fileno())
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                parser.error('Firmware vars template changed during copy')
        fd_prefix = '/proc/self/fd' if Path('/proc/self/fd').is_dir() else '/dev/fd'
        image_fd, code_fd = inputs[0].fileno(), inputs[1].fileno()
        qmp_path = temp / 'monitor.sock'
        command = [args.qemu, '-machine', 'q35,accel=tcg', '-m', '256', '-nodefaults',
            '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
            '-qmp', f'unix:{qmp_path},server=on,wait=off',
            '-drive', f'if=pflash,format=raw,readonly=on,file={fd_prefix}/{code_fd}',
            '-drive', f'if=pflash,format=raw,file={var_path}',
            '-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0',
            '-drive', f'if=none,id=usbdrive,format=raw,snapshot=on,file={fd_prefix}/{image_fd}',
            '-device', 'usb-storage,drive=usbdrive,bus=xhci.0,bootindex=1']
        started = time.monotonic()
        passed = False
        reason = 'timeout'
        action_sent = False
        action_markers = {'shutdown': b'ISOHOPPER:POWER:SHUTDOWN', 'reboot': b'ISOHOPPER:POWER:REBOOT', 'firmware-setup': b'ISOHOPPER:POWER:FIRMWARE_SETUP'}
        output = bytearray()
        errors = bytearray()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(image_fd, code_fd))
        selector = stack.enter_context(selectors.DefaultSelector())
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        try:
            while time.monotonic() - started < args.timeout:
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fd, 65536)
                    if chunk:
                        key.data.extend(chunk)
                    else:
                        selector.unregister(key.fileobj)
                if len(output) + len(errors) > MAX_OUTPUT:
                    reason = 'output-limit'
                    break
                if MARKER in output:
                    if args.action is None:
                        passed = True
                        reason = 'firmware-entry'
                        break
                    if not action_sent:
                        with socket.socket(socket.AF_UNIX) as monitor:
                            deadline = min(started + args.timeout, time.monotonic() + 3)
                            monitor.settimeout(qmp_remaining(deadline))
                            monitor.connect(str(qmp_path))
                            pending = bytearray()
                            greeting = json.loads(read_qmp_line(monitor, pending, deadline))
                            if not isinstance(greeting, dict) or 'QMP' not in greeting:
                                raise RuntimeError('Invalid QMP greeting')
                            def qmp(command, arguments=None):
                                request = {'execute': command}
                                if arguments is not None:
                                    request['arguments'] = arguments
                                deadline = min(started + args.timeout, time.monotonic() + 3)
                                monitor.settimeout(qmp_remaining(deadline))
                                monitor.sendall(json.dumps(request).encode() + b'\n')
                                for _ in range(64):
                                    line = read_qmp_line(monitor, pending, deadline)
                                    reply = json.loads(line)
                                    if not isinstance(reply, dict):
                                        raise RuntimeError('Invalid QMP response')
                                    if 'error' in reply:
                                        raise RuntimeError(reply['error'])
                                    if 'return' in reply:
                                        return reply['return']
                                raise RuntimeError('QMP event limit exceeded')
                            qmp('qmp_capabilities')
                            for key_name in [{'shutdown': 's', 'reboot': 'r', 'firmware-setup': 'f'}[args.action], 'y']:
                                qmp('send-key', {'keys': [{'type': 'qcode', 'data': key_name}], 'hold-time': 50})
                                time.sleep(0.15)
                        action_sent = True
                if not selector.get_map():
                    reason = 'qemu-exited'
                    process.wait(timeout=5)
                    if args.action and action_markers[args.action] in output and process.returncode == 0:
                        passed = True
                        reason = 'power-action-exited-qemu'
                    break
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            reason = 'monitor-error'
            errors.extend(str(error).encode()[:65536])
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
        log.write(output[:MAX_OUTPUT] + b'\nQEMU STDERR\n' + errors[:MAX_OUTPUT])
        print(json.dumps({'status': 'passed' if passed else 'failed', 'reason': reason,
            'marker': MARKER.decode(), 'action': args.action, 'elapsed_seconds': round(time.monotonic() - started, 2),
            'transport': 'emulated USB', 'physical_devices_attached': False,
            'secure_boot_tested': False, 'os_boot_tested': False, 'log': str(args.log)}, indent=2))
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
