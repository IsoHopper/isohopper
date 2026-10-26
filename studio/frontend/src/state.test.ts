// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { canSimulate, confirmationMatches, fileProblem, safeFileName, escapeHTML, relativeImagePath, browserRelativePath, destinationKey, type DiskRecord } from './state';
const ordinary: DiskRecord = { disk: { id: 'usb', serial: '1234', model: 'USB', bus: 'USB', size_bytes: 64_000_000_000, logical_sector_size: 512 }, verdict: { state: 'ok', hard_blocks: [], risks: [] }, challenge: '' };
const risky: DiskRecord = { ...ordinary, disk: { ...ordinary.disk, id: 'nvme' }, verdict: { state: 'confirm', hard_blocks: [], risks: [{ code: 'large', message: 'Large disk' }] }, challenge: 'WIPE 1TB-EXTERNAL-7F3K' };
describe('disk-bound simulation gate', () => {
  it('needs a selected disk and available capacity', () => {
    expect(canSimulate(undefined, '', 0, false)).toBe(false);
    expect(canSimulate(ordinary, '', 63_000_000_000, false)).toBe(true);
    expect(canSimulate(ordinary, '', 64_000_000_000, false)).toBe(false);
    expect(canSimulate(ordinary, '', 0, true)).toBe(false);
  });
  it('requires risky confirmation and never bypasses a hard block', () => {
    expect(canSimulate(risky, '', 0, false)).toBe(false);
    expect(canSimulate(risky, risky.challenge!, 0, false)).toBe(true);
    expect(canSimulate({ ...risky, verdict: { ...risky.verdict, state: 'blocked' } }, risky.challenge!, 0, false)).toBe(false);
    expect(canSimulate({ ...ordinary, verdict: { ...ordinary.verdict, hard_blocks: [{ code: 'root', message: 'System disk' }] } }, '', 0, false)).toBe(false);
    expect(canSimulate({ ...risky, challenge: '' }, '', 0, false)).toBe(false);
  });
  it('ignores case only, and cannot reuse another disk challenge', () => {
    expect(confirmationMatches(risky, 'wipe 1tb-external-7f3k')).toBe(true);
    expect(confirmationMatches(risky, ' WIPE 1TB-EXTERNAL-7F3K')).toBe(false);
    expect(confirmationMatches(risky, 'WIPE 1TB-EXTERNAL-7F3K\n')).toBe(false);
    expect(confirmationMatches(risky, 'WIPE 64GB-USB-1234')).toBe(false);
    expect(confirmationMatches({ ...risky, challenge: 'WIPE 1TB-STRASSE-7F3K' }, 'wipe 1tb-straße-7f3k')).toBe(false);
  });
});
describe('local image intake', () => {
  it('accepts intended formats while rejecting empty, huge and unrelated files', () => {
    expect(fileProblem({ name: 'Installer.ISO', size: 8_000 })).toBeNull();
    expect(fileProblem({ name: 'archive.iso.exe', size: 8_000 })).toMatch(/format/i);
    expect(fileProblem({ name: 'empty.iso', size: 0 })).toMatch(/empty/i);
    expect(fileProblem({ name: 'large.iso', size: 513 * 1024 * 1024 })).toMatch(/512 MiB/);
  });
  it('never renders filenames as HTML or exposes path components', () => {
    expect(safeFileName('../../folder/my\u0000image.iso')).toBe('myimage.iso');
    expect(safeFileName('C:\\media\\installer.iso')).toBe('installer.iso');
    expect(escapeHTML('<img src=x onerror="alert(1)">')).toBe('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  });
});

describe('relative image destinations', () => {
  it('preserves nested paths with spaces and unicode', () => {
    expect(relativeImagePath('Mac/MacOS.img')).toBe('Mac/MacOS.img');
    expect(relativeImagePath('Windows\\Install Media\\Win11.iso')).toBe('Windows/Install Media/Win11.iso');
    expect(relativeImagePath('Linux/日本語 rescue.iso')).toBe('Linux/日本語 rescue.iso');
    expect(browserRelativePath('My USB/Windows/Win11.iso', 'Win11.iso')).toBe('Windows/Win11.iso');
    expect(browserRelativePath('', 'single.iso')).toBe('single.iso');
  });
  it('rejects absolute, traversal and ambiguous paths rather than flattening them', () => {
    for (const path of ['../file.iso', 'Mac/../../file.iso', '/tmp/file.iso', 'C:\\media\\file.iso', '\\\\server\\share\\file.iso', 'Mac//file.iso', 'Mac/./file.iso', 'Mac/\u0000file.iso', '']) {
      expect(() => relativeImagePath(path)).toThrow();
    }
  });
  it('keeps equal basenames in different folders while detecting destination collisions', () => {
    expect(destinationKey({ name: 'boot.iso', relativePath: 'Mac/boot.iso' })).not.toBe(destinationKey({ name: 'boot.iso', relativePath: 'Windows/boot.iso' }));
    expect(destinationKey({ name: 'boot.iso', relativePath: 'Mac/boot.iso' })).toBe(destinationKey({ name: 'BOOT.ISO', relativePath: 'MAC/BOOT.ISO' }));
    expect(destinationKey({ name: 'boot.iso' })).toBe('boot.iso');
  });
});
