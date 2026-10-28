// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { NativeInvoke } from './native';

async function loadBridge(search = '', invoke?: NativeInvoke, nativeHost = !!invoke) {
  vi.resetModules();
  vi.stubGlobal('window', { location: { search }, ...(nativeHost ? { __TAURI__: invoke ? { core: { invoke } } : {} } : {}) });
  return import('./bridge');
}
afterEach(() => vi.unstubAllGlobals());

describe('runtime boundary', () => {
  it('does not replace an absent desktop runtime with fixture devices', async () => {
    const { bridge, initialImages } = await loadBridge();
    expect(initialImages).toEqual([]);
    await expect(bridge.ListDisks()).rejects.toThrow('Native desktop runtime unavailable');
  });
  it('requires explicit browser demo selection', async () => {
    const { bridge, initialImages } = await loadBridge('?demo=1');
    expect(initialImages).toHaveLength(2);
    expect(initialImages.every(image => image.sample)).toBe(true);
    expect((await bridge.ListDisks()).map(record => record.disk.id)).toContain('usb-64gb');
    const { bridge: otherValue } = await loadBridge('?demo=false');
    await expect(otherValue.ListDisks()).rejects.toThrow('Native desktop runtime unavailable');
  });
  it('does not use demo fixtures when the native host exists without its invoke bridge', async () => {
    const { bridge } = await loadBridge('?demo=1', undefined, true);
    await expect(bridge.ListDisks()).rejects.toThrow('Native desktop runtime unavailable');
  });
  it('uses actual inspection records in native mode even with the demo query present', async () => {
    const calls: string[] = [];
    const actual = { id: '\\\\.\\PhysicalDrive7', serial: 'ACTUAL-SERIAL', model: 'Observed USB', size_bytes: 64e9, logical_sector_size: 512, bus: 'usb', safety_checks_complete: false };
    const { bridge, initialImages } = await loadBridge('?demo=1', async <T>(command: string) => {
      calls.push(command);
      if (command !== 'inspect_devices') throw new Error(`Unexpected command ${command}`);
      return { source: 'windows-storage', disks: [actual], warnings: [{ disk_id: actual.id, code: 'safety_incomplete', message: 'Checks incomplete.' }] } as T;
    });
    const listed = await bridge.ListDisks();
    expect(initialImages).toEqual([]);
    expect(listed.map(record => record.disk)).toEqual([actual]);
    expect(listed[0].verdict.state).toBe('blocked');
    expect(listed[0].verdict.hard_blocks).toContainEqual({ code: 'preparation_unavailable', message: expect.any(String) });
    expect(calls).toEqual(['inspect_devices']);
  });
  it('never substitutes fixture data after an inventory failure', async () => {
    const { bridge } = await loadBridge('?demo=1', async () => { throw new Error('Native inventory failed'); });
    await expect(bridge.ListDisks()).rejects.toThrow('Native inventory failed');
  });
  it('rejects native planning before any preparation command can run', async () => {
    const calls: string[] = [];
    const { bridge } = await loadBridge('', async <T>(command: string) => { calls.push(command); return {} as T; });
    await expect(bridge.PlanDisk('usb-64gb')).rejects.toThrow('Physical preparation is unavailable');
    expect(calls).toEqual([]);
  });
});
