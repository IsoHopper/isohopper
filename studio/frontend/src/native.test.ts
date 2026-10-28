// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { createNativeBridge, nativeMediaImage, type NativePickedImage } from './native';
const record: NativePickedImage = { name: '/private/media/installer.iso', bytes: 6_000_000_000, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 6_000_000_000, status: 'hash-only', publisher_verified: false } };
describe('native image intake', () => {
  it('accepts a streamed large image without exposing a full path or claiming publisher trust', () => {
    expect(nativeMediaImage(record, 'test')).toEqual({ id: 'test', name: 'installer.iso', size: 6_000_000_000, sample: false, origin: 'native', status: 'hashed', hash: 'a'.repeat(64) });
  });
  it('preserves relative hierarchy from the native directory picker', () => {
    const image = nativeMediaImage({ ...record, name: 'boot.iso', relative_path: 'Windows/Install Media/boot.iso' }, 'nested');
    expect(image.name).toBe('boot.iso');
    expect(image.relativePath).toBe('Windows/Install Media/boot.iso');
    expect(() => nativeMediaImage({ ...record, relative_path: '../outside.iso' }, 'bad')).toThrow();
  });
  it('invokes the native directory picker without exposing directory paths as arguments', async () => {
    const calls: string[] = [];
    const bridge = createNativeBridge(async <T>(command: string) => { calls.push(command); return { images: [], warnings: ['Skipped symbolic link: shared'] } as T; });
    expect(await bridge.PickDirectory!()).toEqual({ images: [], warnings: ['Skipped symbolic link: shared'] });
    expect(calls).toEqual(['pick_directory']);
  });
  it('rejects inconsistent or incomplete native fingerprints', () => {
    expect(() => nativeMediaImage({ ...record, bytes: 0 }, 'test')).toThrow();
    expect(() => nativeMediaImage({ ...record, verification: { ...record.verification, digest: 'abc' } }, 'test')).toThrow();
    expect(() => nativeMediaImage({ ...record, verification: { ...record.verification, bytes: 20 } }, 'test')).toThrow();
  });
  it('passes picker cancellation through as an empty collection', async () => {
    const calls: string[] = [];
    const bridge = createNativeBridge(async <T>(command: string) => { calls.push(command); return [] as T; });
    expect(await bridge.PickImages!()).toEqual([]);
    expect(calls).toEqual(['pick_images']);
  });
  it('keeps config command arguments compatible with the native boundary', async () => {
    const calls: { command: string; args: Record<string, unknown> | undefined }[] = [];
    const bridge = createNativeBridge(async <T>(command: string, args?: Record<string, unknown>) => {
      calls.push({ command, args });
      return { valid: true } as T;
    });
    expect(await bridge.CheckConfig('boot: {}', 'yaml')).toEqual({ valid: true });
    expect(calls).toEqual([
      { command: 'check_config', args: { text: 'boot: {}', format: 'yaml' } }
    ]);
  });
  it('reads native capabilities and rejects an incomplete response', async () => {
    const capabilities = { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, physical_preparation: false, preparation_unavailable_reason: 'Helper unavailable.' };
    const bridge = createNativeBridge(async <T>() => capabilities as T);
    expect(await bridge.Capabilities()).toEqual(capabilities);
    const incomplete = createNativeBridge(async <T>() => ({ mode: 'native' }) as T);
    await expect(incomplete.Capabilities()).rejects.toThrow('capabilities');
  });
  it('preserves native failures instead of substituting browser fixtures', async () => {
    const bridge = createNativeBridge(async () => { throw new Error('native picker failed'); });
    await expect(bridge.PickImages!()).rejects.toThrow('native picker failed');
  });
});
