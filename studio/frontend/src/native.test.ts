// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { createNativeBridge, nativeImageForDisplay, nativeMediaImage, type NativePickedImage } from './native';
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
  it('keeps the backend source ID separate from the row ID and filename', () => {
    const source_id = `src_${'a'.repeat(64)}`;
    const image = nativeMediaImage({ ...record, source_id }, 'local-row');
    expect(image.id).toBe('local-row');
    expect(image.sourceId).toBe(source_id);
    expect(image.name).toBe('installer.iso');
  });
  it('releases only the supplied opaque source IDs', async () => {
    const sourceId = `src_${'b'.repeat(64)}`;
    const calls: unknown[] = [];
    const bridge = createNativeBridge(async <T>(command: string, args?: Record<string, unknown>) => {
      calls.push({ command, args }); return null as T;
    });
    await bridge.ReleaseSources!([sourceId]);
    expect(calls).toEqual([{ command: 'release_sources', args: { ids: [sourceId] } }]);
  });
  it('lists retained native sources without accepting filesystem paths', async () => {
    const calls: unknown[] = [];
    const retained = { ...record, source_id: `src_${'a'.repeat(64)}` };
    const bridge = createNativeBridge(async <T>(command: string, args?: Record<string, unknown>) => {
      calls.push({ command, args }); return [retained] as T;
    });
    expect(await bridge.ListSources!()).toEqual([retained]);
    expect(calls).toEqual([{ command: 'list_sources', args: undefined }]);
  });
  it('keeps a releasable error row when native metadata cannot be displayed', () => {
    const source_id = `src_${'e'.repeat(64)}`;
    const image = nativeImageForDisplay({ ...record, source_id, relative_path: '../outside.iso' }, 'error-row');
    expect(image).toMatchObject({ id: 'error-row', sourceId: source_id, status: 'error', origin: 'native' });
    expect(image.relativePath).toBeUndefined();
    expect(image.name).toBe('installer.iso');
    const invalidId = nativeImageForDisplay({ ...record, source_id: 17 } as unknown as NativePickedImage, 'invalid-id');
    expect(invalidId.status).toBe('error');
    expect(invalidId.sourceId).toBeUndefined();
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
