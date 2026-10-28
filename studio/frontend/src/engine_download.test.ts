// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { createNativeBridge } from './native';

const snapshot = { job_id: 'a'.repeat(64), phase: 'downloading', active: true, cancel_requested: false, completed_bytes: 4096, total_bytes: 20320548, expected_sha256: 'd86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54', version: '1.1.18', cache_hit: false, message: 'Downloading official archive.' };

describe('native engine download boundary', () => {
  it('starts only the pinned native download, reads status and cancels by job ID', async () => {
    const calls: unknown[] = [];
    const bridge = createNativeBridge(async <T>(command: string, args?: Record<string, unknown>) => { calls.push({ command, args }); return (command === 'cancel_engine_download' ? null : snapshot) as T; });
    expect(bridge.StartEngineDownload).toBeTypeOf('function');
    expect(await bridge.StartEngineDownload!()).toEqual(snapshot);
    expect(await bridge.EngineDownloadStatus!()).toEqual(snapshot);
    await bridge.CancelEngineDownload!(snapshot.job_id);
    expect(calls).toEqual([{ command: 'start_engine_download', args: undefined }, { command: 'engine_download_status', args: undefined }, { command: 'cancel_engine_download', args: { jobId: 'a'.repeat(64) } }]);
  });
  it('accepts no previous job and all coherent phases', async () => {
    const bridge = createNativeBridge(async <T>() => null as T);
    expect(bridge.EngineDownloadStatus).toBeTypeOf('function');
    expect(await bridge.EngineDownloadStatus!()).toBeNull();
    for (const phase of ['checking_cache', 'downloading', 'verifying', 'ready', 'failed', 'cancelled']) {
      const value = { ...snapshot, phase, active: ['checking_cache', 'downloading', 'verifying'].includes(phase), completed_bytes: phase === 'ready' ? 20320548 : 4096, cancel_requested: phase === 'cancelled' };
      expect(await createNativeBridge(async <T>() => value as T).StartEngineDownload!()).toEqual(value);
    }
  });
  it('rejects unpinned, malformed, inconsistent and capability-bearing snapshots', async () => {
    const invalid = [null, {}, { ...snapshot, job_id: 'A'.repeat(64) }, { ...snapshot, phase: 'installed' }, { ...snapshot, phase: 'ready', active: true }, { ...snapshot, phase: 'ready', active: false }, { ...snapshot, phase: 'ready', active: false, completed_bytes: 20320548, cancel_requested: true }, { ...snapshot, phase: 'failed', active: true }, { ...snapshot, active: false }, { ...snapshot, phase: 'cancelled', active: false, cancel_requested: false }, { ...snapshot, completed_bytes: -1 }, { ...snapshot, completed_bytes: 20320549 }, { ...snapshot, completed_bytes: 0.5 }, { ...snapshot, total_bytes: 2048 }, { ...snapshot, expected_sha256: 'b'.repeat(64) }, { ...snapshot, version: 'latest' }, { ...snapshot, cancel_requested: 'false' }, { ...snapshot, cache_hit: 'true' }, { ...snapshot, message: 'x'.repeat(8193) }, { ...snapshot, archive_id: 'stale-token' }];
    for (const value of invalid) {
      const bridge = createNativeBridge(async <T>() => value as T);
      expect(bridge.StartEngineDownload).toBeTypeOf('function');
      await expect(bridge.StartEngineDownload!()).rejects.toThrow('Invalid native engine download response');
      if (value !== null) await expect(bridge.EngineDownloadStatus!()).rejects.toThrow('Invalid native engine download response');
    }
  });
  it('treats download support as an optional boolean capability', async () => {
    const capabilities = { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, physical_preparation: false, preparation_unavailable_reason: '' };
    for (const engine_download of [true, false, undefined]) expect((await createNativeBridge(async <T>() => ({ ...capabilities, engine_download }) as T).Capabilities()).engine_download).toBe(engine_download);
    await expect(createNativeBridge(async <T>() => ({ ...capabilities, engine_download: 'true' }) as T).Capabilities()).rejects.toThrow('capabilities');
  });
});
