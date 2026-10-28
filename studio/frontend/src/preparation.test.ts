// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { preparationSnapshot, canConfirmPreparation, type PreparationSnapshot } from './preparation';
const snapshot: PreparationSnapshot = { job_id: 'a'.repeat(64), phase: 'await_confirmation', message: 'Ready', active: true, cancel_requested: false, completed_bytes: 0, total_bytes: 100, bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sources_released: true, source_manifest: [{ relative_path: 'Windows/boot.iso', bytes: 3, sha256: 'd'.repeat(64) }], target: { device_number: 7, serial: 'Usb-AbC', device_id: null, bus_type: 7, size_bytes: 100, logical_sector_size: 512, physical_sector_size: 512 }, image_sha256: 'b'.repeat(64), description_digest: 'c'.repeat(64), challenge: 'WIPE Usb-AbC' };
describe('native preparation boundary', () => {
  it('requires exact case, active sealed state and the independent physical capability', () => {
    expect(canConfirmPreparation(snapshot, 'WIPE Usb-AbC', false)).toBe(false);
    expect(canConfirmPreparation(snapshot, 'WIPE USB-ABC', true)).toBe(false);
    expect(canConfirmPreparation(snapshot, 'WIPE Usb-AbC', true)).toBe(true);
    expect(canConfirmPreparation({ ...snapshot, sources_released: false }, snapshot.challenge!, true)).toBe(false);
    expect(canConfirmPreparation({ ...snapshot, cancel_requested: true }, snapshot.challenge!, true)).toBe(false);
  });
  it('preserves technical fields and rejects invalid counters or hashes', () => {
    expect(preparationSnapshot(snapshot)).toEqual(snapshot);
    expect(() => preparationSnapshot({ ...snapshot, bytes_verified: -1 })).toThrow();
    expect(() => preparationSnapshot({ ...snapshot, image_sha256: 'bad' })).toThrow();
    expect(() => preparationSnapshot({ ...snapshot, active: 'true' })).toThrow();
  });
  it('requires bounded relative metadata without exposing source capabilities', () => {
    for (const source_manifest of [undefined, [{ relative_path: '/private/source.iso', bytes: 3, sha256: 'd'.repeat(64) }], [{ ...snapshot.source_manifest[0], source_id: 'stale-capability' }], [{ relative_path: 'Windows/boot.iso', bytes: -1, sha256: 'd'.repeat(64) }], [{ relative_path: 'Windows/boot.iso', bytes: 3, sha256: 'bad' }], Array(129).fill(snapshot.source_manifest[0])]) {
      expect(() => preparationSnapshot({ ...snapshot, source_manifest })).toThrow();
    }
    expect(preparationSnapshot(snapshot).source_manifest).toEqual(snapshot.source_manifest);
  });

});

describe('empty media preparation', () => {
  it('permits explicit confirmation of a sealed empty image while retaining source-release and exact challenge gates', () => {
    const empty = { ...snapshot, source_manifest: [] };
    expect(canConfirmPreparation(empty, empty.challenge!, true)).toBe(true);
    expect(canConfirmPreparation({ ...empty, sources_released: false }, empty.challenge!, true)).toBe(false);
    expect(canConfirmPreparation(empty, 'WIPE OTHER', true)).toBe(false);
  });
});
