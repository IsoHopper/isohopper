// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { mergeNativeImages, removeMediaImages } from './image_lifecycle';
import type { MediaImage } from './state';
const native: MediaImage = { id: 'row-native', sourceId: `src_${'a'.repeat(64)}`, name: 'boot.iso', relativePath: 'Windows/boot.iso', size: 3, sample: false, origin: 'native', status: 'hashed' };
const browser: MediaImage = { id: 'row-browser', name: 'browser.iso', size: 3, sample: false, origin: 'browser', status: 'hashed' };

describe('native source lifecycle', () => {
  it('releases the opaque source ID before removing its row', async () => {
    const calls: string[][] = [];
    const remaining = await removeMediaImages([native, browser], new Set([native.id]), async ids => { calls.push(ids); });
    expect(calls).toEqual([[native.sourceId]]);
    expect(remaining).toEqual([browser]);
  });
  it('preserves all rows when batch release rejects a leased source', async () => {
    const images = [native, browser];
    await expect(removeMediaImages(images, new Set(images.map(image => image.id)), async () => { throw new Error('Source is leased'); })).rejects.toThrow('Source is leased');
    expect(images).toEqual([native, browser]);
  });
  it('refuses to discard a retained source if its native release bridge is unavailable', async () => {
    await expect(removeMediaImages([native], new Set([native.id]))).rejects.toThrow('release');
  });
  it('clears browser and sample rows without native operations', async () => {
    const sample: MediaImage = { ...browser, id: 'sample', sample: true, status: 'sample' };
    const calls: string[][] = [];
    expect(await removeMediaImages([browser, sample], new Set([browser.id, sample.id]), async ids => { calls.push(ids); })).toEqual([]);
    expect(calls).toEqual([]);
  });
  it('does not release a source still referenced by another retained row', async () => {
    const duplicate = { ...native, id: 'row-alias' };
    const calls: string[][] = [];
    expect(await removeMediaImages([native, duplicate], new Set([native.id]), async ids => { calls.push(ids); })).toEqual([duplicate]);
    expect(calls).toEqual([]);
    expect(await removeMediaImages([native, duplicate], new Set([native.id, duplicate.id]), async ids => { calls.push(ids); })).toEqual([]);
    expect(calls).toEqual([[native.sourceId]]);
  });
  it('releases a duplicate destination source while retaining different nested destinations', async () => {
    const duplicate = { ...native, id: 'duplicate', sourceId: `src_${'b'.repeat(64)}`, relativePath: 'WINDOWS/BOOT.ISO' };
    const nested = { ...native, id: 'nested', sourceId: `src_${'c'.repeat(64)}`, relativePath: 'Mac/boot.iso' };
    const calls: string[][] = [];
    const result = await mergeNativeImages([native], [duplicate, nested], async ids => { calls.push(ids); });
    expect(result.images).toEqual([native, nested]);
    expect(result.skipped).toEqual([duplicate]);
    expect(calls).toEqual([[duplicate.sourceId]]);
  });
  it('retains a visible retryable error row if releasing a duplicate source fails', async () => {
    const duplicate = { ...native, id: 'duplicate', sourceId: `src_${'b'.repeat(64)}` };
    const result = await mergeNativeImages([native], [duplicate], async () => { throw new Error('Source is leased'); });
    expect(result.images).toHaveLength(2);
    expect(result.images[1]).toMatchObject({ id: duplicate.id, sourceId: duplicate.sourceId, status: 'error' });
    expect(result.releaseError).toContain('Source is leased');
    expect(result.skipped).toEqual([]);
  });
  it('does not release a duplicate response ID still referenced in the collection', async () => {
    const calls: string[][] = [];
    const result = await mergeNativeImages([native], [{ ...native, id: 'alias' }], async ids => { calls.push(ids); });
    expect(result.images).toEqual([native]);
    expect(calls).toEqual([]);
  });
});
