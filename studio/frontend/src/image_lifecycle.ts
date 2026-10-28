// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { destinationKey, type MediaImage } from './state';
export type ReleaseSources = (ids: string[]) => Promise<void>;
export async function removeMediaImages(images: readonly MediaImage[], rowIds: ReadonlySet<string>, release?: ReleaseSources): Promise<MediaImage[]> {
  const remaining = images.filter(image => !rowIds.has(image.id));
  const retainedIds = new Set(remaining.map(image => image.sourceId));
  const ids = [...new Set(images.filter(image => rowIds.has(image.id) && image.origin === 'native' && image.sourceId && !retainedIds.has(image.sourceId)).map(image => image.sourceId!))];
  if (ids.length) {
    if (!release) throw new Error('Native source release is unavailable. Images were retained.');
    await release(ids);
  }
  return remaining;
}

export async function mergeNativeImages(existing: readonly MediaImage[], incoming: readonly MediaImage[], release?: ReleaseSources): Promise<{ images: MediaImage[]; added: MediaImage[]; skipped: MediaImage[]; releaseError?: string }> {
  const images = [...existing]; const added: MediaImage[] = []; const skipped: MediaImage[] = [];
  for (const image of incoming) {
    if (images.some(other => !other.sample && destinationKey(other) === destinationKey(image))) skipped.push(image);
    else { images.push(image); added.push(image); }
  }
  const retainedIds = new Set(images.map(image => image.sourceId));
  const cleanup = skipped.filter(image => image.sourceId && !retainedIds.has(image.sourceId));
  if (cleanup.length) {
    try {
      if (!release) throw new Error('Native source release is unavailable.');
      await release([...new Set(cleanup.map(image => image.sourceId!))]);
    } catch (error) {
      const releaseError = error instanceof Error ? error.message : String(error);
      const retry = cleanup.map(image => ({ ...image, status: 'error' as const, error: `Duplicate destination; source release failed: ${releaseError} Remove this row to retry.` }));
      return { images: [...images, ...retry], added, skipped: skipped.filter(image => !cleanup.includes(image)), releaseError };
    }
  }
  return { images, added, skipped };
}
