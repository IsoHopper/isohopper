// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import type { EngineDownloadSnapshot } from './engine_download';
import type { StudioCapabilities } from './native';
import type { PreparationSnapshot } from './preparation';
import type { MediaImage } from './state';

export type LibraryStatus = 'all' | MediaImage['status'];
export interface LibraryFilters { folder: string; status: LibraryStatus; query: string }
const pathOf = (image: MediaImage) => image.relativePath || image.name;

export function libraryFolders(images: MediaImage[]): { path: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const image of images) {
    const parts = pathOf(image).split('/');
    for (let end = 1; end < parts.length; end++) {
      const path = parts.slice(0, end).join('/');
      counts.set(path, (counts.get(path) || 0) + 1);
    }
  }
  return [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([path, count]) => ({ path, count }));
}

export function filterLibrary(images: MediaImage[], filters: LibraryFilters): MediaImage[] {
  const query = filters.query.toLocaleLowerCase();
  return images.filter(image => (!filters.folder || pathOf(image).startsWith(`${filters.folder}/`))
    && (filters.status === 'all' || image.status === filters.status)
    && pathOf(image).toLocaleLowerCase().includes(query));
}

interface ActivityState {
  bridgeMode: string;
  capabilities?: StudioCapabilities;
  preparationJob?: PreparationSnapshot | null;
  engineDownloadJob?: EngineDownloadSnapshot | null;
  events: { time: string; title: string; detail: string; kind: 'info' | 'success' | 'warning' }[];
}

export function buildActivityReceipt(state: ActivityState, exportedAt: string) {
  return {
    experimental: true,
    exported_at: exportedAt,
    bridge_mode: state.bridgeMode,
    runtime_capabilities: state.capabilities ?? null,
    preparation_snapshot: state.preparationJob ?? null,
    engine_download_snapshot: state.engineDownloadJob ?? null,
    events: state.events,
  };
}
