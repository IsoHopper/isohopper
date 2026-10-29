// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { buildActivityReceipt, filterLibrary, libraryFolders } from './presentation';
import type { MediaImage } from './state';

const entry = (relativePath: string, status: MediaImage['status'] = 'hashed'): MediaImage => ({ id: relativePath, name: relativePath.split('/').at(-1)!, relativePath, status, sample: status === 'sample', size: 3 });
const images = [entry('Linux/live/boot.iso'), entry('Linux/rescue.iso', 'error'), entry('Windows/boot.iso', 'hashing'), entry('LinuxTools/tool.img'), entry('root.iso', 'sample')];

describe('library presentation', () => {
  it('counts nested directories without conflating common prefixes', () => {
    expect(libraryFolders(images)).toEqual([{ path: 'Linux', count: 2 }, { path: 'Linux/live', count: 1 }, { path: 'LinuxTools', count: 1 }, { path: 'Windows', count: 1 }]);
  });
  it('intersects folder, status and case-insensitive filename search', () => {
    expect(filterLibrary(images, { folder: 'Linux', status: 'hashed', query: 'BOOT' })).toEqual([images[0]]);
    expect(filterLibrary(images, { folder: 'Linux', status: 'all', query: '' })).toEqual(images.slice(0, 2));
    expect(filterLibrary(images, { folder: 'Linux/live', status: 'error', query: '' })).toEqual([]);
  });
  it('does not label a sample as a hashed image', () => {
    expect(filterLibrary(images, { folder: '', status: 'sample', query: '' })).toEqual([images[4]]);
    expect(filterLibrary(images, { folder: '', status: 'hashed', query: '' })).toHaveLength(2);
  });
});

describe('activity receipt', () => {
  it('uses one explicit payload shape for preview and download, retaining null native states', () => {
    const events = [{ time: '2026-10-29T12:00:00Z', title: 'Session started', detail: 'Mock runtime', kind: 'info' as const }];
    expect(buildActivityReceipt({ bridgeMode: 'demo', events }, '2026-10-29T12:00:01Z')).toEqual({ experimental: true, exported_at: '2026-10-29T12:00:01Z', bridge_mode: 'demo', runtime_capabilities: null, preparation_snapshot: null, engine_download_snapshot: null, events });
  });
});
