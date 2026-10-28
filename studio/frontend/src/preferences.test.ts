// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import * as preferences from './preferences';
import * as preparation from './preparation';
const target = (selection_token: string, overrides: Record<string, unknown> = {}) => ({ selection_token, display_id: `disk-${selection_token}`, disk: { number: 7, friendly_name: 'Thumb drive', serial_number: `serial-${selection_token}`, size: 64 * 1024 ** 3, bus_type: 7, logical_sector_size: 512, physical_sector_size: 512, is_boot: false, is_system: false, is_read_only: false, is_offline: false, is_clustered: false, ...overrides } });

describe('saved Studio preferences', () => {
  it('restores known settings and strips native capabilities, paths and confirmation text', () => {
    expect(preferences.parsePreferences).toBeTypeOf('function');
    const result = preferences.parsePreferences(JSON.stringify({ version: 1, options: { netboot: false, timeout: 45, power: { shutdown: false } }, configFormat: 'toml', customConfig: '# My config', showLargeDrives: true, targetHint: { serial: 'USB123', size: 64 * 1024 ** 3, bus: 7 }, archive_id: 'stale', source_id: 'stale', preparationPhrase: 'WIPE USB123', paths: ['C:\\private.iso'] }));
    expect(result).toMatchObject({ options: { netboot: false, timeout: 45, memtest: true, power: { reboot: true, shutdown: false } }, configFormat: 'toml', customConfig: '# My config', showLargeDrives: true, targetHint: { serial: 'USB123', size: 64 * 1024 ** 3, bus: 7 } });
    expect(Object.keys(result).sort()).toEqual(['configFormat', 'customConfig', 'options', 'showLargeDrives', 'targetHint', 'version']);
  });
  it('discards malformed, out-of-range and incompatible preferences', () => {
    expect(preferences.parsePreferences).toBeTypeOf('function');
    for (const raw of [null, 'not json', '{"version":2,"showLargeDrives":true}', '[1,2]']) expect(preferences.parsePreferences(raw)).toMatchObject({ showLargeDrives: false, configFormat: 'yaml', options: { timeout: 10, theme: 'midnight', policy: 'enforce' } });
    const result = preferences.parsePreferences(JSON.stringify({ version: 1, options: { netboot: 'false', timeout: 301, theme: '<script>', policy: 'unsafe' }, configFormat: 'html', customConfig: 'x'.repeat(131073), showLargeDrives: 'true', targetHint: { serial: '', size: -1, bus: 17 } }));
    expect(result).toMatchObject({ showLargeDrives: false, configFormat: 'yaml', options: { netboot: true, timeout: 10, theme: 'midnight', policy: 'enforce' } });
    expect(result.targetHint).toBeUndefined();
    expect(result.customConfig).toBeUndefined();
  });
});

describe('conservative target defaults', () => {
  it('selects a single small USB or SD, preferring the exact IsoHopper name without authorizing writes', () => {
    expect(preparation.defaultPreparationTarget).toBeTypeOf('function');
    expect(preparation.defaultPreparationTarget([target('a')], '')).toBe('a');
    expect(preparation.defaultPreparationTarget([target('a'), target('b', { friendly_name: 'IsoHopper', bus_type: 12 })], '')).toBe('b');
    expect(preparation.defaultPreparationTarget([target('a'), { ...target('b'), volume_labels: ['Data', 'IsoHopper'] }], '')).toBe('b');
    expect(preparation.defaultPreparationTarget([{ ...target('a'), volume_labels: ['IsoHopper'] }, target('b', { friendly_name: 'IsoHopper' })], '')).toBe('');
    expect(preparation.defaultPreparationTarget([target('a'), target('b')], '')).toBe('');
    expect(preparation.defaultPreparationTarget([target('a', { friendly_name: 'IsoHopper' }), target('b', { friendly_name: 'isohopper' })], '')).toBe('');
  });
  it('never automatically selects internal, large, unknown or flagged media', () => {
    expect(preparation.defaultPreparationTarget).toBeTypeOf('function');
    for (const overrides of [{ bus_type: 17 }, { size: 257 * 1024 ** 3 }, { size: null }, ...['is_boot', 'is_system', 'is_read_only', 'is_offline', 'is_clustered'].flatMap(key => [{ [key]: true }, { [key]: null }, { [key]: undefined }])]) expect(preparation.defaultPreparationTarget([target('a', overrides)], '')).toBe('');
  });
  it('preserves explicit choice and restores only a unique serial/size/bus hint against fresh tokens', () => {
    expect(preparation.defaultPreparationTarget).toBeTypeOf('function');
    const list = [target('a'), target('new', { serial_number: 'SERIAL', friendly_name: 'IsoHopper' })];
    expect(preparation.defaultPreparationTarget(list, 'a')).toBe('a');
    expect(preparation.defaultPreparationTarget(list, '', { serial: 'SERIAL', size: 64 * 1024 ** 3, bus: 7 })).toBe('new');
    expect(preparation.defaultPreparationTarget(list, '', { serial: 'removed', size: 64 * 1024 ** 3, bus: 7 })).toBe('');
    expect(preparation.defaultPreparationTarget([...list, target('duplicate', { serial_number: 'SERIAL' })], '', { serial: 'SERIAL', size: 64 * 1024 ** 3, bus: 7 })).toBe('');
  });
  it('hides large candidates by default while retaining an explicit current choice', () => {
    expect(preparation.visiblePreparationTargets).toBeTypeOf('function');
    const list = [target('small'), target('large', { size: 1024 ** 4 }), target('unknown', { size: null })];
    expect(preparation.visiblePreparationTargets(list, false, '').map(t => t.selection_token)).toEqual(['small', 'unknown']);
    expect(preparation.visiblePreparationTargets(list, true, '').map(t => t.selection_token)).toEqual(['small', 'large', 'unknown']);
    expect(preparation.visiblePreparationTargets(list, false, 'large').map(t => t.selection_token)).toEqual(['small', 'large', 'unknown']);
  });
});
