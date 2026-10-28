// SPDX-License-Identifier: GPL-3.0-or-later
import { relativeImagePath } from './state';
import type { TargetHint } from './preferences';
export interface EngineArchive { archive_id: string; name: string; bytes: number; sha256: string; version: string }
export interface PreparationTarget { selection_token: string; display_id: string; volume_labels?: string[] | null; disk: { number: number; friendly_name?: string | null; serial_number?: string | null; size: number | null; logical_sector_size: number | null; physical_sector_size: number | null; bus_type: number | null; [key: string]: unknown } }
export interface PreparationSource { relative_path: string; bytes: number; sha256: string }
export interface PreparationSnapshot {
  job_id: string; phase: string; message: string; active: boolean; cancel_requested: boolean;
  completed_bytes: number; total_bytes: number; bytes_written: number; bytes_verified: number;
  target_may_be_incomplete: boolean; sources_released: boolean;
  source_manifest: PreparationSource[];
  target: { device_number: number; serial: string; device_id: string | null; bus_type: number; size_bytes: number; logical_sector_size: number; physical_sector_size: number } | null;
  image_sha256: string | null; description_digest: string | null; challenge: string | null;
}
const hex = /^[a-f0-9]{64}$/;
export function preparationSnapshot(value: unknown): PreparationSnapshot {
  if (!value || typeof value !== 'object') throw new Error('Invalid native preparation response.');
  const v = value as PreparationSnapshot;
  if (typeof v.job_id !== 'string' || !hex.test(v.job_id) || typeof v.phase !== 'string' || v.phase.length > 64 || typeof v.message !== 'string' || v.message.length > 8192 ||
      ['active', 'cancel_requested', 'target_may_be_incomplete', 'sources_released'].some(k => typeof v[k as keyof PreparationSnapshot] !== 'boolean') ||
      [v.completed_bytes, v.total_bytes, v.bytes_written, v.bytes_verified].some(n => !Number.isSafeInteger(n) || n < 0) || v.completed_bytes > v.total_bytes || v.bytes_verified > v.bytes_written ||
      [v.image_sha256, v.description_digest].some(s => s !== null && (typeof s !== 'string' || !hex.test(s))) ||
      (v.challenge !== null && (typeof v.challenge !== 'string' || v.challenge.length > 4128))) throw new Error('Invalid native preparation response.');
  if (!Array.isArray(v.source_manifest) || v.source_manifest.length > 128 || v.source_manifest.some(source =>
    !source || typeof source !== 'object' || Object.keys(source).sort().join(',') !== 'bytes,relative_path,sha256' ||
    typeof source.relative_path !== 'string' || source.relative_path.length > 4096 || relativeImagePath(source.relative_path) !== source.relative_path ||
    !Number.isSafeInteger(source.bytes) || source.bytes <= 0 || typeof source.sha256 !== 'string' || !hex.test(source.sha256)
  )) throw new Error('Invalid native preparation source manifest.');
  if (v.target !== null) {
    const t = v.target;
    if (!t || typeof t.serial !== 'string' || t.serial.length > 4096 || [t.device_number, t.bus_type, t.size_bytes, t.logical_sector_size, t.physical_sector_size].some(n => !Number.isSafeInteger(n) || n < 0) || (t.device_id !== null && (typeof t.device_id !== 'string' || !/^[a-f0-9]{32}$/.test(t.device_id)))) throw new Error('Invalid native target description.');
  }
  return v;
}
export function canConfirmPreparation(job: PreparationSnapshot | null, text: string, physicalEnabled: boolean): boolean {
  return !!(physicalEnabled && job?.active && job.phase === 'await_confirmation' && job.sources_released && !job.cancel_requested && job.challenge && job.description_digest && text === job.challenge);
}
export const largeDriveBytes = 256 * 1024 ** 3;
export function visiblePreparationTargets(targets: PreparationTarget[], showLarge: boolean, current: string): PreparationTarget[] {
  return targets.filter(target => showLarge || target.selection_token === current || target.disk.size === null || target.disk.size <= largeDriveBytes);
}
function eligibleDefault(target: PreparationTarget): boolean {
  const disk = target.disk;
  return (disk.bus_type === 7 || disk.bus_type === 12) && Number.isSafeInteger(disk.size) && disk.size! > 0 && ['is_boot', 'is_system', 'is_read_only', 'is_offline', 'is_clustered'].every(key => disk[key] === false);
}
export function preparationTargetHint(target?: PreparationTarget): TargetHint | undefined {
  const disk = target?.disk;
  if (!disk || typeof disk.serial_number !== 'string' || !disk.serial_number.trim() || !Number.isSafeInteger(disk.size) || disk.size! <= 0 || (disk.bus_type !== 7 && disk.bus_type !== 12)) return;
  return { serial: disk.serial_number, size: disk.size!, bus: disk.bus_type };
}
export function defaultPreparationTarget(targets: PreparationTarget[], current: string, hint?: TargetHint): string {
  if (targets.some(target => target.selection_token === current)) return current;
  const eligible = targets.filter(eligibleDefault);
  if (hint) {
    const matching = eligible.filter(({ disk }) => disk.serial_number === hint.serial && disk.size === hint.size && disk.bus_type === hint.bus);
    return matching.length === 1 ? matching[0].selection_token : '';
  }
  const small = eligible.filter(target => target.disk.size! <= largeDriveBytes);
  const named = small.filter(target => [target.disk.friendly_name, ...(target.volume_labels || [])].some(name => name?.trim().toLowerCase() === 'isohopper'));
  return named.length === 1 ? named[0].selection_token : named.length === 0 && small.length === 1 ? small[0].selection_token : '';
}
