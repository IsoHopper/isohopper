// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
export interface Reason { code: string; message: string }
export interface Disk { id: string; serial: string; model: string; bus: string; size_bytes: number; logical_sector_size: number; [key: string]: unknown }
export interface DiskRecord { disk: Disk; verdict: { state: string; hard_blocks: Reason[] | null; risks: Reason[] | null; challenge?: string }; challenge?: string }
export interface Partition { name: string; start_lba: number; end_lba: number }
export interface DiskPlan { size_bytes: number; logical_sector_size: number; partitions: Partition[] }
export interface MediaImage { id: string; name: string; size: number; sample: boolean; sourceId?: string; relativePath?: string; origin?: 'native' | 'browser'; hash?: string; status: 'sample' | 'hashing' | 'hashed' | 'error'; error?: string }
export function challengeFor(disk: DiskRecord): string { return disk.challenge || disk.verdict.challenge || ''; }
export function confirmationMatches(disk: DiskRecord, input: string): boolean {
  const challenge = challengeFor(disk);
  // ASCII folding avoids Unicode expansions such as ß matching two S characters.
  const fold = (value: string) => value.replace(/[a-z]/g, char => char.toUpperCase());
  return challenge.length > 0 && fold(challenge) === fold(input);
}
export function canSimulate(disk: DiskRecord | undefined, input: string, bytes: number, busy: boolean): boolean {
  if (!disk || busy || (disk.verdict.hard_blocks?.length ?? 0) > 0 || !['ok', 'confirm'].includes(disk.verdict.state)) return false;
  if (!Number.isFinite(bytes) || bytes < 0 || bytes > disk.disk.size_bytes - 130 * 1024 * 1024) return false;
  return disk.verdict.state === 'ok' || confirmationMatches(disk, input);
}
export function fileProblem(file: { name: string; size: number }): string | null {
  if (!/\.(iso|img|wim|vhd|vhdx|efi)$/i.test(file.name)) return 'Unsupported format. Use ISO, IMG, WIM, VHD, VHDX or EFI.';
  if (file.size <= 0) return 'This file is empty.';
  if (file.size > 512 * 1024 * 1024) return 'This preview hashes files up to 512 MiB. Streaming large images requires native file access.';
  return null;
}
export function safeFileName(name: string): string { return (name.split(/[\\/]/).pop() || 'Untitled image').replace(/[\u0000-\u001f\u007f]/g, ''); }
export function escapeHTML(value: string): string { return value.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!)); }
export function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${Number((bytes / 1e12).toFixed(1))} TB`;
  if (bytes >= 1e9) return `${Number((bytes / 1e9).toFixed(1))} GB`;
  if (bytes >= 1e6) return `${Number((bytes / 1e6).toFixed(1))} MB`;
  if (bytes >= 1e3) return `${Number((bytes / 1e3).toFixed(1))} KB`;
  return `${bytes} B`;
}

export function relativeImagePath(path: string): string {
  if (!path || /^[\\/]/.test(path) || /^[a-z]:/i.test(path) || /[\u0000-\u001f\u007f]/.test(path)) throw new Error('Image path must be relative and contain no control characters.');
  const normalized = path.replace(/\\/g, '/');
  const parts = normalized.split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) throw new Error('Image path contains an empty, current-directory or parent-directory segment.');
  return normalized;
}
export function browserRelativePath(relative: string, name: string): string {
  if (!relative) return relativeImagePath(name);
  const normalized = relativeImagePath(relative);
  const parts = normalized.split('/');
  return parts.length > 1 ? parts.slice(1).join('/') : normalized;
}
export function destinationKey(image: { name: string; relativePath?: string }): string {
  return relativeImagePath(image.relativePath || image.name).normalize('NFC').toLowerCase();
}
