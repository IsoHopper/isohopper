// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { relativeImagePath, safeFileName, type DiskRecord, type DiskPlan, type MediaImage, type Disk } from './state';
export interface NativePickedImage { name: string; relative_path?: string; source_id?: string; bytes: number; verification: { algorithm: string; digest: string; bytes: number; status: string; publisher_verified: boolean } }
export interface NativeDirectoryResult { images: NativePickedImage[]; warnings: string[] }
export interface HostInventory { source: string; disks: Disk[]; warnings: { disk_id?: string; code: string; message: string }[] }
export interface StudioCapabilities { mode: 'native' | 'demo'; platform: string; file_import: boolean; host_inventory: boolean; physical_preparation: boolean; preparation_unavailable_reason: string }
export const preparationUnavailable = 'Physical preparation is unavailable. The privileged helper is not connected.';
export type NativeInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
export interface NativeBridge {
  Capabilities(): Promise<StudioCapabilities>;
  ListDisks(): Promise<DiskRecord[]>;
  PlanDisk(id: string): Promise<DiskPlan>;
  CheckConfig(text: string, format: string): Promise<{ valid: boolean; error?: string; warnings?: string[] }>;
  PickImages?(): Promise<NativePickedImage[]>;
  PickDirectory?(): Promise<NativeDirectoryResult>;
  InspectDevices?(): Promise<HostInventory>;
  ReleaseSources?(ids: string[]): Promise<void>;
  ListSources?(): Promise<NativePickedImage[]>;
}
export function createNativeBridge(invoke: NativeInvoke): NativeBridge {
  return {
    Capabilities: async () => {
      const value = await invoke<StudioCapabilities>('capabilities');
      if (!value || value.mode !== 'native' || typeof value.platform !== 'string' || !value.platform || typeof value.file_import !== 'boolean' || typeof value.host_inventory !== 'boolean' || typeof value.physical_preparation !== 'boolean' || typeof value.preparation_unavailable_reason !== 'string') throw new Error('Native capabilities response is incomplete.');
      return value;
    },
    ListDisks: async () => inspectionRecords(await invoke<HostInventory>('inspect_devices')),
    PlanDisk: async () => { throw new Error(preparationUnavailable); },
    CheckConfig: (text, format) => invoke('check_config', { text, format }),
    PickImages: () => invoke('pick_images'),
    PickDirectory: () => invoke('pick_directory'),
    InspectDevices: () => invoke('inspect_devices'),
    ReleaseSources: ids => invoke('release_sources', { ids }),
    ListSources: () => invoke('list_sources')
  };
}
// An inspection record is never authorization to prepare a physical disk.
export function inspectionRecords(inventory: HostInventory): DiskRecord[] {
  return inventory.disks.map(disk => ({ disk, verdict: { state: 'blocked', hard_blocks: [{ code: 'preparation_unavailable', message: preparationUnavailable }], risks: [] } }));
}
export function nativeMediaImage(record: NativePickedImage, id: string): MediaImage {
  if (record.source_id !== undefined && (typeof record.source_id !== 'string' || !record.source_id)) throw new Error('Native source ID is invalid.');
  if (!Number.isSafeInteger(record.bytes) || record.bytes <= 0 || record.verification.bytes !== record.bytes || record.verification.algorithm !== 'sha256' || record.verification.status !== 'hash-only' || !/^[a-f0-9]{64}$/i.test(record.verification.digest)) {
    throw new Error('Native image fingerprint is incomplete or inconsistent.');
  }
  const relativePath = record.relative_path === undefined ? undefined : relativeImagePath(record.relative_path);
  relativeImagePath(relativePath || safeFileName(record.name));
  return { id, ...(record.source_id ? { sourceId: record.source_id } : {}), ...(relativePath ? { relativePath } : {}), name: safeFileName(record.name), size: record.bytes, sample: false, origin: 'native', status: 'hashed', hash: record.verification.digest.toLowerCase() };
}

export function nativeImageForDisplay(record: NativePickedImage, id: string): MediaImage {
  try { return nativeMediaImage(record, id); }
  catch (error) {
    // Keep a removable row even when display validation rejects import metadata.
    // Only the backend source ID is needed to release the retained handle.
    const name = typeof record?.name === 'string' ? safeFileName(record.name) : '';
    return { id, sourceId: typeof record?.source_id === 'string' ? record.source_id : undefined, name: name && name !== '.' && name !== '..' ? name : 'Rejected import', size: Number.isSafeInteger(record?.bytes) && record.bytes > 0 ? record.bytes : 0, sample: false, origin: 'native', status: 'error', error: `Native image metadata rejected: ${error instanceof Error ? error.message : String(error)} Remove this row to release its source.` };
  }
}
