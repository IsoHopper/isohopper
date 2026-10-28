// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { preparationSnapshot, type EngineArchive, type PreparationTarget, type PreparationSnapshot } from './preparation';
import { relativeImagePath, safeFileName, type DiskRecord, type DiskPlan, type MediaImage, type Disk } from './state';
export interface NativePickedImage { name: string; relative_path?: string; source_id?: string; bytes: number; verification: { algorithm: string; digest: string; bytes: number; status: string; publisher_verified: boolean } }
export interface NativeDirectoryResult { images: NativePickedImage[]; warnings: string[] }
export interface HostInventory { source: string; disks: Disk[]; warnings: { disk_id?: string; code: string; message: string }[] }
export interface StudioCapabilities { mode: 'native' | 'demo'; platform: string; file_import: boolean; host_inventory: boolean; helper_probe?: boolean; preparation_available?: boolean; physical_preparation: boolean; preparation_unavailable_reason: string }
export type HelperProbe = { status: 'cancelled'; physical_preparation: false } | { status: 'connected'; protocol: 1; helper_version: string; helper_pid: number; helper_created: string; helper_sha256: string; physical_preparation: false };
export const preparationUnavailable = 'Physical preparation is unavailable. Disk preparation and OS boot integration are unfinished.';
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
  ProbeHelper?(): Promise<HelperProbe>;
  PickEngineArchive?(): Promise<EngineArchive | null>;
  SelectedEngineArchive?(): Promise<EngineArchive | null>;
  ListPreparationTargets?(): Promise<PreparationTarget[]>;
  PreparationStatus?(): Promise<PreparationSnapshot | null>;
  StartPreparation?(targetToken: string, sourceIds: string[], archiveToken: string): Promise<PreparationSnapshot>;
  ConfirmPreparation?(jobId: string, descriptionDigest: string, challenge: string): Promise<void>;
  CancelPreparation?(jobId: string): Promise<void>;
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
    ListSources: () => invoke('list_sources'),
    PickEngineArchive: () => invoke('pick_engine_archive'),
    SelectedEngineArchive: () => invoke('selected_engine_archive'),
    ListPreparationTargets: () => invoke('list_preparation_targets'),
    PreparationStatus: async () => { const result = await invoke<unknown>('preparation_status'); return result === null ? null : preparationSnapshot(result); },
    StartPreparation: async (targetToken, sourceIds, archiveToken) => preparationSnapshot(await invoke('start_preparation', { targetToken, sourceIds, archiveToken })),
    ConfirmPreparation: (jobId, descriptionDigest, challenge) => invoke('confirm_preparation', { jobId, descriptionDigest, challenge }),
    CancelPreparation: jobId => invoke('cancel_preparation', { jobId }),
    ProbeHelper: async () => {
      const value = await invoke<HelperProbe>('probe_helper');
      if (!value || value.physical_preparation !== false || (value.status !== 'cancelled' && (value.status !== 'connected' || value.protocol !== 1 || typeof value.helper_version !== 'string' || value.helper_version.length > 128 || !value.helper_version || !Number.isSafeInteger(value.helper_pid) || value.helper_pid <= 0 || typeof value.helper_created !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.helper_created) || typeof value.helper_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.helper_sha256)))) throw new Error('Native helper probe response is invalid.');
      return value;
    }
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
