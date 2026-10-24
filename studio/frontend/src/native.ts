// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { relativeImagePath, safeFileName, type DiskRecord, type DiskPlan, type MediaImage, type Disk } from './state';
export interface NativePickedImage { name: string; relative_path?: string; bytes: number; verification: { algorithm: string; digest: string; bytes: number; status: string; publisher_verified: boolean } }
export interface NativeDirectoryResult { images: NativePickedImage[]; warnings: string[] }
export interface HostInventory { source: string; disks: Disk[]; warnings: { disk_id?: string; code: string; message: string }[] }
export type NativeInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
export interface NativeBridge {
  ListDisks(): Promise<DiskRecord[]>;
  PlanDisk(id: string): Promise<DiskPlan>;
  CheckConfig(text: string, format: string): Promise<{ valid: boolean; error?: string; warnings?: string[] }>;
  PickImages?(): Promise<NativePickedImage[]>;
  PickDirectory?(): Promise<NativeDirectoryResult>;
  InspectDevices?(): Promise<HostInventory>;
}
export function createNativeBridge(invoke: NativeInvoke): NativeBridge {
  return {
    ListDisks: () => invoke('list_disks'),
    PlanDisk: id => invoke('plan_disk', { id }),
    CheckConfig: (text, format) => invoke('check_config', { text, format }),
    PickImages: () => invoke('pick_images'),
    PickDirectory: () => invoke('pick_directory'),
    InspectDevices: () => invoke('inspect_devices')
  };
}
export function nativeMediaImage(record: NativePickedImage, id: string): MediaImage {
  if (!Number.isSafeInteger(record.bytes) || record.bytes <= 0 || record.verification.bytes !== record.bytes || record.verification.algorithm !== 'sha256' || record.verification.status !== 'hash-only' || !/^[a-f0-9]{64}$/i.test(record.verification.digest)) {
    throw new Error('Native image fingerprint is incomplete or inconsistent.');
  }
  const relativePath = record.relative_path === undefined ? undefined : relativeImagePath(record.relative_path);
  return { id, ...(relativePath ? { relativePath } : {}), name: safeFileName(record.name), size: record.bytes, sample: false, origin: 'native', status: 'hashed', hash: record.verification.digest.toLowerCase() };
}
