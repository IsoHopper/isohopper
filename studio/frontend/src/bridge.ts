// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import type { DiskRecord, DiskPlan } from './state';
import { createNativeBridge, type NativeBridge, type NativeInvoke } from './native';
declare global { interface Window { __TAURI__?: { core?: { invoke: NativeInvoke } } } }
const invoke = window.__TAURI__?.core?.invoke;
const native = invoke ? createNativeBridge(invoke) : undefined;
export const bridgeMode = native ? 'Native file I/O · demo hardware inventory' : 'Browser file I/O · demo hardware inventory';
// These records are deliberately synthetic. No browser API enumerates physical disks.
// The native core remains the authoritative guard when a native bridge is present.
const mockDisks: DiskRecord[] = [
  { disk: { id: 'usb-64gb', serial: 'USB64-ABCD', model: 'USB flash drive 64 GB', bus: 'usb', size_bytes: 64e9, logical_sector_size: 512, physical_sector_size: 4096 }, verdict: { state: 'ok', hard_blocks: [], risks: [] } },
  { disk: { id: 'usb-nvme-1tb', serial: 'NVME1T-EF12', model: 'USB NVMe bridge 1 TB', bus: 'usb', size_bytes: 1e12, logical_sector_size: 512, physical_sector_size: 4096, nvme: true }, verdict: { state: 'confirm', hard_blocks: [], risks: [
    { code: 'nvme', message: 'The disk uses NVMe storage.' },
    { code: 'large_capacity', message: 'The disk exceeds the configured capacity warning threshold.' },
    { code: 'existing_data', message: 'The disk contains existing data.' }
  ], challenge: 'WIPE 1TB-USB-NVME-BRIDGE-1-TB-EF12' } },
  { disk: { id: 'internal-system', serial: 'INTERNAL-3456', model: 'Internal system disk', bus: 'nvme', size_bytes: 512e9, logical_sector_size: 512, physical_sector_size: 4096 }, verdict: { state: 'blocked', hard_blocks: [
    { code: 'not_external', message: 'The disk is not confirmed external.' },
    { code: 'unsupported_bus', message: 'Only confirmed USB and SD transport is permitted.' },
    { code: 'system_disk', message: 'The disk contains the running system.' },
    { code: 'system_mount', message: 'The disk backs a mounted system volume.' },
    { code: 'encryption_in_use', message: 'The disk participates in active encryption.' },
    { code: 'container_member', message: 'The disk belongs to a storage container.' }
  ], risks: [] } },
  { disk: { id: 'sd-32gb', serial: 'SD32-7890', model: 'SD card 32 GB', bus: 'sd', size_bytes: 32e9, logical_sector_size: 512, physical_sector_size: 512 }, verdict: { state: 'ok', hard_blocks: [], risks: [] } },
  { disk: { id: 'missing-serial', serial: '', model: 'USB bridge without serial', bus: 'usb', size_bytes: 64e9, logical_sector_size: 512, physical_sector_size: 4096 }, verdict: { state: 'blocked', hard_blocks: [{ code: 'identity_missing', message: 'A stable disk identifier and nonempty serial are required.' }], risks: [] } }
];
export const bridge: NativeBridge = native || {
  async ListDisks() { return structuredClone(mockDisks); },
  async PlanDisk(id) {
    const record = mockDisks.find(record => record.disk.id === id);
    if (!record || record.verdict.state === 'blocked') throw new Error('Target is blocked. Choose an external fixture device.');
    const sector = record.disk.logical_sector_size;
    const alignedEnd = Math.floor((record.disk.size_bytes / sector - 34) / 2048) * 2048;
    return { size_bytes: record.disk.size_bytes, logical_sector_size: sector, partitions: [
      { name: 'ISOHOPPER', start_lba: 2048, end_lba: alignedEnd - 262145 },
      { name: 'ISOHOPPER-A', start_lba: alignedEnd - 262144, end_lba: alignedEnd - 131073 },
      { name: 'ISOHOPPER-B', start_lba: alignedEnd - 131072, end_lba: alignedEnd - 1 }
    ] };
  },
  async CheckConfig() { return { valid: false, error: 'Native schema validation is available in the desktop app. This browser preview can edit and export configuration.' }; }
};
