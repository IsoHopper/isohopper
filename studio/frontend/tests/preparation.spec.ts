// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, test } from '@playwright/test';

test('native staging keeps physical writes gated and recovers its backend job after reload', async ({ page }) => {
  await page.addInitScript(() => {
    const host = window as unknown as { __TAURI__: unknown; preparationCalls: { command: string; args: unknown }[] };
    host.preparationCalls = [];
    const source = { source_id: `src_${'a'.repeat(64)}`, name: 'boot.iso', relative_path: 'Windows/boot.iso', bytes: 3, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } };
    const archive = { archive_id: `src_${'b'.repeat(64)}`, name: 'ventoy-1.1.18-linux.tar.gz', bytes: 20320548, sha256: 'd86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54', version: '1.1.18' };
    const target = { selection_token: 'c'.repeat(64), display_id: '\\\\.\\PhysicalDrive7', disk: { number: 7, friendly_name: 'Disposable USB', serial_number: 'USB-AbC', size: 8000000000, logical_sector_size: 512, physical_sector_size: 512, bus_type: 7 } };
    host.__TAURI__ = { core: { invoke: async (command: string, args: unknown) => {
      host.preparationCalls.push({ command, args });
      if (command === 'capabilities') return { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, preparation_available: true, physical_preparation: false, preparation_unavailable_reason: 'Physical writing disabled pending native validation.' };
      if (command === 'inspect_devices') return { source: 'native-test', disks: [], warnings: [] };
      if (command === 'list_sources') return sessionStorage.getItem('job') ? [] : [source];
      if (command === 'selected_engine_archive') return sessionStorage.getItem('job') ? null : archive;
      if (command === 'list_preparation_targets') return [target];
      if (command === 'preparation_status') return JSON.parse(sessionStorage.getItem('job') || 'null');
      if (command === 'start_preparation') {
        const job = { job_id: 'd'.repeat(64), phase: 'await_confirmation', message: 'Staged image ready. Physical writing is disabled in this build; cancel to clean up.', active: true, cancel_requested: false, completed_bytes: 8000000000, total_bytes: 8000000000, bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sources_released: true, target: { device_number: 7, serial: 'USB-AbC', device_id: null, bus_type: 7, size_bytes: 8000000000, logical_sector_size: 512, physical_sector_size: 512 }, image_sha256: 'e'.repeat(64), description_digest: 'f'.repeat(64), challenge: 'WIPE USB-AbC' };
        sessionStorage.setItem('job', JSON.stringify(job)); return job;
      }
      if (command === 'cancel_preparation') {
        const job = JSON.parse(sessionStorage.getItem('job')!); job.cancel_requested = true; job.active = false; job.phase = 'cancelled'; job.message = 'Staging removed; no target writes.'; sessionStorage.setItem('job', JSON.stringify(job)); return null;
      }
      throw new Error(`Unexpected command ${command}`);
    } } };
  });
  await page.goto('/');
  await page.locator('#preparation-target').selectOption('c'.repeat(64));
  await page.getByRole('button', { name: 'Build preparation image', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Write device', exact: true })).toBeDisabled();
  await expect(page.locator('#preparation-phrase')).toBeDisabled();
  await expect(page.locator('.preparation-status')).toContainText('e'.repeat(64));
  const start = await page.evaluate(() => (window as unknown as { preparationCalls: { command: string; args: unknown }[] }).preparationCalls.find(call => call.command === 'start_preparation'));
  expect(start?.args).toEqual({ targetToken: 'c'.repeat(64), sourceIds: [`src_${'a'.repeat(64)}`], archiveToken: `src_${'b'.repeat(64)}` });
  await page.reload();
  await expect(page.locator('.preparation-status')).toContainText('d'.repeat(64));
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeDisabled();
  await expect(page.locator('.image-row')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Cancel preparation', exact: true }).click();
  await expect(page.locator('.preparation-status')).toContainText('Staging removed; no target writes.');
  expect(await page.evaluate(() => (window as unknown as { preparationCalls: { command: string }[] }).preparationCalls.some(call => call.command === 'confirm_preparation'))).toBe(false);
});
