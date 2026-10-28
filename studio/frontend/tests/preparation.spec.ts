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

test('enabled native preparation requires an exact explicit one-shot confirmation and preserves its receipt', async ({ page }) => {
  await page.addInitScript(() => {
    const host = window as unknown as {
      __TAURI__: unknown;
      preparationCalls: { command: string; args: unknown }[];
      resolveConfirmation: (() => void) | null;
      finishPreparation: boolean;
    };
    host.preparationCalls = [];
    host.resolveConfirmation = null;
    host.finishPreparation = false;
    let job = {
      job_id: '1'.repeat(64), phase: 'await_confirmation', message: 'Exact retained target ready.',
      active: true, cancel_requested: false, completed_bytes: 8000000000, total_bytes: 8000000000,
      bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sources_released: true,
      target: { device_number: 7, serial: 'USB-AbC', device_id: '2'.repeat(32), bus_type: 7, size_bytes: 8000000000, logical_sector_size: 512, physical_sector_size: 4096 },
      image_sha256: '3'.repeat(64), description_digest: '4'.repeat(64), challenge: 'WIPE USB-AbC',
    };
    host.__TAURI__ = { core: { invoke: async (command: string, args: unknown) => {
      host.preparationCalls.push({ command, args });
      if (command === 'capabilities') return { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, preparation_available: true, physical_preparation: true, preparation_unavailable_reason: '' };
      if (command === 'inspect_devices') return { source: 'native-test', disks: [], warnings: [] };
      if (command === 'list_sources' || command === 'list_preparation_targets') return [];
      if (command === 'selected_engine_archive') return null;
      if (command === 'preparation_status') {
        if (host.finishPreparation) job = { ...job, phase: 'succeeded', active: false, message: 'Mock device write and full readback verified.', bytes_written: 8000000000, bytes_verified: 8000000000, target_may_be_incomplete: false };
        return structuredClone(job);
      }
      if (command === 'confirm_preparation') {
        await new Promise<void>(resolve => { host.resolveConfirmation = resolve; });
        job = { ...job, phase: 'writing_target', message: 'Mock write in progress.', completed_bytes: 4096, bytes_written: 4096, target_may_be_incomplete: true };
        return null;
      }
      throw new Error(`Unexpected command ${command}`);
    } } };
  });
  const calls = () => page.evaluate(() => (window as unknown as { preparationCalls: { command: string; args: unknown }[] }).preparationCalls.filter(call => call.command === 'confirm_preparation'));
  await page.goto('/');
  const phrase = page.getByRole('textbox', { name: 'Exact device write challenge', exact: true });
  const write = page.getByRole('button', { name: 'Write device', exact: true });
  await expect(phrase).toBeEnabled();
  await expect(write).toBeDisabled();
  await phrase.pressSequentially('WIPE USB-ABC');
  await expect(write).toBeDisabled();
  await phrase.press('Enter');
  expect(await calls()).toEqual([]);
  await phrase.fill('');
  const prevented = await phrase.evaluate(input => {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', 'WIPE USB-AbC');
    const event = new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true });
    input.dispatchEvent(event);
    return event.defaultPrevented;
  });
  expect(prevented).toBe(true);
  await expect(phrase).toHaveValue('');
  await expect(write).toBeDisabled();
  await phrase.pressSequentially('WIPE USB-AbC');
  await expect(write).toBeEnabled();
  await phrase.press('Enter');
  expect(await calls()).toEqual([]);
  await write.click();
  const expectedCall = { command: 'confirm_preparation', args: { jobId: '1'.repeat(64), descriptionDigest: '4'.repeat(64), challenge: 'WIPE USB-AbC' } };
  await expect.poll(calls).toEqual([expectedCall]);
  // Keep the native invoke unresolved: disabled state and handler re-entry must
  // both prevent duplicate requests while its result is pending.
  await expect(write).toBeDisabled();
  await write.dispatchEvent('click');
  expect(await calls()).toEqual([expectedCall]);
  await page.evaluate(() => (window as unknown as { resolveConfirmation: () => void }).resolveConfirmation());
  const status = page.locator('.preparation-status');
  const value = (label: string) => status.locator('dl > div').filter({ has: page.locator('dt', { hasText: new RegExp(`^${label}$`) }) }).locator('dd');
  await expect(value('Phase')).toHaveText('writing_target');
  await expect(value('Target may be incomplete')).toHaveText('true');
  await page.evaluate(() => { (window as unknown as { finishPreparation: boolean }).finishPreparation = true; });
  await expect(value('Phase')).toHaveText('succeeded');
  await expect(value('Written / verified')).toHaveText('8,000,000,000 bytes / 8,000,000,000 bytes');
  await expect(value('Target may be incomplete')).toHaveText('false');
  await expect(status).toContainText('3'.repeat(64));
  await expect(status).toContainText('4'.repeat(64));
  await expect(write).toHaveCount(0);
  expect(await calls()).toEqual([expectedCall]);
  await expect(page.locator('.experimental')).toContainText('physical preparation enabled');
  await expect(page.locator('.experimental')).not.toContainText('unavailable');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Activity', exact: true }).click();
  const downloadReady = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export activity', exact: true }).click();
  const download = await downloadReady;
  const exported = JSON.parse(await (await import('node:fs/promises')).readFile((await download.path())!, 'utf8'));
  expect(exported.runtime_capabilities.physical_preparation).toBe(true);
  expect(exported.preparation_snapshot).toMatchObject({ job_id: '1'.repeat(64), phase: 'succeeded', bytes_written: 8000000000, bytes_verified: 8000000000, target_may_be_incomplete: false, image_sha256: '3'.repeat(64), description_digest: '4'.repeat(64) });
  expect(exported).not.toHaveProperty('physical_disk_writes');
});
