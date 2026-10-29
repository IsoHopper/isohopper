// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, test, type Page } from '@playwright/test';

async function installMock(page: Page, mode: 'selected' | 'download' | 'library-error' | 'empty' | 'targets-error' | 'archive-error' | 'restored' | 'preflight' = 'selected') {
  await page.addInitScript(mode => {
    const host = window as unknown as { __TAURI__: unknown; calls: { command: string; args: unknown }[]; finishDownload: () => void; finishInstall: () => void; failInstall: () => void; failLoadingAgain: () => void; advanceWritePhase: (phase: string) => void };
    host.calls = [];
    const archive = { archive_id: `src_${'b'.repeat(64)}`, name: 'ventoy-1.1.18-linux.tar.gz', bytes: 20320548, sha256: 'd86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54', version: '1.1.18' };
    let selectedArchive = archive;
    let selected = mode !== 'download';
    let failedLoading = false;
    host.failLoadingAgain = () => { failedLoading = false; };
    let download: Record<string, unknown> | null = null;
    const newJob = () => ({ job_id: 'e'.repeat(64), phase: 'await_confirmation', message: 'Mock target bound and image staged.', active: true, cancel_requested: false, completed_bytes: 8000000000, total_bytes: 8000000000, bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sources_released: true, source_manifest: [], target: { device_number: 7, serial: 'Usb-AbC', device_id: 'f'.repeat(32), bus_type: 7, size_bytes: 8000000000, logical_sector_size: 512, physical_sector_size: 4096 }, image_sha256: '1'.repeat(64), description_digest: '2'.repeat(64), challenge: 'ENABLE_WRITE' });
    let job: Record<string, unknown> | null = mode === 'restored' ? { ...newJob(), phase: 'succeeded', active: false, bytes_written: 8000000000, bytes_verified: 8000000000 } : null;
    host.finishDownload = () => { selected = true; download = { ...download, phase: 'ready', active: false, cancel_requested: false, completed_bytes: 20320548 }; };
    host.finishInstall = () => { job = { ...job, phase: 'succeeded', active: false, completed_bytes: 8000000000, bytes_written: 8000000000, bytes_verified: 8000000000, target_may_be_incomplete: false }; };
    host.advanceWritePhase = phase => { job = { ...job, phase, active: true, completed_bytes: 0, bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false }; };
    host.failInstall = () => { job = { ...job, phase: 'failed', active: false, target_may_be_incomplete: true, message: 'Mock write failed.' }; };
    host.__TAURI__ = { core: { invoke: async (command: string, args: unknown) => {
      host.calls.push({ command, args });
      if (!failedLoading && ((mode === 'targets-error' && command === 'list_preparation_targets') || (mode === 'archive-error' && command === 'selected_engine_archive'))) {
        failedLoading = true;
        throw new Error(`Mock ${command} unavailable`);
      }
      if (command === 'capabilities') return { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, preparation_available: true, physical_preparation: true, engine_download: true, preparation_unavailable_reason: '' };
      if (command === 'list_sources') {
        if (mode === 'library-error') throw new Error('Saved image unavailable');
        if (mode === 'empty') return [];
        return [{ source_id: `src_${'a'.repeat(64)}`, name: 'library.iso', bytes: 3, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } }];
      }
      if (command === 'selected_engine_archive') return selected ? selectedArchive : null;
      if (command === 'pick_engine_archive') return selectedArchive = { ...archive, name: 'renamed-verified-engine.tar.gz' };
      if (command === 'engine_download_status') return download;
      if (command === 'start_engine_download') return download = { job_id: 'd'.repeat(64), phase: 'downloading', active: true, cancel_requested: false, completed_bytes: 4096, total_bytes: 20320548, expected_sha256: archive.sha256, version: '1.1.18', cache_hit: false, message: 'Mock engine download' };
      if (command === 'cancel_engine_download') { download = { ...download, phase: 'cancelled', active: false, cancel_requested: true }; return null; }
      if (command === 'inspect_devices') return { source: 'mock', disks: [], warnings: [] };
      if (command === 'list_preparation_targets') return [{ selection_token: 'c'.repeat(64), display_id: '\\\\.\\PhysicalDrive7', volume_labels: ['ISOHopper'], disk: { number: 7, friendly_name: 'Test USB', serial_number: 'Usb-AbC', size: 8000000000, logical_sector_size: 512, physical_sector_size: 4096, bus_type: 7, is_boot: false, is_system: false, is_read_only: false, is_offline: false, is_clustered: false } }];
      if (command === 'preparation_status') return job;
      if (command === 'start_preparation') return job = newJob();
      if (command === 'confirm_preparation') { if (mode === 'preflight') { host.advanceWritePhase('checking_readiness'); return null; } job = { ...job, phase: 'writing_target', completed_bytes: 4096, bytes_written: 4096, target_may_be_incomplete: true }; return null; }
      throw new Error(`Unexpected command ${command}`);
    } } };
  }, mode);
}
const commands = (page: Page, command: string) => page.evaluate(command => (window as unknown as { calls: { command: string; args: unknown }[] }).calls.filter(call => call.command === command), command);

for (const mode of ['selected', 'library-error'] as const) {
  test(`drive-only installation ignores ${mode === 'selected' ? 'populated' : 'failed'} image library and requires exact confirmation`, async ({ page }, testInfo) => {
    await installMock(page, mode);
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Prepare drive', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add images', exact: true })).toHaveCount(0);
    await expect(page.locator('.image-row')).toHaveCount(0);
    if (mode === 'selected') { await page.evaluate(() => document.fonts.ready); await page.screenshot({ path: `../../.local/release-work/studio-redesign-choose-${testInfo.project.name}.png`, fullPage: true }); }
    await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
    await expect(page.locator('.wizard-steps [aria-current="step"]')).toContainText('Review');
    expect(await commands(page, 'start_preparation')).toEqual([{ command: 'start_preparation', args: { targetToken: 'c'.repeat(64), sourceIds: [], archiveToken: `src_${'b'.repeat(64)}` } }]);
    const install = page.getByRole('button', { name: 'Install ISOHopper', exact: true });
    await expect(install).toBeDisabled();
    await expect(page.locator('.bound-target')).toContainText('Test USB');
    await expect(page.locator('.wizard-summary')).toContainText('16,268,435,456 bytes');
    if (mode === 'selected') await page.screenshot({ path: `../../.local/release-work/studio-redesign-review-${testInfo.project.name}.png`, fullPage: true });
    await expect(page.locator('.preparation-status')).toContainText('8,000,000,000 bytes');
    await expect(page.locator('.preparation-status')).toContainText('1'.repeat(64));
    const phrase = page.getByRole('textbox', { name: 'Write confirmation' });
    await phrase.pressSequentially('ENABLE_WRITE');
    await phrase.press('Enter');
    expect(await commands(page, 'confirm_preparation')).toEqual([]);
    await install.click();
    await expect(page.locator('.wizard-steps [aria-current="step"]')).toContainText('Install');
    await expect(page.locator('.installation-phases .current')).toContainText('writing_target');
    await expect(page.locator('.installation-phases li').filter({ hasText: 'verifying_target' })).toContainText('Pending');
    if (mode === 'selected') await page.screenshot({ path: `../../.local/release-work/studio-redesign-install-${testInfo.project.name}.png`, fullPage: true });
    await page.evaluate(() => (window as unknown as { finishInstall: () => void }).finishInstall());
    await expect(page.locator('.wizard-steps [aria-current="step"]')).toContainText('Done');
    await expect(page.getByText('ISOHopper is installed', { exact: true })).toBeVisible();
    await expect(page.locator('.installation-phases .complete')).toHaveCount(6);
    await expect(page.locator('.installation-phases .current')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Prepare another drive' })).toBeVisible();
    if (mode === 'selected') await page.screenshot({ path: `../../.local/release-work/studio-redesign-done-${testInfo.project.name}.png`, fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test('explicit installation downloads a missing engine then stages once without authorizing a write', async ({ page }) => {
  await installMock(page, 'download');
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeEnabled();
  expect(await commands(page, 'start_engine_download')).toEqual([]);
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await expect(page.locator('.engine-download-status')).toContainText('4,096 bytes');
  expect(await commands(page, 'start_preparation')).toEqual([]);
  await page.evaluate(() => (window as unknown as { finishDownload: () => void }).finishDownload());
  await expect(page.getByRole('textbox', { name: 'Write confirmation' })).toBeVisible();
  expect(await commands(page, 'start_engine_download')).toHaveLength(1);
  expect(await commands(page, 'start_preparation')).toHaveLength(1);
  expect(await commands(page, 'confirm_preparation')).toEqual([]);
});

test('manual engine selection is under Advanced and shortcut hints are shown only once', async ({ page }) => {
  await installMock(page);
  await page.goto('/');
  await expect(page.locator('.engine-advanced')).not.toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: 'Choose engine archive', exact: true })).toBeHidden();
  await page.getByText('Advanced', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Choose engine archive', exact: true })).toBeVisible();
  await page.locator('nav').getByRole('button', { name: 'Launcher preview', exact: true }).click();
  for (const key of ['R', 'S', 'F']) await expect(page.locator('kbd').filter({ hasText: new RegExp(`^${key}$`) })).toHaveCount(1);
  const before = await page.evaluate(() => (window as unknown as { calls: unknown[] }).calls.length);
  await page.keyboard.press('r');
  await expect(page.locator('#toast')).toContainText('Reboot: preview only');
  expect(await page.evaluate(() => (window as unknown as { calls: unknown[] }).calls.length)).toBe(before);
});


test('cancelling an installation engine download never auto-starts staging if completion races cancellation', async ({ page }) => {
  await installMock(page, 'download');
  await page.goto('/');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await expect(page.locator('.engine-download-status')).toContainText('downloading');
  await page.getByRole('button', { name: 'Cancel download', exact: true }).click();
  await page.evaluate(() => (window as unknown as { finishDownload: () => void }).finishDownload());
  await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeEnabled();
  expect(await commands(page, 'start_preparation')).toEqual([]);
});

test('library, settings, activity and launcher remain separate honest previews', async ({ page }, testInfo) => {
  await installMock(page, 'empty');
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeEnabled();
  await page.evaluate(() => document.fonts.ready);
  for (const [name, file] of [['Image library', 'library-empty'], ['Configuration', 'configuration'], ['Activity', 'activity'], ['Launcher preview', 'launcher']]) {
    await page.locator('nav').getByRole('button', { name, exact: true }).click();
    if (name === 'Image library') await expect(page.getByRole('heading', { name: 'No images', exact: true })).toBeVisible();
    if (name === 'Configuration') await expect(page.getByText('LOCAL PREVIEW', { exact: true })).toBeVisible();
    if (name === 'Launcher preview') await expect(page.getByText(/Visual menu preview; not installed/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: `../../.local/release-work/studio-redesign-${file}-${testInfo.project.name}.png`, fullPage: true });
  }
});


for (const [mode, command] of [['targets-error', 'list_preparation_targets'], ['archive-error', 'selected_engine_archive']] as const) {
  test(`native wizard shows ${command} failure and Refresh restores installation readiness`, async ({ page }) => {
    await installMock(page, mode);
    await page.goto('/');
    const error = page.getByRole('alert').filter({ hasText: `Mock ${command} unavailable` });
    await expect(error).toBeVisible();
    await expect(error).toContainText('Refresh');
    await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeDisabled();
    expect(await commands(page, 'start_preparation')).toEqual([]);
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(error).toHaveCount(0);
    await expect(page.locator('#preparation-target')).toHaveValue('c'.repeat(64));
    await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeEnabled();
    expect(await commands(page, command)).toHaveLength(2);
    await page.evaluate(() => (window as unknown as { failLoadingAgain: () => void }).failLoadingAgain());
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(error).toBeVisible();
    await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(error).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Install ISOHopper', exact: true })).toBeEnabled();
    expect(await commands(page, 'start_preparation')).toEqual([]);
    expect(await commands(page, 'start_engine_download')).toEqual([]);
  });
}


test('copy controls preserve full values and report clipboard failures accurately', async ({ page }) => {
  await installMock(page);
  await page.addInitScript(() => {
    const host = window as unknown as { copiedValues: string[]; clipboardFails: boolean };
    host.copiedValues = []; host.clipboardFails = false;
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (value: string) => {
      if (host.clipboardFails) throw new Error('Clipboard denied');
      host.copiedValues.push(value);
    } } });
  });
  const copied = () => page.evaluate(() => (window as unknown as { copiedValues: string[] }).copiedValues);
  await page.goto('/');
  await page.getByRole('button', { name: 'Copy candidate serial', exact: true }).click();
  expect(await copied()).toEqual(['Usb-AbC']);
  await page.getByRole('button', { name: 'Copy engine SHA-256', exact: true }).click();
  expect((await copied()).at(-1)).toBe('d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54');
  await expect(page.locator('#toast')).toContainText('Copied engine SHA-256');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await page.getByText('Installation details and checksums', { exact: true }).click();
  for (const [label, value] of [['target serial', 'Usb-AbC'], ['target device ID', 'f'.repeat(32)], ['preparation job ID', 'e'.repeat(64)], ['image SHA-256', '1'.repeat(64)], ['description digest', '2'.repeat(64)], ['confirmation text', 'ENABLE_WRITE']]) {
    await page.getByRole('button', { name: `Copy ${label}`, exact: true }).click();
    expect((await copied()).at(-1)).toBe(value);
  }
  expect(await commands(page, 'confirm_preparation')).toEqual([]);
  await page.evaluate(() => { (window as unknown as { clipboardFails: boolean }).clipboardFails = true; });
  const before = await copied();
  await page.getByRole('button', { name: 'Copy image SHA-256', exact: true }).click();
  expect(await copied()).toEqual(before);
  await expect(page.locator('#toast')).toContainText('Clipboard access failed');
  await expect(page.locator('#toast')).not.toContainText('Copied');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});


test('native oversized drops retain the preview guard and direct users to streaming import', async ({ page }) => {
  await installMock(page);
  await page.goto('/');
  await page.locator('nav').getByRole('button', { name: 'Image library', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
  await page.locator('#file-input').evaluate(input => {
    const file = new File(['tiny backing bytes'], 'large.iso');
    Object.defineProperty(file, 'size', { value: 513 * 1024 * 1024 });
    const transfer = new DataTransfer(); transfer.items.add(file);
    (input as HTMLInputElement).files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await expect(page.locator('#toast')).toContainText('Use Add images or Import folder');
  await expect(page.locator('.image-row')).toHaveCount(1);
  await expect(page.locator('body')).not.toContainText('512 MiB');
});


test('failed installation never shows completed phases or an installed drive', async ({ page }) => {
  await installMock(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await page.getByRole('textbox', { name: 'Write confirmation' }).fill('ENABLE_WRITE');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await expect(page.locator('.installation-phases .current')).toContainText('writing_target');
  await page.evaluate(() => (window as unknown as { failInstall: () => void }).failInstall());
  await expect(page.getByRole('heading', { name: 'Installation stopped' })).toBeVisible();
  await expect(page.locator('.installation-phases')).toHaveCount(0);
  await expect(page.locator('.success-banner')).toHaveCount(0);
  await expect(page.getByText('The target may be incomplete.', { exact: false })).toBeVisible();
});


test('completed job keeps its original engine metadata when the current selection changes', async ({ page }) => {
  await installMock(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await expect(page.locator('.setup-details')).not.toHaveAttribute('open', '');
  await expect(page.locator('.wizard-summary')).toBeHidden();
  await expect(page.locator('.verification-summary')).toContainText('ventoy-1.1.18-linux.tar.gz');
  await page.getByRole('textbox', { name: 'Write confirmation' }).fill('ENABLE_WRITE');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await expect(page.locator('.installation-phases .current')).toContainText('writing_target');
  await page.evaluate(() => (window as unknown as { finishInstall: () => void }).finishInstall());
  await expect(page.getByRole('heading', { name: 'ISOHopper is installed', exact: true })).toBeVisible();
  await page.getByText('Setup details', { exact: true }).click();
  await page.getByText('Advanced', { exact: true }).click();
  await page.getByRole('button', { name: 'Choose engine archive', exact: true }).click();
  await expect(page.locator('.wizard-summary')).toContainText('renamed-verified-engine.tar.gz');
  await expect(page.locator('.setup-details')).toHaveAttribute('open', '');
  await expect(page.locator('.verification-summary')).toContainText('ventoy-1.1.18-linux.tar.gz');
  await expect(page.locator('.verification-summary')).not.toContainText('renamed-verified-engine.tar.gz');
  await expect(page.locator('.verification-summary')).toContainText('d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54');
});

test('restored job does not claim the current engine selection belongs to its receipt', async ({ page }) => {
  await installMock(page, 'restored');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'ISOHopper is installed', exact: true })).toBeVisible();
  await expect(page.locator('.verification-summary')).toContainText('Engine metadata is unavailable for this restored job.');
  await expect(page.locator('.verification-summary .verified-engine')).toHaveCount(0);
  await expect(page.locator('.verification-summary')).toContainText('1'.repeat(64));
  expect(await commands(page, 'start_preparation')).toEqual([]);
  await page.getByText('Setup details', { exact: true }).click();
  await expect(page.locator('.wizard-summary')).toContainText('ventoy-1.1.18-linux.tar.gz');
});


test('all post-confirmation write phases keep the wizard in Install', async ({ page }) => {
  await installMock(page, 'preflight');
  await page.goto('/');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  await page.getByRole('textbox', { name: 'Write confirmation' }).fill('ENABLE_WRITE');
  await page.getByRole('button', { name: 'Install ISOHopper', exact: true }).click();
  for (const phase of ['checking_readiness', 'locking_target', 'writing_target', 'flushing_target', 'verifying_target']) {
    if (phase !== 'checking_readiness') await page.evaluate(phase => (window as unknown as { advanceWritePhase: (phase: string) => void }).advanceWritePhase(phase), phase);
    await expect(page.locator('.installation-phases .current')).toContainText(phase);
    await expect(page.locator('.wizard-steps [aria-current="step"]')).toHaveText('3Install');
    await expect(page.getByRole('heading', { name: 'Installing ISOHopper', exact: true })).toBeVisible();
    await expect(page.getByText('Preparing empty bootable image', { exact: true })).toHaveCount(0);
  }
});
