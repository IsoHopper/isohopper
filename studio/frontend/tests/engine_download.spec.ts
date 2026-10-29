// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

interface MockOptions { pauseCommand?: string; sessionRestore?: boolean; emptyImages?: boolean; targets?: unknown[]; platform?: string; preparationAvailable?: boolean; advertised?: boolean; selected?: boolean; active?: boolean; preparation?: boolean; pendingStart?: boolean; statusError?: boolean; startError?: boolean }
interface MockHost { pauseCommand: string; pendingCommand: string; releaseNative: () => void; engineCalls: { command: string; args: unknown }[]; setDownload: (phase: string, bytes?: number, cacheHit?: boolean) => void; resolveStart: () => void; statusError: boolean; startError: boolean; selectionError: boolean; clearSelection: () => void }
async function mockNative(page: Page, options: MockOptions = {}) {
  await page.addInitScript((options: MockOptions) => {
    const host = window as unknown as MockHost & { __TAURI__: unknown };
    const archive = { archive_id: `src_${'b'.repeat(64)}`, name: 'ventoy-1.1.18-linux.tar.gz', bytes: 20320548, sha256: 'd86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54', version: '1.1.18' };
    const source = { source_id: `src_${'a'.repeat(64)}`, name: 'boot.iso', bytes: 3, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } };
    const target = { selection_token: 'c'.repeat(64), display_id: '\\\\.\\PhysicalDrive7', disk: { number: 7, friendly_name: 'Mock USB', serial_number: 'USB-AbC', size: 8000000000, logical_sector_size: 512, physical_sector_size: 512, bus_type: 7 } };
    const createJob = (phase: string, bytes = 0, cacheHit = false) => ({ job_id: 'd'.repeat(64), phase, active: ['checking_cache', 'downloading', 'verifying'].includes(phase), cancel_requested: phase === 'cancelled', completed_bytes: bytes, total_bytes: 20320548, expected_sha256: archive.sha256, version: '1.1.18', cache_hit: cacheHit, message: phase === 'failed' ? 'SHA-256 mismatch; partial download removed.' : phase === 'cancelled' ? 'Download cancelled; partial download removed.' : phase === 'ready' ? 'Verified archive selected.' : 'Mock download in progress.' });
    let job = JSON.parse(sessionStorage.getItem('engine-job') || 'null') || (options.active ? createJob('downloading', 4096) : null);
    let selected = sessionStorage.getItem('engine-selected') === 'true' || options.selected === true;
    host.engineCalls = [];
    host.statusError = options.statusError === true;
    host.startError = options.startError === true;
    host.selectionError = false;
    host.pauseCommand = options.pauseCommand || '';
    host.pendingCommand = '';
    host.clearSelection = () => { selected = false; };
    host.setDownload = (phase, bytes, cacheHit) => {
      job = createJob(phase, bytes, cacheHit);
      sessionStorage.setItem('engine-job', JSON.stringify(job));
      if (phase === 'ready') { selected = true; sessionStorage.setItem('engine-selected', 'true'); }
    };
    host.__TAURI__ = { core: { invoke: async (command: string, args: unknown) => {
      host.engineCalls.push({ command, args });
      if (host.pendingCommand && ['restore_session', 'list_preparation_targets', 'inspect_devices', 'probe_helper', 'pick_images', 'pick_directory', 'pick_engine_archive', 'release_sources', 'start_preparation', 'start_engine_download'].includes(command)) throw new Error('Another native operation is running');
      if (command === host.pauseCommand) {
        host.pauseCommand = ''; host.pendingCommand = command;
        await new Promise<void>(resolve => { host.releaseNative = () => { host.pendingCommand = ''; resolve(); }; });
      }
      if (command === 'capabilities') return { mode: 'native', platform: options.platform || 'windows', file_import: true, host_inventory: true, helper_probe: true, preparation_available: options.preparationAvailable !== false, physical_preparation: options.preparationAvailable !== false, preparation_unavailable_reason: '', ...(options.advertised === false ? {} : { engine_download: true }), ...(options.sessionRestore ? { session_restore: true } : {}) };
      if (command === 'list_sources') return options.emptyImages ? [] : [source];
      if (command === 'restore_session') return { images: [source], warnings: ['Missing image skipped during session restore.'] };
      if (command === 'selected_engine_archive') { if (host.selectionError) throw new Error('Selection unavailable.'); return selected ? archive : null; }
      if (command === 'pick_engine_archive') { selected = true; return archive; }
      if (command === 'list_preparation_targets') return JSON.parse(sessionStorage.getItem('target-overrides') || 'null') || options.targets || [target];
      if (command === 'inspect_devices') return { source: 'mock-native', disks: [], warnings: [] };
      if (command === 'probe_helper') return { status: 'cancelled', physical_preparation: false };
      if (command === 'preparation_status') return options.preparation ? { job_id: 'e'.repeat(64), phase: 'await_confirmation', message: 'Mock exact target ready.', active: true, cancel_requested: false, completed_bytes: 8000000000, total_bytes: 8000000000, bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sources_released: true, source_manifest: options.emptyImages ? [] : [{ relative_path: 'boot.iso', bytes: 3, sha256: 'a'.repeat(64) }], target: null, image_sha256: 'f'.repeat(64), description_digest: 'a'.repeat(64), challenge: 'ENABLE_WRITE' } : null;
      if (command === 'engine_download_status') { if (host.statusError) throw new Error('Status bridge unavailable.'); return structuredClone(job); }
      if (command === 'start_engine_download') {
        if (host.startError) throw new Error('Network unavailable.');
        if (options.pendingStart) await new Promise<void>(resolve => { host.resolveStart = resolve; });
        host.setDownload('checking_cache'); return structuredClone(job);
      }
      if (command === 'cancel_engine_download') { host.setDownload('cancelled', job.completed_bytes); return null; }
      if (command === 'start_preparation') throw new Error('Mock staging intentionally stopped.');
      throw new Error(`Unexpected command ${command}`);
    } } };
  }, options);
}
const calls = (page: Page, command: string) => page.evaluate(command => (window as unknown as MockHost).engineCalls.filter(call => call.command === command), command);
const setDownload = (page: Page, phase: string, bytes = 0, cacheHit = false) => page.evaluate(({ phase, bytes, cacheHit }) => (window as unknown as MockHost).setDownload(phase, bytes, cacheHit), { phase, bytes, cacheHit });
const start = (page: Page) => page.getByRole('button', { name: 'Download engine', exact: true });
const status = (page: Page) => page.locator('.engine-download-status');
const build = (page: Page) => page.getByRole('button', { name: 'Install ISOHopper', exact: true });

test('download is explicit, shows exact progress, refreshes selection and preserves configuration editing', async ({ page }, testInfo) => {
  await mockNative(page);
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(start(page)).toBeEnabled();
  expect(await calls(page, 'start_engine_download')).toEqual([]);
  await page.locator('#preparation-target').selectOption('c'.repeat(64));
  await start(page).click();
  await expect(status(page)).toContainText('checking_cache');
  await setDownload(page, 'downloading', 1048576);
  await expect(status(page)).toContainText('1,048,576 bytes / 20,320,548 bytes');
  await expect(status(page)).toContainText('d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54');
  await expect(page.getByRole('button', { name: 'Choose engine archive', exact: true })).toBeDisabled();
  await expect(build(page)).toBeDisabled();
  await page.getByRole('button', { name: 'Image library', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Remove boot.iso', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Remove boot.iso', exact: true }).dispatchEvent('click');
  expect(await calls(page, 'release_sources')).toEqual([]);
  await page.getByRole('button', { name: 'Prepare drive', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Check elevated helper', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Inspect host devices (read only)', exact: true })).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: `../../.local/release-work/engine-download-ui${testInfo.project.name === 'desktop-chromium' ? '' : '-compact'}.png`, fullPage: true });
  if (testInfo.project.name === 'compact-chromium') {
    await page.locator('#engine-selection').evaluate(element => element.scrollIntoView({ block: 'center' }));
    await page.locator('#engine-selection').screenshot({ path: '../../.local/release-work/engine-download-ui-compact-detail.png' });
  }
  await page.getByRole('button', { name: 'Configuration', exact: true }).click();
  const editor = page.getByRole('textbox', { name: 'Configuration source', exact: true });
  await editor.fill('# Keep this manual edit\nboot: {}');
  await editor.focus();
  await setDownload(page, 'verifying', 20320548);
  await expect.poll(async () => (await calls(page, 'engine_download_status')).length).toBeGreaterThan(2);
  await expect(editor).toHaveValue('# Keep this manual edit\nboot: {}');
  await expect(editor).toBeFocused();
  await setDownload(page, 'ready', 20320548);
  await expect.poll(async () => (await calls(page, 'selected_engine_archive')).length).toBeGreaterThan(1);
  await expect(editor).toBeFocused();
  await page.getByRole('button', { name: 'Prepare drive', exact: true }).click();
  await expect(status(page)).toContainText('ready');
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
  await expect(build(page)).toBeEnabled();
  await page.getByRole('button', { name: 'Activity', exact: true }).click();
  const ready = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export activity', exact: true }).click();
  const exported = JSON.parse(await readFile((await (await ready).path())!, 'utf8'));
  expect(exported.engine_download_snapshot).toMatchObject({ phase: 'ready', completed_bytes: 20320548, cache_hit: false });
  expect(exported.events.filter((event: { title: string; detail: string }) => event.title === 'Engine download state' && event.detail.includes('phase=downloading'))).toHaveLength(1);
});

test('pending start blocks duplicate starts, archive replacement and staging handlers', async ({ page }) => {
  await mockNative(page, { selected: true, pendingStart: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(start(page)).toBeEnabled();
  await page.locator('#preparation-target').selectOption('c'.repeat(64));
  await start(page).click();
  await expect(start(page)).toBeDisabled();
  await start(page).dispatchEvent('click');
  await page.locator('#pick-engine').dispatchEvent('click');
  await page.locator('#start-preparation').dispatchEvent('click');
  expect(await calls(page, 'start_engine_download')).toHaveLength(1);
  expect(await calls(page, 'pick_engine_archive')).toEqual([]);
  expect(await calls(page, 'start_preparation')).toEqual([]);
  await page.evaluate(() => (window as unknown as MockHost).resolveStart());
  await expect(status(page)).toContainText('checking_cache');
});

test('reload recovers an active download, cancel preserves old selection and stops polling', async ({ page }) => {
  await mockNative(page, { selected: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await start(page).click();
  await setDownload(page, 'downloading', 8192);
  await page.reload();
  await page.locator('.engine-advanced > summary').click();
  await expect(status(page)).toContainText('8,192 bytes');
  expect(await calls(page, 'start_engine_download')).toEqual([]);
  expect(await calls(page, 'list_preparation_targets')).toEqual([]);
  await page.getByRole('button', { name: 'Cancel download', exact: true }).click();
  await expect(status(page)).toContainText('cancelled');
  expect(await calls(page, 'cancel_engine_download')).toEqual([{ command: 'cancel_engine_download', args: { jobId: 'd'.repeat(64) } }]);
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
  await expect(start(page)).toBeEnabled();
  const count = (await calls(page, 'engine_download_status')).length;
  await page.waitForTimeout(1600);
  expect(await calls(page, 'engine_download_status')).toHaveLength(count);
  await expect(page.locator('#preparation-target option')).toHaveCount(2);
});

test('failed verification leaves no phantom selection and permits explicit retry', async ({ page }) => {
  await mockNative(page);
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await start(page).click();
  await setDownload(page, 'failed', 20320548);
  await expect(status(page)).toContainText('SHA-256 mismatch');
  await expect(page.locator('#engine-selection')).toContainText('No engine archive selected.');
  await expect(build(page)).toBeDisabled();
  await start(page).click();
  expect(await calls(page, 'start_engine_download')).toHaveLength(2);
  await setDownload(page, 'ready', 20320548, true);
  await expect(status(page)).toContainText('Verified cache');
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
});

test('failed new download preserves a valid manually selected archive', async ({ page }) => {
  await mockNative(page, { selected: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(start(page)).toBeEnabled();
  await page.locator('#preparation-target').selectOption('c'.repeat(64));
  await start(page).click();
  await setDownload(page, 'failed', 1000);
  await expect(status(page)).toContainText('SHA-256 mismatch');
  await expect(build(page)).toBeEnabled();
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
});

test('unadvertised native versions retain offline selection without new IPC calls', async ({ page }) => {
  await mockNative(page, { advertised: false });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(page.getByRole('button', { name: 'Choose engine archive', exact: true })).toBeEnabled();
  await expect(start(page)).toHaveCount(0);
  expect(await calls(page, 'engine_download_status')).toEqual([]);
  await page.getByRole('button', { name: 'Choose engine archive', exact: true }).click();
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
});

test('status failure keeps unknown operations gated until explicit read-only recovery', async ({ page }) => {
  await mockNative(page, { statusError: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(page.locator('#engine-selection')).toContainText('Status bridge unavailable');
  await expect(start(page)).toBeDisabled();
  await page.evaluate(() => { (window as unknown as MockHost).statusError = false; });
  await page.getByRole('button', { name: 'Retry download status', exact: true }).click();
  await expect(start(page)).toBeEnabled();
  await expect(page.locator('#preparation-target option')).toHaveCount(2);
  expect(await calls(page, 'start_engine_download')).toEqual([]);
});

test('start failure displays an actionable error without losing offline selection', async ({ page }) => {
  await mockNative(page, { startError: true, selected: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await start(page).click();
  await expect(page.locator('#engine-selection')).toContainText('Network unavailable');
  await expect(start(page)).toBeEnabled();
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
});

test('preparation confirmation blocks download starts and status polling leaves typed challenge intact', async ({ page }) => {
  await mockNative(page, { preparation: true });
  await page.goto('/');
  await page.locator('.setup-details > summary').click();
  await page.locator('.engine-advanced > summary').click();
  const phrase = page.getByRole('textbox', { name: 'Write confirmation', exact: true });
  await expect(phrase).toBeEnabled();
  await phrase.fill('ENABLE_WRITE');
  await expect(start(page)).toBeDisabled();
  await start(page).dispatchEvent('click');
  expect(await calls(page, 'start_engine_download')).toEqual([]);
  await page.waitForTimeout(1600);
  await expect(phrase).toHaveValue('ENABLE_WRITE');
  await expect(phrase).toBeFocused();
});


test('ready selection lookup failure retries the current catalogue before allowing preparation', async ({ page }) => {
  await mockNative(page);
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await start(page).click();
  await page.evaluate(() => { (window as unknown as MockHost).selectionError = true; });
  await setDownload(page, 'ready', 20320548);
  await expect(page.locator('#engine-selection')).toContainText('Selection unavailable');
  await expect(start(page)).toBeDisabled();
  await page.evaluate(() => { (window as unknown as MockHost).selectionError = false; });
  await page.getByRole('button', { name: 'Retry download status', exact: true }).click();
  await expect(page.locator('#engine-selection')).toContainText('ventoy-1.1.18-linux.tar.gz');
  await expect(start(page)).toBeEnabled();
});

test('ready history without a current archive never restores an old capability', async ({ page }) => {
  await mockNative(page);
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await start(page).click();
  await setDownload(page, 'ready', 20320548);
  await page.evaluate(() => { (window as unknown as MockHost).clearSelection(); });
  await expect(page.locator('#engine-selection')).toContainText('No retained engine archive');
  await expect(build(page)).toBeDisabled();
  await expect(start(page)).toBeEnabled();
});

for (const platform of ['macos', 'linux']) test(`${platform} status initialization leaves native import and inventory available without preparation`, async ({ page }) => {
  await mockNative(page, { platform, preparationAvailable: false });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Inspect host devices (read only)', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Image library', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
  expect(await calls(page, 'engine_download_status')).toHaveLength(1);
  expect(await calls(page, 'inspect_devices')).toHaveLength(1);
  expect(await calls(page, 'start_engine_download')).toEqual([]);
  await expect(start(page)).toHaveCount(0);
});


test('configuration preferences and manual source edits survive reload with validated defaults', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.getByRole('button', { name: 'Configuration', exact: true }).click();
  await page.locator('[data-option="netboot"]').uncheck();
  await page.locator('#timeout').fill('25');
  await page.locator('#timeout').blur();
  await page.locator('#theme').selectOption('aurora');
  await page.getByRole('button', { name: 'TOML', exact: true }).click();
  await page.locator('#config-editor').fill('# Remember this manual configuration');
  await page.reload();
  await page.getByRole('button', { name: 'Configuration', exact: true }).click();
  await expect(page.locator('[data-option="netboot"]')).not.toBeChecked();
  await expect(page.locator('#timeout')).toHaveValue('25');
  await expect(page.locator('#theme')).toHaveValue('aurora');
  await expect(page.locator('#config-editor')).toHaveValue('# Remember this manual configuration');
  await expect(page.getByRole('button', { name: 'TOML', exact: true })).toHaveClass('selected');
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('isohopper-preferences-v1')!));
  expect(saved).not.toHaveProperty('preparationPhrase');
  expect(saved).not.toHaveProperty('archive_id');
  expect(saved).not.toHaveProperty('source_id');
});

const candidate = (token: string, name: string, size = 64 * 1024 ** 3) => ({ selection_token: token.repeat(64), display_id: `Mock disk ${token}`, disk: { number: 7, friendly_name: name, serial_number: `SERIAL-${token}`, size, logical_sector_size: 512, physical_sector_size: 512, bus_type: 7, is_boot: false, is_system: false, is_read_only: false, is_offline: false, is_clustered: false } });

test('empty media can build after engine and conservative target defaults are ready', async ({ page }) => {
  await mockNative(page, { emptyImages: true, selected: true, targets: [candidate('a', 'Thumb drive'), { ...candidate('b', 'USB device'), volume_labels: ['IsoHopper'] }, candidate('c', 'Large backup', 1024 ** 4)] });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(page.locator('#preparation-target')).toHaveValue('b'.repeat(64));
  await expect(page.locator('#preparation-target option')).toHaveCount(3);
  await expect(page.locator('#preparation-target option:checked')).toContainText('IsoHopper');
  await expect(page.getByRole('checkbox', { name: /Show large drives/ })).not.toBeChecked();
  await expect(page.locator('#preparation-prerequisites')).toContainText('Empty bootable drive');
  await expect(page.locator('#preparation-prerequisites')).toContainText('Ready.');
  await expect(build(page)).toBeEnabled();
  await build(page).click();
  expect(await calls(page, 'start_preparation')).toEqual([{ command: 'start_preparation', args: { targetToken: 'b'.repeat(64), sourceIds: [], archiveToken: `src_${'b'.repeat(64)}` } }]);
});

test('explicit target preference resolves fresh native tokens and large-drive visibility persists', async ({ page }) => {
  const targets = [candidate('a', 'Thumb drive'), candidate('b', 'IsoHopper'), candidate('c', 'Large backup', 1024 ** 4)];
  await mockNative(page, { targets, selected: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await expect(page.locator('#preparation-target')).toHaveValue('b'.repeat(64));
  await page.locator('#preparation-target').selectOption('a'.repeat(64));
  await page.getByRole('checkbox', { name: /Show large drives/ }).check();
  await expect(page.locator('#preparation-target option')).toHaveCount(4);
  await page.evaluate(targets => sessionStorage.setItem('target-overrides', JSON.stringify(targets)), targets.map(target => ({ ...target, selection_token: target.selection_token === 'a'.repeat(64) ? 'd'.repeat(64) : target.selection_token })));
  await page.reload();
  await page.locator('.engine-advanced > summary').click();
  await expect(page.locator('#preparation-target')).toHaveValue('d'.repeat(64));
  await expect(page.getByRole('checkbox', { name: /Show large drives/ })).toBeChecked();
  const saved = await page.evaluate(() => localStorage.getItem('isohopper-preferences-v1'));
  expect(saved).toContain('SERIAL-a');
  expect(saved).not.toContain('a'.repeat(64));
  expect(saved).not.toContain('d'.repeat(64));
});


test('native session restore shows retained images and skipped-file warnings without frontend paths', async ({ page }) => {
  await mockNative(page, { sessionRestore: true });
  await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
  await page.getByRole('button', { name: 'Image library', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(1);
  await expect(page.locator('.source-restore-warnings')).toContainText('Missing image skipped');
  expect(await calls(page, 'restore_session')).toEqual([{ command: 'restore_session', args: undefined }]);
  expect(await calls(page, 'list_sources')).toEqual([]);
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
});


test('a sealed empty preparation still requires the exact explicit write challenge', async ({ page }) => {
  await mockNative(page, { preparation: true, emptyImages: true });
  await page.goto('/');
  await page.locator('.setup-details > summary').click();
  await page.locator('.engine-advanced > summary').click();
  await expect(page.locator('.job-source-manifest')).toHaveCount(0);
  const write = page.getByRole('button', { name: 'Install ISOHopper', exact: true });
  await expect(write).toBeDisabled();
  await page.getByRole('textbox', { name: 'Write confirmation' }).fill('ENABLE_WRITE');
  await expect(write).toBeEnabled();
  expect(await calls(page, 'confirm_preparation')).toEqual([]);
});

for (const phase of ['startup targets', 'startup inventory', 'helper probe', 'host inspection']) {
  test(`native operations stay gated during ${phase} without blocking configuration`, async ({ page }) => {
    const command = phase === 'startup targets' ? 'list_preparation_targets' : phase === 'helper probe' ? 'probe_helper' : 'inspect_devices';
    await mockNative(page, { selected: true, sessionRestore: true, targets: [candidate('a', 'IsoHopper')], ...(phase.startsWith('startup') ? { pauseCommand: command } : {}) });
    await page.goto('/');
  await page.locator('.engine-advanced > summary').click();
    if (!phase.startsWith('startup')) {
      await expect(start(page)).toBeEnabled();
      await page.evaluate(command => { (window as unknown as MockHost).pauseCommand = command; }, command);
      await page.locator(phase === 'helper probe' ? '#probe-helper' : '#inspect-host').click();
      if (phase === 'host inspection') await page.getByRole('button', { name: 'Close host inventory' }).click();
    }
    await expect.poll(() => page.evaluate(() => (window as unknown as MockHost).pendingCommand)).toBe(command);
    const before = await page.evaluate(() => (window as unknown as MockHost).engineCalls);
    for (const selector of ['#pick-engine', '#download-engine', '#start-preparation', '#refresh-drives', '#probe-helper', '#inspect-host']) {
      await expect(page.locator(selector)).toBeDisabled();
      await page.locator(selector).dispatchEvent('click');
    }
    await page.getByRole('button', { name: 'Image library', exact: true }).click();
    for (const selector of ['#dropzone', '#import-folder', '.remove-image']) {
      await expect(page.locator(selector)).toBeDisabled();
      await page.locator(selector).dispatchEvent('click');
    }
    await expect(page.locator('#clear-images')).toBeDisabled();
    await page.locator('#clear-images').dispatchEvent('click');
    await page.getByRole('button', { name: 'Configuration', exact: true }).click();
    await page.getByRole('textbox', { name: 'Configuration source', exact: true }).fill('# settings remain editable');
    expect(await page.evaluate(() => (window as unknown as MockHost).engineCalls)).toEqual(before);
    await page.evaluate(() => (window as unknown as MockHost).releaseNative());
    await page.getByRole('button', { name: 'Prepare drive', exact: true }).click();
    await expect(start(page)).toBeEnabled();
    await expect(build(page)).toBeEnabled();
    await page.getByRole('button', { name: 'Image library', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
    await expect(page.locator('.image-row')).toHaveCount(1);
    await expect(page.locator('.source-restore-warnings')).toContainText('Missing image skipped');
    await page.getByRole('button', { name: 'Configuration', exact: true }).click();
    await expect(page.getByRole('textbox', { name: 'Configuration source', exact: true })).toHaveValue('# settings remain editable');
  });
}
