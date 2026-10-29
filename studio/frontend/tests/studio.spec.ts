// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, test, type Page } from '@playwright/test';

interface NativeScenario {
  helperOutcome?: 'connected' | 'cancelled' | 'error';
  capabilityError?: string;
  inventoryError?: string;
  pickerOutcome?: 'image' | 'cancel' | 'error';
  releaseFailures?: number;
  sourceListError?: string;
}

async function installNativeBridge(page: Page, scenario: NativeScenario = {}) {
  await page.addInitScript(({ capabilityError, inventoryError, pickerOutcome, releaseFailures, sourceListError, helperOutcome }) => {
    const host = window as unknown as { __TAURI__: unknown; nativeCommands: string[]; releasedSourceIds: string[][]; publishNativeSource: (source: StoredSource) => void; nativeSourceListError?: string; pauseSourceListing: () => void; finishSourceListing: () => void };
    host.nativeCommands = [];
    host.releasedSourceIds = [];
    let failuresLeft = releaseFailures || 0;
    type StoredSource = { source_id: string; name: string; relative_path?: string; bytes: number; verification: { algorithm: string; digest: string; bytes: number; status: string; publisher_verified: boolean } };
    let retained: StoredSource[] = JSON.parse(sessionStorage.getItem('test-retained-sources') || '[]');
    const store = (entries: StoredSource[]) => { retained = entries; sessionStorage.setItem('test-retained-sources', JSON.stringify(entries)); };
    host.publishNativeSource = source => store([...retained, source]);
    let sourceListPause: Promise<void> | undefined;
    host.pauseSourceListing = () => { sourceListPause = new Promise(resolve => { host.finishSourceListing = () => { sourceListPause = undefined; resolve(); }; }); };

    host.__TAURI__ = { core: { invoke: async (command: string, args?: { ids?: string[] }) => {
      host.nativeCommands.push(command);
      if (command === 'capabilities') {
        if (capabilityError) throw new Error(capabilityError);
        return { mode: 'native', platform: 'windows', file_import: true, host_inventory: true, helper_probe: !!helperOutcome, physical_preparation: false, preparation_unavailable_reason: 'Privileged preparation helper is not available.' };
      }
      if (command === 'probe_helper') {
        if (helperOutcome === 'error') throw new Error('Helper user or logon mismatch');
        if (helperOutcome === 'cancelled') return { status: 'cancelled', physical_preparation: false };
        return { status: 'connected', protocol: 1, helper_version: '0.1.0', helper_pid: 42, helper_created: '133721455931234567', helper_sha256: 'a'.repeat(64), physical_preparation: false };
      }
      if (command === 'inspect_devices') {
        if (inventoryError) throw new Error(inventoryError);
        return { source: 'test-host-adapter', disks: [{ id: 'host-system-unique-id', serial: 'HOST-SERIAL-1234', model: 'Host system storage', bus: 'nvme', size_bytes: 512_000_000_000, logical_sector_size: 512, physical_sector_size: 4096, system_disk: true, external: false, safety_checks_complete: false }], warnings: [{ disk_id: 'host-system-unique-id', code: 'safety_unknown', message: 'Safety metadata is not complete.' }] };
      }
      if (command === 'list_sources') {
        if (sourceListError || host.nativeSourceListError) throw new Error(sourceListError || host.nativeSourceListError);
        const snapshot = [...retained];
        await sourceListPause;
        return snapshot;
      }
      if (command === 'pick_images') {
        if (pickerOutcome === 'error') throw new Error('file read failed');
        if (pickerOutcome === 'cancel') return [];
        const selected = [{ source_id: `src_${'a'.repeat(64)}`, name: '/private/media/native-large.iso', bytes: 6_000_000_000, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 6_000_000_000, status: 'hash-only', publisher_verified: false } }];
        store([...retained, ...selected]); return selected;
      }
      if (command === 'pick_directory') {
        const image = (relative_path: string, id: string) => ({ source_id: `src_${id.repeat(64)}`, name: 'boot.iso', relative_path, bytes: 3, verification: { algorithm: 'sha256', digest: 'b'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } });
        const selected = [image('Mac/boot.iso', 'b'), image('Windows/boot.iso', 'c'), image('MAC/BOOT.ISO', 'd')];
        store([...retained, ...selected]);
        return { images: selected, warnings: ['Skipped symbolic link: external'] };
      }
      if (command === 'release_sources') {
        host.releasedSourceIds.push(args!.ids!);
        if (failuresLeft-- > 0) throw new Error('Source is leased by a job');
        store(retained.filter(source => !args!.ids!.includes(source.source_id)));
        return null;
      }
      if (command === 'check_config') return { valid: true };
      throw new Error(`Unexpected native operation: ${command}`);
    } } };
  }, scenario);
}

async function openLibrary(page: Page) {
  await page.locator('nav').getByRole('button', { name: 'Image library', exact: true }).click();
}

async function nativeCommands(page: Page) {
  return page.evaluate(() => (window as unknown as { nativeCommands: string[] }).nativeCommands);
}

async function expectNoDemoContent(page: Page) {
  await expect(page.getByText(/USB flash drive 64 GB|USB NVMe bridge 1 TB|SD card 32 GB/)).toHaveCount(0);
  await expect(page.getByText(/linux-desktop-demo\.iso|recovery-toolkit-demo\.img/)).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Load samples' })).toHaveCount(0);
  await expect(page.getByText('Explicit browser demo · mock devices · no physical disk writes')).toHaveCount(0);
}

for (const helperOutcome of ['connected', 'cancelled', 'error'] as const) {
  test(`explicit helper probe ${helperOutcome} keeps physical preparation unavailable`, async ({ page }) => {
    await installNativeBridge(page, { helperOutcome });
    await page.goto('/');
    const button = page.getByRole('button', { name: 'Check elevated helper', exact: true });
    await expect(button).toBeEnabled();
    expect(await nativeCommands(page)).not.toContain('probe_helper');
    await button.click();
    await expect(page.locator('#helper-status')).toContainText(helperOutcome === 'connected' ? 'Read-only helper connected and exited' : helperOutcome === 'cancelled' ? 'Windows elevation cancelled' : 'Helper check failed');
    await expect(page.getByText('Preparation unavailable', { exact: true })).toBeVisible();
    expect((await nativeCommands(page)).filter(command => command === 'probe_helper')).toHaveLength(1);
    await expectNoDemoContent(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test('bare browser reports unavailable native runtime and requires an explicit demo choice', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Native desktop runtime unavailable.', { exact: true })).toBeVisible();
  await expect(page.getByText('Experimental · physical preparation unavailable')).toBeVisible();
  await expect(page.locator('.image-row')).toHaveCount(0);
  await expectNoDemoContent(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('link', { name: 'Open browser demo' }).click();
  await expect(page).toHaveURL(/\?demo=1$/);
  await expect(page.getByText('Explicit browser demo · mock devices · no physical disk writes')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeEnabled();
});

for (const url of ['/', '/?demo=1']) {
  test(`native startup uses actual read-only inventory without fixtures at ${url}`, async ({ page }) => {
    await installNativeBridge(page);
    await page.goto(url);
    await expect(page.getByText('Experimental · physical preparation unavailable')).toBeVisible();
    await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
    await expect(page.locator('.target-panel')).toContainText('Preparation unavailable');
    await expect(page.locator('.target-panel')).toContainText('Privileged preparation helper is not available.');
    await expect(page.locator('.image-row')).toHaveCount(0);
    await expect(page.locator('#choose-drive')).toHaveCount(0);
    await expectNoDemoContent(page);
    expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices']);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.locator('nav').getByRole('button', { name: 'Image library' }).click();
    await expect(page.locator('.image-row')).toHaveCount(0);
    await expectNoDemoContent(page);
  });
}

for (const stage of ['capabilities', 'inventory'] as const) {
  test(`native ${stage} failure is visible and never falls back to browser fixtures`, async ({ page }) => {
    const message = `${stage} service unavailable`;
    await installNativeBridge(page, stage === 'capabilities' ? { capabilityError: message } : { inventoryError: message });
    await page.goto('/?demo=1');
    await expect(page.locator('.target-panel')).toContainText(message);
    await expect(page.locator('.target-panel')).toContainText('Preparation unavailable');
    await expect(page.locator('.image-row')).toHaveCount(0);
    await expectNoDemoContent(page);
    expect(await nativeCommands(page)).toEqual(stage === 'capabilities' ? ['capabilities'] : ['capabilities', 'list_sources', 'inspect_devices']);
  });
}

test('explicit browser demo shows mock devices and has no horizontal overflow', async ({ page }) => {
  await page.goto('/?demo=1');
  await expect(page.getByText('Explicit browser demo · mock devices · no physical disk writes')).toBeVisible();
  await expect(page.locator('header')).toHaveCount(0);
  await expect(page.locator('.experimental')).toContainText('Browser file I/O · demo hardware inventory');
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeEnabled();
  await expect(page.locator('.image-row')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('risk confirmation binds to the selected device and Enter does not start a run', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.locator('#choose-drive').click();
  const picker = page.getByRole('dialog');
  await expect(picker.getByRole('button', { name: /Internal system disk/ })).toBeDisabled();
  await expect(picker.getByRole('button', { name: /USB bridge without serial/ })).toBeDisabled();
  await picker.getByRole('button', { name: /USB NVMe bridge 1 TB/ }).click();
  const run = page.getByRole('button', { name: 'Simulate preparation' });
  await expect(run).toBeDisabled();
  const challenge = await page.locator('.challenge').innerText();
  const input = page.getByRole('textbox', { name: 'Disk confirmation phrase' });
  await input.fill('wrong disk');
  await expect(run).toBeDisabled();
  await input.fill(challenge.toLowerCase());
  await expect(run).toBeEnabled();
  await input.press('Enter');
  await expect(page.getByRole('progressbar')).toHaveCount(0);
  await page.locator('#choose-drive').click();
  await picker.getByRole('button', { name: /SD card 32 GB/ }).click();
  await page.locator('#choose-drive').click();
  await picker.getByRole('button', { name: /USB NVMe bridge 1 TB/ }).click();
  await expect(input).toHaveValue('');
  await expect(run).toBeDisabled();
});

test('paste into the risky confirmation field is rejected', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.locator('#choose-drive').click();
  await page.getByRole('dialog').getByRole('button', { name: /USB NVMe bridge 1 TB/ }).click();
  const input = page.getByRole('textbox', { name: 'Disk confirmation phrase' });
  const allowed = await input.evaluate(element => element.dispatchEvent(new ClipboardEvent('paste', { cancelable: true, bubbles: true })));
  expect(allowed).toBe(false);
  await expect(input).toHaveValue('');
});

test('hashes actual local data without treating it as publisher verification', async ({ page }) => {
  await page.goto('/?demo=1');
  await openLibrary(page);
  await page.locator('#file-input').setInputFiles({ name: 'tiny.iso', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  const row = page.locator('.image-row').filter({ hasText: 'tiny.iso' });
  await expect(row.getByText('Hash only')).toBeVisible();
  await expect(row).toContainText('ba7816bf8f01');
  await expect(row).toContainText('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  await expect(row.getByRole('button', { name: 'Copy SHA-256 for tiny.iso' })).toBeEnabled();
  await row.getByRole('button', { name: 'Remove tiny.iso' }).click();
  await expect(page.getByText('tiny.iso', { exact: true })).toHaveCount(0);
});

test('populated checksums and nested paths scroll inside the table without widening the page', async ({ page }) => {
  await page.goto('/?demo=1');
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeEnabled();
  await openLibrary(page);
  await page.locator('#folder-input').evaluate(input => {
    const transfer = new DataTransfer();
    for (const [path, data] of [['tiny.iso', 'abc'], ['Windows/boot.iso', 'windows'], ['Mac/boot.img', 'mac']]) {
      const file = new File([data], path.split('/').pop()!, { type: 'application/octet-stream' });
      Object.defineProperty(file, 'webkitRelativePath', { value: `Library/${path}` });
      transfer.items.add(file);
    }
    (input as HTMLInputElement).files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await expect(page.locator('.hash-cell code')).toHaveCount(3);
  await expect(page.getByText('Windows/boot.iso', { exact: true })).toBeVisible();
  await expect(page.getByText('Mac/boot.img', { exact: true })).toBeVisible();
  for (const view of ['Image library']) {
    await page.locator('nav').getByRole('button', { name: view }).click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (page.viewportSize()!.width <= 640) {
      const table = page.locator('.image-list');
      const scrolled = await table.evaluate(element => {
        element.scrollLeft = element.scrollWidth;
        return element.scrollWidth > element.clientWidth && element.scrollLeft > 0;
      });
      expect(scrolled).toBe(true);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    }
  }
});

test('rejects unsupported intake and displays safe filenames', async ({ page }) => {
  await page.goto('/?demo=1');
  await openLibrary(page);
  await page.locator('#file-input').setInputFiles({ name: 'program.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  await expect(page.getByRole('status')).toContainText('Unsupported format');
  await expect(page.locator('.image-row').filter({ hasText: 'program.exe' })).toHaveCount(0);
  await openLibrary(page);
  await page.locator('#file-input').setInputFiles({ name: '<svg onload=alert(1)>.iso', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  await expect(page.getByText('<svg onload=alert(1)>.iso', { exact: true })).toBeVisible();
  await expect(page.locator('[onload]')).toHaveCount(0);
});

test('completes a simulation and records what did and did not happen', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.getByRole('button', { name: 'Simulate preparation' }).click();
  await expect(page.getByRole('button', { name: 'Simulation in progress' })).toBeDisabled();
  await expect(page.getByText('No disk was opened or modified.')).toBeVisible();
  await page.locator('nav').getByRole('button', { name: 'Activity' }).click();
  await expect(page.locator('.activity-panel').getByText('Preparation simulation complete')).toBeVisible();
  await expect(page.locator('.activity-panel').getByText(/No files copied, disk writes, boot verification, or ejection performed/)).toBeVisible();
});

test('settings change the launcher preview and config can be exported', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.locator('nav').getByRole('button', { name: 'Configuration' }).click();
  await page.locator('[data-option="netboot"]').uncheck();
  await expect(page.getByRole('textbox', { name: 'Configuration source' })).toContainText('netboot_xyz: false');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export', exact: true }).click();
  expect((await downloadPromise).suggestedFilename()).toBe('isohopper.yml');
  await page.getByRole('button', { name: 'Validate', exact: true }).click();
  await expect(page.getByText(/Native schema validation is available in the desktop app/)).toBeVisible();
  await page.getByRole('textbox', { name: 'Configuration source' }).fill('boot: changed');
  await expect(page.locator('.config-result')).toHaveCount(0);
  await page.locator('nav').getByRole('button', { name: 'Launcher preview' }).click();
  await expect(page.getByRole('button', { name: /Network boot/ })).toHaveCount(0);
  await page.getByRole('button', { name: /recovery-toolkit-demo.img/ }).click();
  await expect(page.getByText(/Selected: recovery-toolkit-demo.img. This is a visual preview only./)).toBeVisible();
});

test('power settings control firmware preview actions and serialize in both formats', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.locator('nav').getByRole('button', { name: 'Configuration' }).click();
  await expect(page.locator('[data-power-option="reboot"]')).toBeChecked();
  await expect(page.locator('[data-power-option="shutdown"]')).toBeChecked();
  await expect(page.locator('[data-power-option="firmware_setup"]')).toBeChecked();
  await page.locator('[data-power-option="shutdown"]').uncheck();
  await expect(page.getByRole('textbox', { name: 'Configuration source' })).toContainText('  power:\n    reboot: true\n    shutdown: false\n    firmware_setup: true');
  await page.getByRole('button', { name: 'TOML', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Configuration source' })).toContainText('[launcher.power]\nreboot = true\nshutdown = false\nfirmware_setup = true');
  await page.locator('nav').getByRole('button', { name: 'Launcher preview' }).click();
  await expect(page.getByRole('button', { name: 'Reboot', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Shut down', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Firmware setup', exact: true })).toBeVisible();
  await expect(page.getByText('Requires firmware support', { exact: true })).toBeVisible();
  await page.locator('nav').getByRole('button', { name: 'Configuration' }).click();
  await page.locator('[data-power-option="reboot"]').uncheck();
  await page.locator('[data-power-option="firmware_setup"]').uncheck();
  await page.locator('nav').getByRole('button', { name: 'Launcher preview' }).click();
  await expect(page.locator('[data-power-preview]')).toHaveCount(0);
});

test('power preview clicks remain inert even with the native bridge available', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await page.locator('nav').getByRole('button', { name: 'Launcher preview' }).click();
  for (const name of ['Reboot', 'Shut down', 'Firmware setup']) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.locator('#toast')).toContainText(`${name}: preview only. No host action performed.`);
  }
  expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices']);
});

for (const outcome of ['image', 'cancel', 'error'] as const) {
  test(`native picker handles ${outcome} without using browser file intake`, async ({ page }) => {
    await installNativeBridge(page, { pickerOutcome: outcome });
    await page.goto('/');
    await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
    await expect(page.locator('.image-row')).toHaveCount(0);
    await openLibrary(page);
  await page.getByRole('button', { name: 'Add images', exact: true }).click();
    if (outcome === 'image') {
      const row = page.locator('.image-row').filter({ hasText: 'native-large.iso' });
      await expect(row).toContainText('6 GB');
      await expect(row).toContainText('Hash only');
      await expect(page.getByText('/private/media/native-large.iso', { exact: true })).toHaveCount(0);
    } else {
      await expect(page.locator('.image-row')).toHaveCount(0);
      if (outcome === 'error') await expect(page.getByRole('status')).toContainText('Native image selection failed');
    }
    await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
    expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices', 'pick_images']);
    await expect(page.getByRole('button', { name: 'Simulate preparation' })).toHaveCount(0);
  });
}

test('directory import preserves nested names and reports conflicting destinations and scan warnings', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Import folder', exact: true }).click();
  await expect(page.getByText('Mac/boot.iso', { exact: true })).toBeVisible();
  await expect(page.getByText('Windows/boot.iso', { exact: true })).toBeVisible();
  await expect(page.locator('.image-row')).toHaveCount(2);
  await expect(page.getByRole('status')).toContainText('Skipped symbolic link: external');
  await page.locator('nav').getByRole('button', { name: 'Activity' }).click();
  await expect(page.locator('.activity-panel').getByText('Directory import warning', { exact: true })).toBeVisible();
  await expect(page.locator('.activity-panel').getByText('Destination skipped', { exact: true })).toBeVisible();
  expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices', 'pick_directory', 'release_sources']);
});

test('host inventory stays read only and can be inspected and exported', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await expect(page.locator('#choose-drive')).toHaveCount(0);
  await page.getByRole('button', { name: 'Inspect host devices (read only)' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('host-system-unique-id', { exact: true })).toBeVisible();
  await expect(dialog.getByText('HOST-SERIAL-1234', { exact: true })).toBeVisible();
  await expect(dialog).toContainText('512,000,000,000 bytes');
  await expect(dialog).toContainText('Safety metadata is not complete.');
  await dialog.getByRole('button', { name: 'Export JSON' }).focus();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Copy device ID for Host system storage', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Copy serial for host-system-unique-id', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.locator('summary')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(dialog.locator('pre')).toContainText('"safety_checks_complete": false');
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Close host inventory' })).toBeFocused();
  const download = page.waitForEvent('download');
  await dialog.getByRole('button', { name: 'Export JSON' }).click();
  expect((await download).suggestedFilename()).toBe('isohopper-host-inventory.json');
  await dialog.getByRole('button', { name: 'Close host inventory' }).click();
  await expect(page.getByRole('button', { name: 'Inspect host devices (read only)' })).toBeFocused();
  await expect(page.locator('.target-panel')).toContainText('Preparation unavailable');
  await expect(page.locator('#choose-drive')).toHaveCount(0);
  expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices', 'inspect_devices']);
});

for (const failOnce of [false, true]) {
  test(`native removal ${failOnce ? 'retains state after failure and retries' : 'releases its opaque source ID'}`, async ({ page }) => {
    await installNativeBridge(page, { releaseFailures: failOnce ? 1 : 0 });
    await page.goto('/');
    await openLibrary(page);
  await page.getByRole('button', { name: 'Add images', exact: true }).click();
    const row = page.locator('.image-row').filter({ hasText: 'native-large.iso' });
    await expect(row).toContainText(`src_${'a'.repeat(64)}`);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await row.getByRole('button', { name: 'Remove native-large.iso' }).click();
    if (failOnce) {
      await expect(page.getByRole('status')).toContainText('collection retained');
      await expect(row).toBeVisible();
      await row.getByRole('button', { name: 'Remove native-large.iso' }).click();
    }
    await expect(row).toHaveCount(0);
    const releases = await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds);
    expect(releases).toEqual(Array.from({ length: failOnce ? 2 : 1 }, () => [`src_${'a'.repeat(64)}`]));
    await expectNoDemoContent(page);
  });
}

test('clear library releases remaining native sources in one batch after duplicate cleanup', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Import folder', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(2);
  await page.locator('nav').getByRole('button', { name: 'Image library' }).click();
  await page.getByRole('button', { name: 'Clear library', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(0);
  const releases = await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds);
  expect(releases).toEqual([[`src_${'d'.repeat(64)}`], [`src_${'b'.repeat(64)}`, `src_${'c'.repeat(64)}`]]);
  await expectNoDemoContent(page);
});

test('failed duplicate cleanup keeps an error row that can release its source on removal', async ({ page }) => {
  await installNativeBridge(page, { releaseFailures: 1 });
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Import folder', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(3);
  const row = page.locator('.image-row').filter({ has: page.locator('.source-id').getByText(`src_${'d'.repeat(64)}`, { exact: true }) });
  await expect(row).toContainText('source release failed');
  await row.getByRole('button', { name: 'Remove MAC/BOOT.ISO' }).click();
  await expect(row).toHaveCount(0);
  await expect(page.locator('.image-row')).toHaveCount(2);
  const releases = await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds);
  expect(releases).toEqual([[`src_${'d'.repeat(64)}`], [`src_${'d'.repeat(64)}`]]);
});


test('native reload restores retained source IDs and removed sources stay absent', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Add images', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(1);
  await page.reload();
  await openLibrary(page);
  const row = page.locator('.image-row').filter({ hasText: 'native-large.iso' });
  await expect(row).toContainText(`src_${'a'.repeat(64)}`);
  expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices']);
  await row.getByRole('button', { name: 'Remove native-large.iso' }).click();
  await expect(row).toHaveCount(0);
  await page.reload();
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await expect(page.locator('.image-row')).toHaveCount(0);
  await expectNoDemoContent(page);
});

test('native source listing failure stays visible and disables new imports without loading fixtures', async ({ page }) => {
  await installNativeBridge(page, { sourceListError: 'Source catalogue unavailable' });
  await page.goto('/?demo=1');
  await openLibrary(page);
  await expect(page.getByText(/Native source listing failed: Source catalogue unavailable/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Import folder', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Retry source listing', exact: true })).toBeEnabled();
  await expect(page.locator('.image-row')).toHaveCount(0);
  await expectNoDemoContent(page);
});


test('native Refresh recovers a source imported after the reload listing', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await page.reload();
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await expect(page.locator('.image-row')).toHaveCount(0);
  await page.evaluate(() => {
    const host = window as unknown as { publishNativeSource: (source: unknown) => void };
    host.publishNativeSource({ source_id: `src_${'e'.repeat(64)}`, name: 'late.iso', relative_path: 'Windows/late.iso', bytes: 3, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } });
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await openLibrary(page);
  const row = page.locator('.image-row').filter({ hasText: 'Windows/late.iso' });
  await expect(row).toContainText(`src_${'e'.repeat(64)}`);
  expect((await nativeCommands(page)).filter(command => command === 'list_sources')).toHaveLength(2);
  await expectNoDemoContent(page);
});

test('failed native Refresh preserves the existing source rows', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Add images', exact: true }).click();
  const row = page.locator('.image-row').filter({ hasText: 'native-large.iso' });
  await expect(row).toContainText(`src_${'a'.repeat(64)}`);
  await page.evaluate(() => { (window as unknown as { nativeSourceListError: string }).nativeSourceListError = 'Catalogue refresh failed'; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByText(/Native source listing failed: Catalogue refresh failed/)).toBeVisible();
  await expect(row).toContainText(`src_${'a'.repeat(64)}`);
  await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeDisabled();
  expect(await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds)).toEqual([]);
});


test('pending source refresh blocks Remove and Clear until its snapshot resolves', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Add images', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(1);
  await page.evaluate(() => (window as unknown as { pauseSourceListing: () => void }).pauseSourceListing());
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.locator('nav').getByRole('button', { name: 'Image library' }).click();
  const remove = page.getByRole('button', { name: 'Remove native-large.iso', exact: true });
  const clear = page.getByRole('button', { name: 'Clear library', exact: true });
  await expect(remove).toBeDisabled();
  await expect(clear).toBeDisabled();
  // Dispatch directly as well: the handlers must guard stale/programmatic events.
  await remove.dispatchEvent('click');
  await clear.dispatchEvent('click');
  expect(await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds)).toEqual([]);
  await page.evaluate(() => (window as unknown as { finishSourceListing: () => void }).finishSourceListing());
  await expect(remove).toBeEnabled();
  await expect(clear).toBeEnabled();
  await expect(page.locator('.image-row')).toHaveCount(1);
  expect(await page.evaluate(() => (window as unknown as { releasedSourceIds: string[][] }).releasedSourceIds)).toEqual([]);
});

test('library folder, status and filename filters work together without changing native sources', async ({ page }, testInfo) => {
  await installNativeBridge(page);
  await page.goto('/');
  await openLibrary(page);
  await page.getByRole('button', { name: 'Import folder', exact: true }).click();
  await expect(page.locator('.image-row')).toHaveCount(2);
  await page.locator('[data-library-folder="Windows"]').click();
  await expect(page.locator('.image-row')).toHaveCount(1);
  await expect(page.locator('.image-row')).toContainText('Windows/boot.iso');
  await page.locator('[data-library-status="hashed"]').click();
  await page.getByRole('searchbox', { name: 'Search images' }).fill('BOOT');
  await expect(page.locator('.image-row')).toHaveCount(1);
  await page.getByRole('searchbox', { name: 'Search images' }).fill('missing');
  await expect(page.getByText('No matching images.')).toBeVisible();
  await page.getByRole('searchbox', { name: 'Search images' }).fill('');
  await page.locator('[data-library-status="error"]').click();
  await expect(page.locator('.image-row')).toHaveCount(0);
  await page.locator('[data-library-status="all"]').click();
  await page.locator('[data-library-folder=""]').click();
  await expect(page.locator('.image-row')).toHaveCount(2);
  expect((await nativeCommands(page)).filter(command => command === 'release_sources')).toHaveLength(1);
  await page.screenshot({ path: `../../.local/release-work/studio-redesign-library-${testInfo.project.name}.png`, fullPage: true });
  await page.locator('nav').getByRole('button', { name: 'Launcher preview', exact: true }).click();
  await page.screenshot({ path: `../../.local/release-work/studio-redesign-launcher-populated-${testInfo.project.name}.png`, fullPage: true });
});

test('activity receipt preview and export share the same payload', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await page.locator('nav').getByRole('button', { name: 'Activity', exact: true }).click();
  const preview = JSON.parse((await page.locator('#activity-receipt').textContent())!);
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export activity', exact: true }).click();
  const stream = await (await downloadPromise).createReadStream();
  const chunks = [];
  for await (const chunk of stream!) chunks.push(chunk);
  const exported = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  expect(exported.exported_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  expect({ ...exported, exported_at: preview.exported_at }).toEqual(preview);
  await page.getByRole('button', { name: 'Clear activity', exact: true }).click();
  expect(JSON.parse((await page.locator('#activity-receipt').textContent())!).events).toEqual([]);
});

test('launcher keyboard selection and unique power shortcuts remain inert', async ({ page }) => {
  await installNativeBridge(page);
  await page.goto('/');
  await expect(page.locator('.target-panel')).toContainText('host-system-unique-id');
  await page.locator('nav').getByRole('button', { name: 'Launcher preview', exact: true }).click();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('[data-boot="1"]')).toBeFocused();
  await expect(page.locator('[data-boot="1"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('[data-boot="1"] .boot-marker')).toHaveText('›');
  await page.keyboard.press('Enter');
  await expect(page.locator('.launcher-selection')).toContainText('Memory diagnostics');
  await expect(page.locator('kbd').filter({ hasText: /^R$/ })).toHaveCount(1);
  await page.keyboard.press('r');
  await expect(page.locator('#toast')).toContainText('Reboot: preview only. No host action performed.');
  expect(await nativeCommands(page)).toEqual(['capabilities', 'list_sources', 'inspect_devices']);
});
