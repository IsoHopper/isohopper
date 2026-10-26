// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, test } from '@playwright/test';

test('starts with an honest mock-device workspace and no horizontal overflow', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Experimental · mock devices · no physical disk writes')).toBeVisible();
  await expect(page.locator('header')).toHaveCount(0);
  await expect(page.locator('.experimental')).toContainText('Browser file I/O · demo hardware inventory');
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeEnabled();
  await expect(page.getByText('Sample entries are labels only. No sample files are loaded.')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('risk confirmation binds to the selected device and Enter does not start a run', async ({ page }) => {
  await page.goto('/');
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
  await page.goto('/');
  await page.locator('#choose-drive').click();
  await page.getByRole('dialog').getByRole('button', { name: /USB NVMe bridge 1 TB/ }).click();
  const input = page.getByRole('textbox', { name: 'Disk confirmation phrase' });
  const allowed = await input.evaluate(element => element.dispatchEvent(new ClipboardEvent('paste', { cancelable: true, bubbles: true })));
  expect(allowed).toBe(false);
  await expect(input).toHaveValue('');
});

test('hashes actual local data without treating it as publisher verification', async ({ page }) => {
  await page.goto('/');
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
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeEnabled();
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
  for (const view of ['Prepare drive', 'Image library']) {
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
  await page.goto('/');
  await page.locator('#file-input').setInputFiles({ name: 'program.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  await expect(page.getByRole('status')).toContainText('Unsupported format');
  await expect(page.locator('.image-row').filter({ hasText: 'program.exe' })).toHaveCount(0);
  await page.locator('#file-input').setInputFiles({ name: '<svg onload=alert(1)>.iso', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  await expect(page.getByText('<svg onload=alert(1)>.iso', { exact: true })).toBeVisible();
  await expect(page.locator('[onload]')).toHaveCount(0);
});

test('completes a simulation and records what did and did not happen', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Simulate preparation' }).click();
  await expect(page.getByRole('button', { name: 'Simulation in progress' })).toBeDisabled();
  await expect(page.getByText('No disk was opened or modified.')).toBeVisible();
  await page.locator('nav').getByRole('button', { name: 'Activity' }).click();
  await expect(page.getByText('Preparation simulation complete')).toBeVisible();
  await expect(page.getByText(/No files copied, disk writes, boot verification, or ejection performed/)).toBeVisible();
});

test('settings change the launcher preview and config can be exported', async ({ page }) => {
  await page.goto('/');
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

test('native bridge errors are visible and do not silently select browser fixtures', async ({ page }) => {
  await page.addInitScript(() => {
    (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke: async () => { throw new Error('fixture provider unavailable'); } } };
  });
  await page.goto('/');
  await expect(page.getByText(/Device list unavailable: fixture provider unavailable/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Simulate preparation' })).toBeDisabled();
});

test('power settings control firmware preview actions and serialize in both formats', async ({ page }) => {
  await page.goto('/');
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
  await page.addInitScript(() => {
    const host = window as unknown as { __TAURI__: unknown; previewCommands: string[] };
    host.previewCommands = [];
    host.__TAURI__ = { core: { invoke: async (command: string) => {
      host.previewCommands.push(command);
      if (command === 'list_disks') return [];
      throw new Error(`Unexpected native operation: ${command}`);
    } } };
  });
  await page.goto('/');
  await page.locator('nav').getByRole('button', { name: 'Launcher preview' }).click();
  for (const name of ['Reboot', 'Shut down', 'Firmware setup']) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.locator('#toast')).toContainText(`${name}: preview only. No host action performed.`);
  }
  expect(await page.evaluate(() => (window as unknown as { previewCommands: string[] }).previewCommands)).toEqual(['list_disks']);
});

for (const outcome of ['image', 'cancel', 'error'] as const) {
  test(`native picker handles ${outcome} without using browser file intake`, async ({ page }) => {
    await page.addInitScript(({ outcome }) => {
      (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke: async (command: string) => {
        if (command === 'list_disks') return [{ disk: { id: 'usb-64gb', serial: 'USB64-ABCD', model: 'USB flash drive 64 GB', bus: 'usb', size_bytes: 64_000_000_000, logical_sector_size: 512 }, verdict: { state: 'ok', hard_blocks: [], risks: [] } }];
        if (command === 'plan_disk') return { size_bytes: 64_000_000_000, logical_sector_size: 512, partitions: [{ name: 'ISOHOPPER', start_lba: 2048, end_lba: 124_737_855 }] };
        if (command === 'pick_images') {
          if (outcome === 'error') throw new Error('file read failed');
          if (outcome === 'cancel') return [];
          return [{ name: '/private/media/native-large.iso', bytes: 6_000_000_000, verification: { algorithm: 'sha256', digest: 'a'.repeat(64), bytes: 6_000_000_000, status: 'hash-only', publisher_verified: false } }];
        }
        return { valid: true };
      } } };
    }, { outcome });
    await page.goto('/');
    await page.getByRole('button', { name: 'Add images', exact: true }).click();
    if (outcome === 'image') {
      const row = page.locator('.image-row').filter({ hasText: 'native-large.iso' });
      await expect(row).toContainText('6 GB');
      await expect(row).toContainText('Hash only');
      await expect(page.getByText('/private/media/native-large.iso', { exact: true })).toHaveCount(0);
    } else {
      await expect(page.locator('.image-row')).toHaveCount(2);
      if (outcome === 'error') await expect(page.getByRole('status')).toContainText('Native image selection failed');
    }
    await expect(page.getByRole('button', { name: 'Add images', exact: true })).toBeEnabled();
  });
}

test('directory import preserves nested names and reports conflicting destinations and scan warnings', async ({ page }) => {
  await page.addInitScript(() => {
    const image = (relative_path: string) => ({ name: 'boot.iso', relative_path, bytes: 3, verification: { algorithm: 'sha256', digest: 'b'.repeat(64), bytes: 3, status: 'hash-only', publisher_verified: false } });
    (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke: async (command: string) => {
      if (command === 'list_disks') return [];
      if (command === 'pick_directory') return { images: [image('Mac/boot.iso'), image('Windows/boot.iso'), image('MAC/BOOT.ISO')], warnings: ['Skipped symbolic link: external'] };
      return [];
    } } };
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Import folder', exact: true }).click();
  await expect(page.getByText('Mac/boot.iso', { exact: true })).toBeVisible();
  await expect(page.getByText('Windows/boot.iso', { exact: true })).toBeVisible();
  await expect(page.locator('.image-row')).toHaveCount(4);
  await expect(page.getByRole('status')).toContainText('Skipped symbolic link: external');
  await page.locator('nav').getByRole('button', { name: 'Activity' }).click();
  await expect(page.getByText('Directory import warning')).toBeVisible();
  await expect(page.getByText('Destination skipped')).toBeVisible();
});

test('host inventory is read only and stays separate from fixture preparation', async ({ page }) => {
  await page.addInitScript(() => {
    (window as unknown as { __TAURI__: unknown }).__TAURI__ = { core: { invoke: async (command: string) => {
      if (command === 'list_disks') return [];
      if (command === 'inspect_devices') return { source: 'test-host-adapter', disks: [{ id: 'host-system-unique-id', serial: 'HOST-SERIAL-1234', model: 'Host system storage', bus: 'nvme', size_bytes: 512_000_000_000, logical_sector_size: 512, physical_sector_size: 4096, safety_checks_complete: false }], warnings: [{ disk_id: 'host-system-unique-id', code: 'safety_unknown', message: 'Safety metadata is not complete.' }] };
      return [];
    } } };
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Inspect host devices (read only)' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('host-system-unique-id', { exact: true })).toBeVisible();
  await expect(dialog.getByText('HOST-SERIAL-1234', { exact: true })).toBeVisible();
  await expect(dialog).toContainText('512,000,000,000 bytes');
  await expect(dialog).toContainText('Safety metadata is not complete.');
  await dialog.getByRole('button', { name: 'Export JSON' }).focus();
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
  await page.locator('#choose-drive').click();
  await expect(page.getByRole('dialog')).not.toContainText('host-system-unique-id');
});
