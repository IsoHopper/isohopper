// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import './style.css';
import { bridge, bridgeMode } from './bridge';
import { icon } from './icons';
import { nativeMediaImage, type HostInventory } from './native';
import { browserRelativePath, destinationKey, canSimulate, challengeFor, confirmationMatches, escapeHTML as esc, fileProblem, formatBytes, safeFileName, type DiskRecord, type DiskPlan, type MediaImage } from './state';

type Tab = 'prepare' | 'images' | 'settings' | 'activity' | 'launcher';
interface Log { time: string; title: string; detail: string; kind: 'info' | 'success' | 'warning' }
const app = document.querySelector<HTMLDivElement>('#app')!;
const nav: { id: Tab; label: string; icon: string }[] = [
  { id: 'prepare', label: 'Prepare drive', icon: 'drive' }, { id: 'images', label: 'Image library', icon: 'layers' },
  { id: 'settings', label: 'Configuration', icon: 'settings' }, { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'launcher', label: 'Launcher preview', icon: 'monitor' }
];
let tab: Tab = 'prepare';
let disks: DiskRecord[] = [];
let selected: DiskRecord | undefined;
let plan: DiskPlan | undefined;
let confirmation = '';
let deviceError = '';
let planError = '';
let planLoading = false;
let refreshing = false;
let busy = false;
let pickingImages = false;
let progress = 0;
let complete = false;
let runTitle = '';
let toast = '';
let toastTimer: ReturnType<typeof setTimeout>;
let deviceDialog = false;
let inventoryDialog = false;
let inspectingHost = false;
let hostInventory: HostInventory | undefined;
let inventoryError = '';
let query = '';
let configFormat = 'yaml';
let configResult = '';
let customConfig: string | undefined;
let launcherChoice = 0;
const powerLabels = { reboot: 'Reboot', shutdown: 'Shut down', firmware_setup: 'Firmware setup' } as const;
const options = { netboot: true, systemInfo: true, memtest: true, timeout: 10, theme: 'midnight', policy: 'enforce', power: { reboot: true, shutdown: true, firmware_setup: true } };
let images: MediaImage[] = bridge.PickImages ? [] : [
  { id: 'sample-linux', name: 'linux-desktop-demo.iso', size: 4_800_000_000, sample: true, status: 'sample' },
  { id: 'sample-recovery', name: 'recovery-toolkit-demo.img', size: 1_600_000_000, sample: true, status: 'sample' }
];
let logs: Log[] = [{ time: new Date().toISOString(), title: 'Session started', detail: 'Experimental build. All devices are fixtures; no physical disk writes are available.', kind: 'info' }];
const exactBytes = (bytes: number) => `${bytes.toLocaleString('en-GB')} bytes`;
const imagePath = (image: MediaImage) => image.relativePath || image.name;
const sumBytes = () => images.reduce((sum, image) => sum + image.size, 0);
const pendingImages = () => images.some(image => image.status === 'hashing' || image.status === 'error');
const runAllowed = () => !!plan && !planLoading && !planError && !pickingImages && !pendingImages() && canSimulate(selected, confirmation, sumBytes(), busy);
function log(title: string, detail: string, kind: Log['kind'] = 'info') { logs.unshift({ time: new Date().toISOString(), title, detail, kind }); }
function notify(message: string) { toast = message; clearTimeout(toastTimer); renderToast(); toastTimer = setTimeout(() => { toast = ''; renderToast(); }, 6000); }
function renderToast() { const node = document.querySelector('#toast'); if (node) { node.textContent = toast; node.classList.toggle('visible', !!toast); } }
function badge(state: string) { return state === 'ok' ? '<span class="badge teal">Eligible fixture</span>' : state === 'confirm' ? '<span class="badge amber">Review required</span>' : '<span class="badge red">Blocked</span>'; }
function deviceName(record?: DiskRecord) { return record ? esc(record.disk.model) : 'Choose a fixture drive'; }
function configText() {
  if (customConfig !== undefined) return customConfig;
  return configFormat === 'toml'
    ? `# IsoHopper configuration preview\n[boot]\nnetboot_xyz = ${options.netboot}\nsecure_boot_policy = "${options.policy}"\ntimeout = ${options.timeout}\ndefault = "last"\n\n[launcher]\nsystem_info = ${options.systemInfo}\nwarn_multi_disk = true\ntheme = "${options.theme}"\n\n[launcher.power]\nreboot = ${options.power.reboot}\nshutdown = ${options.power.shutdown}\nfirmware_setup = ${options.power.firmware_setup}\n\n[images]\nverify_hash = true\nverify_signature = "prefer"\n\n[extras]\nmemtest86plus = ${options.memtest}\n`
    : `# IsoHopper configuration preview\nboot:\n  netboot_xyz: ${options.netboot}\n  secure_boot_policy: ${options.policy}\n  timeout: ${options.timeout}\n  default: last\n\nlauncher:\n  system_info: ${options.systemInfo}\n  warn_multi_disk: true\n  theme: ${options.theme}\n  power:\n    reboot: ${options.power.reboot}\n    shutdown: ${options.power.shutdown}\n    firmware_setup: ${options.power.firmware_setup}\n\nimages:\n  verify_hash: true\n  verify_signature: prefer\n\nextras:\n  memtest86plus: ${options.memtest}\n`;
}
function render() {
  app.innerHTML = `<div class="app-shell">
    <aside class="sidebar"><a class="brand" href="#prepare" aria-label="IsoHopper home"><img src="./mark.svg" alt=""/><span>IsoHopper</span></a>
      <nav aria-label="Main navigation">${nav.map(item => `<button class="nav-item ${tab === item.id ? 'active' : ''}" data-tab="${item.id}" aria-label="${item.label}" title="${item.label}" ${tab === item.id ? 'aria-current="page"' : ''}>${icon(item.icon)}<span>${item.label}</span>${item.id === 'images' ? `<span class="nav-count">${images.length}</span>` : ''}</button>`).join('')}</nav>
      <div class="sidebar-version">v0.1 · GPL-3.0+</div>
    </aside>
    <div class="workspace">
      <div class="experimental">${icon('info')}<span>Experimental · mock devices · no physical disk writes</span><span class="source-mode">${bridgeMode}</span></div>
      <main id="main-content">${tab === 'prepare' ? prepareView() : tab === 'images' ? imagesView() : tab === 'settings' ? settingsView() : tab === 'activity' ? activityView() : launcherView()}</main>
    </div>
  </div><input id="file-input" type="file" accept=".iso,.img,.wim,.vhd,.vhdx,.efi" multiple hidden/><input id="folder-input" type="file" webkitdirectory multiple hidden/><div id="toast" class="toast" role="status" aria-live="polite"></div>${deviceDialog ? dialogView() : ''}${inventoryDialog ? inventoryView() : ''}`;
  bindEvents(); renderToast();
}
function titleBlock(_eyebrow: string, title: string, description: string, actions = '') { return `<div class="page-title"><div><h1>${title}</h1>${description ? `<p>${description}</p>` : ''}</div>${actions}</div>`; }
function prepareView() {
  return `${titleBlock('', 'Prepare media', 'Review images, target device and partition layout before running a simulation.')}
    <div class="prepare-grid"><div class="main-column"><section class="panel media-panel"><div class="panel-heading"><h2>Images <span class="count">${images.length}</span></h2><button class="text-button" data-tab="images">Open library</button></div>${dropZone()}<div class="image-list">${images.length ? imageTable(images) : '<div class="empty-inline">No images added.</div>'}</div><div class="panel-foot"><span>${images.some(image => image.sample) ? 'Sample entries are labels only. No sample files are loaded.' : 'SHA-256 fingerprints do not verify the publisher.'}</span>${!images.length ? '<button class="text-button" id="load-samples">Load samples</button>' : `<span>${formatBytes(sumBytes())} total</span>`}</div></section>
      <section class="panel options-panel"><div class="panel-heading"><h2>Configuration preview</h2><button class="text-button" data-tab="settings">Edit configuration</button></div>${optionRow('netboot', 'globe', 'Network boot', 'Include netboot.xyz in the configuration.', options.netboot)}${optionRow('systemInfo', 'monitor', 'System information', 'Show hardware details in the launcher preview.', options.systemInfo)}<div class="option-note">Secure Boot policy: <strong>${esc(options.policy)}</strong><span>Configuration only. Boot chain not implemented.</span></div></section>
    </div><aside class="detail-column">${targetPanel()}${layoutPanel()}</aside></div>`;
}
function dropZone() { return `<div class="add-images"><button class="secondary-button dropzone" id="dropzone" ${busy || pickingImages ? 'disabled' : ''}>${icon(pickingImages ? 'activity' : 'plus')}${pickingImages ? 'Reading selected images…' : 'Add images'}</button><button class="secondary-button" id="import-folder" ${busy || pickingImages ? 'disabled' : ''}>Import folder</button><span>${bridge.PickImages ? 'Native picker: Rust streaming SHA-256, no preview size cap. Browser drop: 512 MiB maximum.' : 'Browser intake: WebCrypto SHA-256; 512 MiB per file. Desktop picker streams larger files.'} Folder paths are relative to the selected directory.</span></div>`; }
function imageTable(items: MediaImage[]) { return `<table class="image-table"><thead><tr><th scope="col">Relative path</th><th scope="col">Size</th><th scope="col">Source</th><th scope="col">SHA-256</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>${items.map(imageRow).join('')}</tbody></table>`; }
function imageRow(image: MediaImage) {
  return `<tr class="image-row"><td class="image-name">${esc(imagePath(image))}</td><td class="size-cell">${formatBytes(image.size)}<small class="exact-value">${exactBytes(image.size)}</small></td><td>${image.sample ? 'Sample' : image.origin === 'native' ? 'Native' : 'Browser'}</td><td class="hash-cell">${image.sample ? '<span class="subtle">No file loaded</span>' : image.status === 'hashing' ? 'SHA-256: computing' : image.status === 'error' ? `<span class="error-text">${esc(image.error || 'Failed')}</span>` : `<code>${image.hash!}</code><small>Hash only · publisher not verified</small>`}</td><td class="row-actions">${image.hash ? `<button class="icon-button copy-hash" data-id="${image.id}" aria-label="Copy SHA-256 for ${esc(imagePath(image))}" title="Copy SHA-256">${icon('copy')}</button>` : ''}<button class="icon-button remove-image" data-id="${image.id}" aria-label="Remove ${esc(imagePath(image))}" title="Remove image" ${busy ? 'disabled' : ''}>${icon('close')}</button></td></tr>`;
}
function optionRow(key: string, _glyph: string, title: string, detail: string, checked: boolean) { return `<label class="option-row"><input class="toggle-input" type="checkbox" data-option="${key}" ${checked ? 'checked' : ''} ${busy ? 'disabled' : ''}/><span class="option-copy"><strong>${title}</strong><small>${detail}</small></span></label>`; }
function powerSettings() {
  return `<fieldset class="power-settings"><legend>Firmware power actions</legend><p>Controls visibility in the boot launcher. Studio preview does not control this computer.</p>${Object.entries(powerLabels).map(([key, label]) => `<label class="option-row"><input class="toggle-input" type="checkbox" data-power-option="${key}" ${options.power[key as keyof typeof options.power] ? 'checked' : ''}/><span class="option-copy"><strong>${label}</strong>${key === 'firmware_setup' ? '<small>Requires firmware support.</small>' : ''}</span></label>`).join('')}</fieldset>`;
}
function powerPreview() {
  const enabled = Object.entries(powerLabels).filter(([key]) => options.power[key as keyof typeof options.power]);
  if (!enabled.length) return '';
  return `<div class="launcher-power"><strong>Power</strong>${enabled.map(([key, label]) => `<div><button class="secondary-button" data-power-preview="${key}" aria-label="${label}">${label}</button>${key === 'firmware_setup' ? '<small>Requires firmware support</small>' : ''}</div>`).join('')}</div>`;
}
function targetPanel() {
  const disk = selected?.disk;
  const risks = selected?.verdict.risks || [];
  return `<section class="panel target-panel"><div class="panel-heading"><h2>Target device</h2><button class="text-button" id="refresh-drives" ${busy || refreshing ? 'disabled' : ''}>${refreshing ? 'Loading…' : 'Refresh'}</button></div>
    ${deviceError ? `<div class="error-notice">${esc(deviceError)}</div>` : ''}
    <button class="selected-drive" id="choose-drive" ${busy || refreshing ? 'disabled' : ''}><span><strong>${deviceName(selected)}</strong><small>Change fixture device</small></span>${icon('down')}</button>
    ${selected && disk ? `<div class="inventory-note">Inventory: built-in fixtures. No OS device enumeration.</div><div class="drive-facts"><span>Guard status</span>${badge(selected.verdict.state)}</div><dl class="device-details"><div><dt>Device ID</dt><dd>${esc(disk.id)}</dd></div><div><dt>Serial</dt><dd>${esc(disk.serial)}</dd></div><div><dt>Capacity</dt><dd>${formatBytes(disk.size_bytes)}<br/>${exactBytes(disk.size_bytes)}</dd></div><div><dt>Bus</dt><dd>${esc(disk.bus.toUpperCase())}</dd></div><div><dt>Logical sector</dt><dd>${disk.logical_sector_size} bytes</dd></div><div><dt>Physical sector</dt><dd>${typeof disk.physical_sector_size === 'number' && disk.physical_sector_size > 0 ? `${disk.physical_sector_size} bytes` : 'Not reported'}</dd></div><div><dt>Layout</dt><dd>GPT / exFAT (planned)</dd></div></dl>` : ''}
    ${disk?.bus === 'sd' ? '<div class="inline-note">SD boot support depends on target firmware.</div>' : ''}
    ${risks.length ? `<div class="risk-box"><strong>Confirmation required</strong><ul>${risks.map(risk => `<li><code>${esc(risk.code)}</code>: ${esc(risk.message)}</li>`).join('')}</ul><label for="confirmation">Type this phrase to enable simulation:</label><code class="challenge">${esc(challengeFor(selected!))}</code><input id="confirmation" value="${esc(confirmation)}" autocomplete="off" spellcheck="false" autocapitalize="characters" aria-label="Disk confirmation phrase" placeholder="Type the phrase above" ${busy ? 'disabled' : ''}/><small id="confirmation-status">${confirmationMatches(selected!, confirmation) ? 'Phrase matches this fixture.' : 'Paste disabled. Enter does not submit.'}</small></div>` : ''}
    ${complete ? `<div class="completion"><strong>Simulation complete</strong><small>No disk was opened or modified.</small></div>` : ''}
    ${busy ? `<div class="run-progress"><div><strong>${esc(runTitle)}</strong><span>${progress}%</span></div><progress value="${progress}" max="100" aria-label="Simulation progress"></progress></div>` : ''}
    <button class="primary-button" id="simulate" ${runAllowed() ? '' : 'disabled'}>${busy ? 'Simulation in progress' : complete ? 'Run simulation again' : 'Simulate preparation'}</button>
    <p class="action-note">No physical disk writes.</p>${bridge.InspectDevices ? `<button class="text-button inspect-host" id="inspect-host" ${inspectingHost ? 'disabled' : ''}>Inspect host devices (read only)</button>` : ''}${pendingImages() ? '<p class="inline-note">Finish hashing or remove failed images to continue.</p>' : ''}${selected && sumBytes() > selected.disk.size_bytes - 130 * 1024 * 1024 ? '<p class="error-notice">Images exceed available space.</p>' : ''}
  </section>`;
}
function layoutPanel() {
  const partitions = plan?.partitions || [];
  return `<section class="panel layout-panel"><div class="panel-heading"><h3>Partition plan</h3><span class="subtle">GPT / 1 MiB alignment</span></div>${planLoading ? '<p class="subtle">Calculating partition boundaries…</p>' : planError ? `<p class="error-notice">${esc(planError)}</p>` : plan ? `<div class="geometry"><div class="geometry-summary">Logical sector: ${plan.logical_sector_size} bytes<br/>Device: ${exactBytes(plan.size_bytes)}</div>${partitions.map(part => `<section class="partition-details"><h4>${esc(part.name)}</h4><dl><div><dt>Start LBA</dt><dd>${part.start_lba.toLocaleString('en-GB')}</dd></div><div><dt>End LBA</dt><dd>${part.end_lba.toLocaleString('en-GB')}</dd></div><div><dt>Sectors</dt><dd>${(part.end_lba - part.start_lba + 1).toLocaleString('en-GB')}</dd></div><div><dt>Size</dt><dd>${exactBytes((part.end_lba - part.start_lba + 1) * plan!.logical_sector_size)}</dd></div></dl></section>`).join('')}</div>` : '<p class="subtle">Choose a device to calculate the layout.</p>'}</section>`;
}
function imagesView() { const filtered = images.filter(image => imagePath(image).toLowerCase().includes(query.toLowerCase())); return `${titleBlock('', 'Images', 'Local SHA-256 fingerprints. Publisher verification is not connected.', `<button class="secondary-button" id="load-samples" ${busy ? 'disabled' : ''}>Load samples</button>`)}<section class="panel library-panel">${dropZone()}<div class="library-toolbar"><h2>Image library <span class="count">${images.length}</span></h2><label class="search-field">${icon('search')}<input id="image-search" type="search" value="${esc(query)}" aria-label="Search images" placeholder="Filter filenames"/></label></div><div class="image-list" id="filtered-images">${filtered.length ? imageTable(filtered) : '<div class="empty-inline">No matching images.</div>'}</div><div class="panel-foot"><span>Sample entries contain no files. Fingerprints are cleared on reload.</span><span>${formatBytes(sumBytes())} total</span></div></section>`; }
function settingsView() { return `${titleBlock('', 'Configuration', 'Edit and export YAML or TOML. Changes are not applied to a drive.')}<div class="settings-grid"><section class="panel"><div class="panel-heading"><h2>Boot settings</h2><span class="badge">Preview</span></div>${optionRow('netboot', 'globe', 'Include network boot', 'Add netboot.xyz to the planned boot menu.', options.netboot)}${optionRow('memtest', 'activity', 'Include memory test', 'Add a Memtest86+ entry to the preview.', options.memtest)}${optionRow('systemInfo', 'monitor', 'Show system information', 'Hardware details in the launcher preview.', options.systemInfo)}${powerSettings()}<label class="field-row"><span><strong>Boot timeout</strong><small>Seconds before default selection.</small></span><input id="timeout" type="number" min="0" max="300" value="${options.timeout}"/></label><label class="field-row"><span><strong>Secure Boot policy</strong><small>Configuration only; not enforced here.</small></span><select id="policy">${['enforce', 'prompt', 'off'].map(policy => `<option ${options.policy === policy ? 'selected' : ''}>${policy}</option>`).join('')}</select></label><label class="field-row"><span><strong>Launcher theme</strong><small>Used in the launcher preview.</small></span><select id="theme">${['midnight', 'aurora'].map(theme => `<option ${options.theme === theme ? 'selected' : ''}>${theme}</option>`).join('')}</select></label><div class="settings-note">${icon('info')} Boot payloads and security enforcement are not implemented.</div></section><section class="panel config-panel"><div class="panel-heading"><h2>Configuration source</h2><div class="segmented" aria-label="Configuration format"><button data-format="yaml" class="${configFormat === 'yaml' ? 'selected' : ''}">YAML</button><button data-format="toml" class="${configFormat === 'toml' ? 'selected' : ''}">TOML</button></div></div><div class="editor-label"><span class="status-dot"></span> isohopper.${configFormat === 'yaml' ? 'yml' : 'toml'}<span>LOCAL PREVIEW</span></div><textarea id="config-editor" aria-label="Configuration source" spellcheck="false">${esc(configText())}</textarea><div class="config-actions"><button class="secondary-button" id="validate-config">${icon('check')} Validate</button><button class="secondary-button" id="reset-config">Reset from settings</button><button class="primary-button compact" id="download-config">${icon('download')} Export</button></div>${configResult ? `<div class="config-result" role="status">${esc(configResult)}</div>` : ''}<p class="subtle editor-note">Changing form settings or format replaces manual edits. Export edits first.</p></section></div>`; }
function activityView() { return `${titleBlock('', 'Activity', 'Device selection, file hashing and simulation events for this session.', '<button class="secondary-button" id="export-activity">'+icon('download')+' Export activity</button>')}<section class="panel activity-panel"><div class="panel-heading"><h2>This session <span class="count">${logs.length}</span></h2><button class="text-button" id="clear-activity">Clear activity</button></div>${logs.length ? logs.map(item => `<article class="log-row"><span class="log-symbol ${item.kind}">[${item.kind === 'success' ? 'OK' : item.kind === 'warning' ? 'WARN' : 'INFO'}]</span><div><strong>${esc(item.title)}</strong><p>${esc(item.detail)}</p></div><time>${item.time}</time></article>`).join('') : '<div class="empty-state">No events.</div>'}</section>`; }
function launcherView() {
  const entries = [...images.map(image => ({ name: imagePath(image), detail: image.sample ? 'Sample entry · no file loaded' : 'Local fingerprint · boot unavailable', icon: 'image' })), ...(options.netboot ? [{ name: 'Network boot', detail: 'netboot.xyz · planned', icon: 'globe' }] : []), ...(options.memtest ? [{ name: 'Memory diagnostics', detail: 'Memtest86+ · planned', icon: 'activity' }] : [])];
  launcherChoice = Math.min(launcherChoice, Math.max(0, entries.length - 1));
  return `${titleBlock('', 'Launcher preview', 'Visual menu preview. Selecting an entry does not boot an image.', '<button class="secondary-button" data-tab="settings">Edit configuration</button>')}<section class="launcher-frame ${options.theme}"><div class="launcher-top"><strong>Boot menu</strong><span>Theme: ${esc(options.theme)} · Timeout: ${options.timeout}s</span></div><div class="launcher-body"><div class="launcher-menu"><div class="boot-entries">${entries.map((entry, index) => `<button data-boot="${index}" class="boot-entry ${index === launcherChoice ? 'chosen' : ''}"><span><strong>${esc(entry.name)}</strong><small>${esc(entry.detail)}</small></span>${index === launcherChoice ? icon('check') : ''}</button>`).join('') || '<div class="empty-inline">No entries configured.</div>'}</div><div class="launcher-selection" role="status">${entries.length ? `Selected: ${esc(entries[launcherChoice].name)}. This is a visual preview only.` : 'No entries configured.'}</div></div>${options.systemInfo ? `<aside class="system-card"><h3>System information (example)</h3><dl><div><dt>CPU</dt><dd>8 cores</dd></div><div><dt>Memory</dt><dd>16 GB</dd></div><div><dt>Firmware</dt><dd>UEFI</dd></div><div><dt>Secure Boot</dt><dd>Not detected</dd></div></dl><p>No host scan performed.</p></aside>` : ''}</div>${powerPreview()}</section>`;
}
function dialogView() { return `<div class="modal-backdrop"><section class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><div class="panel-heading"><div><h2 id="dialog-title">Choose a fixture drive</h2></div><button class="icon-button" id="close-dialog" aria-label="Close drive picker">${icon('close')}</button></div><p class="dialog-description">Synthetic devices only. No physical drives are scanned.</p><div class="device-list">${disks.map(record => `<div class="device-choice ${selected?.disk.id === record.disk.id ? 'selected' : ''} ${record.verdict.state === 'blocked' ? 'blocked' : ''}"><button data-disk="${esc(record.disk.id)}" ${record.verdict.state === 'blocked' ? 'disabled' : ''}><span class="drive-art">${icon(record.disk.bus === 'sd' ? 'sd' : record.verdict.state === 'blocked' ? 'lock' : 'drive')}</span><span class="device-choice-copy"><strong>${deviceName(record)}</strong><small>${formatBytes(record.disk.size_bytes)} / ${exactBytes(record.disk.size_bytes)} · ${esc(record.disk.bus.toUpperCase())}<br/>ID=${esc(record.disk.id)} · serial=${esc(record.disk.serial) || 'UNAVAILABLE'}<br/>logical=${record.disk.logical_sector_size} B · physical=${typeof record.disk.physical_sector_size === 'number' ? record.disk.physical_sector_size : 'unknown'} B</small></span>${badge(record.verdict.state)}${selected?.disk.id === record.disk.id ? icon('check') : ''}</button>${record.verdict.state === 'blocked' ? `<div class="blocked-reasons">${(record.verdict.hard_blocks || []).map(reason => `<span><code>${esc(reason.code)}</code>: ${esc(reason.message)}</span>`).join('')}</div>` : ''}</div>`).join('')}</div><div class="dialog-foot">${icon('shield')} Blocked fixtures cannot be selected or overridden.</div></section></div>`; }
function inventoryView() {
  return `<div class="modal-backdrop inventory-backdrop"><section class="inventory-dialog" role="dialog" aria-modal="true" aria-labelledby="inventory-title"><div class="panel-heading"><h2 id="inventory-title">Host devices — read only</h2><button class="icon-button" id="close-inventory" aria-label="Close host inventory">${icon('close')}</button></div><p class="dialog-description">Actual OS inventory. These records cannot be selected for preparation. Unknown safety metadata remains unknown.</p>${inspectingHost ? '<p class="inventory-status" role="status">Reading host inventory…</p>' : inventoryError ? `<p class="error-notice">${esc(inventoryError)}</p>` : hostInventory ? `<div class="inventory-toolbar"><code>source=${esc(hostInventory.source)} disks=${hostInventory.disks.length} warnings=${hostInventory.warnings.length}</code><button class="secondary-button" id="export-inventory">Export JSON</button></div>${hostInventory.warnings.length ? `<div class="inventory-warnings">${hostInventory.warnings.map(warning => `<p><code>${esc(warning.code)}${warning.disk_id ? ` [${esc(warning.disk_id)}]` : ''}</code> ${esc(warning.message)}</p>`).join('')}</div>` : ''}<div class="host-device-list">${hostInventory.disks.length ? hostInventory.disks.map(disk => `<article class="host-device"><h3>${esc(disk.model || disk.id)}</h3><dl class="device-details"><div><dt>Device ID</dt><dd>${esc(disk.id)}</dd></div><div><dt>Serial</dt><dd>${esc(disk.serial || 'Not reported')}</dd></div><div><dt>Capacity</dt><dd>${formatBytes(disk.size_bytes)} / ${exactBytes(disk.size_bytes)}</dd></div><div><dt>Bus</dt><dd>${esc(disk.bus || 'Unknown')}</dd></div><div><dt>Logical sector</dt><dd>${disk.logical_sector_size} bytes</dd></div><div><dt>Physical sector</dt><dd>${typeof disk.physical_sector_size === 'number' && disk.physical_sector_size > 0 ? `${disk.physical_sector_size} bytes` : 'Not reported'}</dd></div><div><dt>Safety complete</dt><dd>${typeof disk.safety_checks_complete === 'boolean' ? String(disk.safety_checks_complete) : 'Not reported'}</dd></div></dl><details><summary>All reported fields</summary><pre>${esc(JSON.stringify(disk, null, 2))}</pre></details></article>`).join('') : '<p class="empty-inline">No disks returned by the host adapter.</p>'}</div>` : ''}</section></div>`;
}
async function inspectHost() {
  if (!bridge.InspectDevices || inspectingHost) return;
  deviceDialog = false; inventoryDialog = true; inspectingHost = true; inventoryError = ''; render();
  document.querySelector<HTMLButtonElement>('#close-inventory')?.focus();
  try { hostInventory = await bridge.InspectDevices(); log('Host inventory read', `source=${hostInventory.source} disks=${hostInventory.disks.length} warnings=${hostInventory.warnings.length} read_only=true selectable=false`); }
  catch (error) { hostInventory = undefined; inventoryError = `Host inspection failed: ${errorMessage(error)}`; log('Host inventory failed', inventoryError, 'warning'); }
  finally { inspectingHost = false; render(); if (inventoryDialog) document.querySelector<HTMLButtonElement>('#close-inventory')?.focus(); }
}
function closeInventory() { inventoryDialog = false; render(); document.querySelector<HTMLButtonElement>('#inspect-host')?.focus(); }
function bindEvents() {
  document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(button => button.onclick = () => { tab = button.dataset.tab as Tab; render(); });
  document.querySelector('.brand')?.addEventListener('click', event => { event.preventDefault(); tab = 'prepare'; render(); });
  document.querySelector('#about-button')?.addEventListener('click', () => notify('IsoHopper v0.1 · GPL-3.0-or-later · Original source © 2026 S33G. Experimental mock workflow; no physical disk writes.'));
  document.querySelector('#inspect-host')?.addEventListener('click', inspectHost);
  document.querySelector('#close-inventory')?.addEventListener('click', closeInventory);
  document.querySelector('.inventory-backdrop')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeInventory(); });
  document.querySelector('#export-inventory')?.addEventListener('click', () => { if (hostInventory) download('isohopper-host-inventory.json', JSON.stringify(hostInventory, null, 2), 'application/json'); });
  document.querySelector('#choose-drive')?.addEventListener('click', () => { deviceDialog = true; render(); document.querySelector<HTMLButtonElement>('#close-dialog')?.focus(); });
  document.querySelector('#close-dialog')?.addEventListener('click', closeDialog);
  document.querySelector('.modal-backdrop:not(.inventory-backdrop)')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeDialog(); });
  document.querySelectorAll<HTMLButtonElement>('[data-disk]').forEach(button => button.onclick = async () => { const record = disks.find(item => item.disk.id === button.dataset.disk); if (!record || record.verdict.state === 'blocked' || busy) return; selected = record; confirmation = ''; complete = false; deviceDialog = false; log('Fixture selected', `id=${record.disk.id} serial=${record.disk.serial} model=${record.disk.model} bytes=${record.disk.size_bytes} bus=${record.disk.bus} logical_sector=${record.disk.logical_sector_size} physical_sector=${record.disk.physical_sector_size ?? 'unknown'} verdict=${record.verdict.state} risks=${(record.verdict.risks || []).map(reason => reason.code).join(',') || 'none'}`, record.verdict.state === 'confirm' ? 'warning' : 'info'); await loadPlan(); });
  document.querySelector('#refresh-drives')?.addEventListener('click', loadDevices);
  const confirmationInput = document.querySelector<HTMLInputElement>('#confirmation');
  if (confirmationInput) {
    confirmationInput.onpaste = event => { event.preventDefault(); notify('Type the phrase yourself to review this fixture.'); };
    confirmationInput.ondrop = event => event.preventDefault();
    confirmationInput.onkeydown = event => { if (event.key === 'Enter') event.preventDefault(); };
    confirmationInput.oninput = () => { confirmation = confirmationInput.value; document.querySelector<HTMLButtonElement>('#simulate')!.disabled = !runAllowed(); document.querySelector('#confirmation-status')!.textContent = confirmationMatches(selected!, confirmation) ? 'Phrase matches this fixture.' : 'Paste disabled. Enter does not submit.'; };
  }
  document.querySelector('#simulate')?.addEventListener('click', simulate);
  const dropzone = document.querySelector<HTMLButtonElement>('#dropzone');
  if (dropzone) { dropzone.onclick = () => void browseImages(); dropzone.ondragover = event => { event.preventDefault(); dropzone.classList.add('dragging'); }; dropzone.ondragleave = () => dropzone.classList.remove('dragging'); dropzone.ondrop = event => { event.preventDefault(); dropzone.classList.remove('dragging'); if (!busy) void addFiles(Array.from(event.dataTransfer?.files || [])); }; }
  document.querySelector('#import-folder')?.addEventListener('click', () => void browseImages('folder'));
  document.querySelector<HTMLInputElement>('#folder-input')!.onchange = event => void addFiles(Array.from((event.target as HTMLInputElement).files || []));
  document.querySelector<HTMLInputElement>('#file-input')!.onchange = event => void addFiles(Array.from((event.target as HTMLInputElement).files || []));
  bindImageActions();
  document.querySelectorAll<HTMLInputElement>('[data-option]').forEach(input => input.onchange = () => { (options as unknown as Record<string, boolean>)[input.dataset.option!] = input.checked; customConfig = undefined; configResult = ''; complete = false; render(); });
  document.querySelectorAll<HTMLInputElement>('[data-power-option]').forEach(input => input.onchange = () => { options.power[input.dataset.powerOption as keyof typeof options.power] = input.checked; customConfig = undefined; configResult = ''; complete = false; render(); });
  document.querySelectorAll<HTMLButtonElement>('[data-power-preview]').forEach(button => button.onclick = () => { const action = button.dataset.powerPreview as keyof typeof powerLabels; notify(`${powerLabels[action]}: preview only. No host action performed.`); });
  document.querySelector('#load-samples')?.addEventListener('click', () => { if (busy) return; if (!images.some(image => image.id === 'sample-linux')) images.push({ id: 'sample-linux', name: 'linux-desktop-demo.iso', size: 4_800_000_000, sample: true, status: 'sample' }); if (!images.some(image => image.id === 'sample-recovery')) images.push({ id: 'sample-recovery', name: 'recovery-toolkit-demo.img', size: 1_600_000_000, sample: true, status: 'sample' }); complete = false; log('Sample manifest loaded', 'Two illustrative entries. No image data loaded or downloaded.'); render(); });
  document.querySelector<HTMLInputElement>('#image-search')?.addEventListener('input', event => { query = (event.target as HTMLInputElement).value; const filtered = images.filter(image => imagePath(image).toLowerCase().includes(query.toLowerCase())); document.querySelector('#filtered-images')!.innerHTML = filtered.length ? imageTable(filtered) : '<div class="empty-inline">No matching images.</div>'; bindImageActions(); });
  document.querySelectorAll<HTMLButtonElement>('[data-format]').forEach(button => button.onclick = () => { configFormat = button.dataset.format!; customConfig = undefined; configResult = ''; render(); });
  document.querySelector<HTMLTextAreaElement>('#config-editor')?.addEventListener('input', event => { customConfig = (event.target as HTMLTextAreaElement).value; configResult = ''; document.querySelector('.config-result')?.remove(); });
  document.querySelector<HTMLInputElement>('#timeout')?.addEventListener('change', event => { options.timeout = Math.max(0, Math.min(300, Number((event.target as HTMLInputElement).value) || 0)); customConfig = undefined; configResult = ''; render(); });
  for (const key of ['policy', 'theme'] as const) document.querySelector<HTMLSelectElement>(`#${key}`)?.addEventListener('change', event => { options[key] = (event.target as HTMLSelectElement).value; customConfig = undefined; configResult = ''; render(); });
  document.querySelector('#validate-config')?.addEventListener('click', async () => { const text = configText(); const format = configFormat; try { const result = await bridge.CheckConfig(text, format); if (text !== configText() || format !== configFormat) return; configResult = result.valid ? `Native schema validation: valid.${result.warnings?.length ? ` Warnings: ${result.warnings.join('; ')}` : ' No warnings.'} Boot chain not validated.` : result.error || 'Configuration did not pass validation.'; log(result.valid ? 'Configuration validated' : 'Configuration validation result', configResult, result.valid ? 'success' : 'warning'); } catch (error) { configResult = `Validation unavailable: ${errorMessage(error)}`; } render(); });
  document.querySelector('#reset-config')?.addEventListener('click', () => { customConfig = undefined; configResult = ''; render(); });
  document.querySelector('#download-config')?.addEventListener('click', () => { download(`isohopper.${configFormat === 'yaml' ? 'yml' : 'toml'}`, configText(), 'text/plain'); log('Configuration exported', `Downloaded the ${configFormat.toUpperCase()} preview. No target drive was modified.`); notify('Configuration preview exported.'); });
  document.querySelector('#export-activity')?.addEventListener('click', () => download('isohopper-session.json', JSON.stringify({ experimental: true, physical_disk_writes: false, events: logs }, null, 2), 'application/json'));
  document.querySelector('#clear-activity')?.addEventListener('click', () => { logs = []; render(); });
  document.querySelectorAll<HTMLButtonElement>('[data-boot]').forEach(button => button.onclick = () => { launcherChoice = Number(button.dataset.boot); render(); document.querySelector<HTMLButtonElement>(`[data-boot="${launcherChoice}"]`)?.focus(); });
}
function bindImageActions() {
  document.querySelectorAll<HTMLButtonElement>('.remove-image').forEach(button => button.onclick = () => { if (busy) return; const image = images.find(item => item.id === button.dataset.id); if (!image) return; images = images.filter(item => item.id !== image.id); complete = false; log('Image removed from collection', imagePath(image)); render(); });
  document.querySelectorAll<HTMLButtonElement>('.copy-hash').forEach(button => button.onclick = async () => { const image = images.find(item => item.id === button.dataset.id); if (!image?.hash) return; try { await navigator.clipboard.writeText(image.hash); notify(`SHA-256 copied: ${image.hash}`); } catch { notify('Clipboard access failed. Select and copy the full checksum from the table.'); } });
}
function closeDialog() { deviceDialog = false; render(); document.querySelector<HTMLButtonElement>('#choose-drive')?.focus(); }
document.addEventListener('keydown', event => { if (!deviceDialog && !inventoryDialog) return; if (event.key === 'Escape') { if (inventoryDialog) closeInventory(); else closeDialog(); } if (event.key === 'Tab') { const dialog = document.querySelector(inventoryDialog ? '.inventory-dialog' : '.device-dialog'); const items = Array.from(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), summary') || []); const first = items[0]; const last = items[items.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); } } });
async function loadDevices() {
  if (busy || refreshing) return;
  refreshing = true; deviceError = ''; confirmation = ''; complete = false; render();
  try { disks = await bridge.ListDisks(); selected = disks.find(record => record.disk.id === selected?.disk.id && record.verdict.state !== 'blocked') || disks.find(record => record.verdict.state === 'ok'); log('Fixture devices refreshed', `source=fixtures count=${disks.length} devices=${disks.map(record => `${record.disk.id}:${record.verdict.state}`).join(', ')} host_enumeration=false`); }
  catch (error) { disks = []; selected = undefined; plan = undefined; deviceError = `Device list unavailable: ${errorMessage(error)}`; log('Device list unavailable', deviceError, 'warning'); }
  refreshing = false; await loadPlan();
}
async function loadPlan() {
  const id = selected?.disk.id; plan = undefined; planError = ''; planLoading = !!id; render();
  if (!id) return;
  try { const next = await bridge.PlanDisk(id); if (selected?.disk.id !== id) return; plan = next; log('Partition plan calculated', `id=${id} bytes=${next.size_bytes} sector_size=${next.logical_sector_size} partitions=${next.partitions.map(part => `${part.name}[${part.start_lba}..${part.end_lba}]`).join(', ')} physical_writes=0`); }
  catch (error) { if (selected?.disk.id !== id) return; planError = `Layout unavailable: ${errorMessage(error)}`; }
  finally { if (selected?.disk.id === id) { planLoading = false; render(); } }
}
async function browseImages(mode: 'files' | 'folder' = 'files') {
  if (busy || pickingImages) return;
  const picker = mode === 'folder' ? bridge.PickDirectory : bridge.PickImages;
  if (!picker) { document.querySelector<HTMLInputElement>(mode === 'folder' ? '#folder-input' : '#file-input')?.click(); return; }
  pickingImages = true; complete = false; render();
  try {
    const selection = await picker();
    const picked = Array.isArray(selection) ? selection : selection.images;
    const warnings = Array.isArray(selection) ? [] : selection.warnings;
    for (const warning of warnings) log('Directory import warning', warning, 'warning');
    let added = 0;
    for (const record of picked) {
      const image = nativeMediaImage(record, crypto.randomUUID());
      if (images.some(existing => !existing.sample && destinationKey(existing) === destinationKey(image))) { log('Destination skipped', `path=${imagePath(image)} reason=destination-already-present`, 'warning'); continue; }
      images.push(image); added++;
      log('Native SHA-256 calculated', `path=${imagePath(image)} bytes=${image.size} source=native algorithm=SHA-256 status=hash-only digest=${image.hash} publisher_verified=false`, 'success');
    }
    if (warnings.length) notify(`${added} images added; ${warnings.length} directory warning(s). ${warnings[0]} See Activity for all warnings.`);
    else if (picked.length) notify(`${added} image${added === 1 ? '' : 's'} added. SHA-256 only; publisher not verified.`);
  } catch {
    const message = 'Native image selection failed. Check that the selected files are readable.';
    log('Image selection failed', message, 'warning'); notify(message);
  } finally { pickingImages = false; render(); }
}
async function addFiles(files: File[]) {
  if (busy || pickingImages) return;
  complete = false;
  for (const file of files) {
    const name = safeFileName(file.name); let relativePath: string;
    try { relativePath = browserRelativePath(file.webkitRelativePath || '', file.name); } catch (error) { notify(`Invalid relative image path: ${errorMessage(error)}`); log('Image path rejected', errorMessage(error), 'warning'); continue; }
    const problem = fileProblem(file);
    if (problem) { notify(`${name}: ${problem}`); log('Image not added', `${name}: ${problem}`, 'warning'); continue; }
    if (images.some(image => !image.sample && destinationKey(image) === destinationKey({ name, relativePath }))) { notify(`Destination already present: ${relativePath}`); log('Destination skipped', `path=${relativePath} reason=destination-already-present`, 'warning'); continue; }
    const image: MediaImage = { id: crypto.randomUUID(), name, relativePath, size: file.size, sample: false, origin: 'browser', status: 'hashing' };
    images.push(image); render();
    try { const hash = await crypto.subtle.digest('SHA-256', await file.arrayBuffer()); if (!images.includes(image)) continue; image.hash = Array.from(new Uint8Array(hash)).map(value => value.toString(16).padStart(2, '0')).join(''); image.status = 'hashed'; log('Local fingerprint calculated', `path=${imagePath(image)} bytes=${image.size} source=browser algorithm=SHA-256 status=hash-only digest=${image.hash} publisher_verified=false`, 'success'); }
    catch (error) { image.status = 'error'; image.error = errorMessage(error); log('Fingerprint failed', `${name}: ${image.error}`, 'warning'); }
    render();
  }
}
async function simulate() {
  if (!runAllowed() || !selected) return;
  busy = true; complete = false; progress = 0;
  const chosen = selected; const total = sumBytes();
  log('Preparation simulation started', `mode=simulation target_id=${chosen.disk.id} serial=${chosen.disk.serial} target_bytes=${chosen.disk.size_bytes} manifest_entries=${images.length} manifest_bytes=${total} disk_io=false`);
  const steps = [[15, 'Reviewing fixture identity'], [35, 'Modeling the partition layout'], [60, 'Inspecting the image manifest'], [85, 'Exercising progress events'], [100, 'Simulation complete']] as const;
  for (const [percent, title] of steps) { runTitle = title; progress = percent; log('Simulation stage', `status=simulated progress=${percent}% stage=${title} disk_io=false`); render(); await new Promise(resolve => setTimeout(resolve, 650)); }
  busy = false; complete = true; confirmation = '';
  log('Preparation simulation complete', `target_id=${chosen.disk.id} serial=${chosen.disk.serial} status=simulation-complete files_copied=0 bytes_written=0. No files copied, disk writes, boot verification, or ejection performed.`, 'success'); render(); notify('Simulation complete. No physical disk was modified.');
}
function download(name: string, content: string, type: string) { const url = URL.createObjectURL(new Blob([content], { type })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
function errorMessage(error: unknown) { return error instanceof Error ? error.message : String(error); }
render(); void loadDevices();
