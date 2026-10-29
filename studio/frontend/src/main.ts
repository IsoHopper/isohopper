// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import './style.css';
import { bridge, bridgeMode, initialImages, isDemo, isNative, nativeHost } from './bridge';
import { defaultPreparationTarget, preparationTargetHint, visiblePreparationTargets, canConfirmPreparation, type EngineArchive, type PreparationTarget, type PreparationSnapshot } from './preparation';
import { icon } from './icons';
import type { EngineDownloadSnapshot } from './engine_download';
import { parsePreferences, preferencesKey, type StudioPreferences } from './preferences';
import { mergeNativeImages, removeMediaImages } from './image_lifecycle';
import { nativeImageForDisplay, inspectionRecords, preparationUnavailable, type HostInventory, type StudioCapabilities } from './native';
import { browserRelativePath, destinationKey, canSimulate, challengeFor, confirmationMatches, escapeHTML as esc, fileProblem, formatBytes, safeFileName, type DiskRecord, type DiskPlan, type MediaImage } from './state';

type Tab = 'prepare' | 'images' | 'settings' | 'activity' | 'launcher';
interface Log { time: string; title: string; detail: string; kind: 'info' | 'success' | 'warning' }
const app = document.querySelector<HTMLDivElement>('#app')!;
const savedPreferences = readPreferences();
const nav: { id: Tab; label: string; icon: string }[] = [
  { id: 'prepare', label: 'Prepare drive', icon: 'drive' }, { id: 'images', label: 'Image library', icon: 'layers' },
  { id: 'settings', label: 'Configuration', icon: 'settings' }, { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'launcher', label: 'Launcher preview', icon: 'monitor' }
];
let tab: Tab = 'prepare';
let capabilities: StudioCapabilities | undefined;
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
let releasingImages = false;
let sourcesLoaded = false;
let sourcesLoading = false;
let sourcesError = '';
let sourceRestoreWarnings: string[] = [];
let progress = 0;
let complete = false;
let runTitle = '';
let toast = '';
let toastTimer: ReturnType<typeof setTimeout>;
let deviceDialog = false;
let inventoryDialog = false;
let inspectingHost = false;
let probingHelper = false;
let helperStatus = '';
let engineArchive: EngineArchive | null = null;
let engineAdvanced = false;
let engineDownloadJob: EngineDownloadSnapshot | null = null;
let engineDownloadLoaded = false;
let engineDownloadRequest = false;
let engineDownloadSyncing = false;
let engineDownloadCancelling = false;
let engineDownloadPolling = false;
let engineDownloadError = '';
let engineDownloadStatusError = false;
let engineSelectionJob: string | undefined;
let engineDownloadTimer: ReturnType<typeof setTimeout> | undefined;
let preparationTargets: PreparationTarget[] = [];
let preparationTarget = '';
let targetHint = savedPreferences.targetHint;
let showLargeDrives = savedPreferences.showLargeDrives;
let preferenceWriteWarning = false;
let preparationJob: PreparationSnapshot | null = null;
let preparationError = '';
let preparationPhrase = '';
let preparationRequest = false;
let installationRequested = false;
let preparationEditing = false;
let preparationConfirming = false;
let preparationPolling = false;
let preparationTimer: ReturnType<typeof setTimeout> | undefined;
let hostInventory: HostInventory | undefined;
let inventoryError = '';
let query = '';
let configFormat = savedPreferences.configFormat;
let configResult = '';
let customConfig = savedPreferences.customConfig;
let launcherChoice = 0;
const powerLabels = { reboot: 'Reboot', shutdown: 'Shut down', firmware_setup: 'Firmware setup' } as const;
const options = savedPreferences.options;
let images: MediaImage[] = initialImages;
let logs: Log[] = [{ time: new Date().toISOString(), title: 'Session started', detail: `${bridgeMode}. Awaiting runtime capabilities.`, kind: 'info' }];
const engineDownloadLocked = () => capabilities?.engine_download === true && (!engineDownloadLoaded || engineDownloadRequest || engineDownloadSyncing || engineDownloadJob?.active === true);
// These actions share the native operation guard, including read-only inventory.
const nativeActionsLocked = () => engineDownloadLocked() || busy || preparationRequest || pickingImages || releasingImages || sourcesLoading || refreshing || probingHelper || inspectingHost;
const canImport = () => !nativeActionsLocked() && capabilities?.file_import === true && (!isNative || (sourcesLoaded && !sourcesError));
const exactBytes = (bytes: number) => `${bytes.toLocaleString('en-GB')} bytes`;
const physicalPreparationEnabled = () => isNative && capabilities?.physical_preparation === true;
const preparationConfirmationAllowed = () => !engineDownloadLocked() && !preparationConfirming && canConfirmPreparation(preparationJob, preparationPhrase, physicalPreparationEnabled());
const runtimeDescription = () => isDemo ? 'Explicit browser demo; mock devices; no physical disk writes.' : physicalPreparationEnabled() ? 'Experimental physical preparation enabled; exact device confirmation required.' : capabilities?.preparation_available ? 'Native image staging available; physical writing disabled.' : 'Physical preparation unavailable.';
const imagePath = (image: MediaImage) => image.relativePath || image.name;
const sumBytes = () => images.reduce((sum, image) => sum + image.size, 0);
const pendingImages = () => images.some(image => image.status === 'hashing' || image.status === 'error');
const runAllowed = () => isDemo && !!plan && !planLoading && !planError && !pickingImages && !releasingImages && !pendingImages() && canSimulate(selected, confirmation, sumBytes(), busy);
function readPreferences(): StudioPreferences {
  try { return parsePreferences(localStorage.getItem(preferencesKey)); }
  catch { return parsePreferences(null); }
}
function savePreferences() {
  // Persist only presentation settings and a device identity hint. Live native
  // source/archive/target tokens and write confirmations remain session-only.
  const preferences = parsePreferences(JSON.stringify({ version: 1, options, configFormat, customConfig, showLargeDrives, targetHint }));
  try { localStorage.setItem(preferencesKey, JSON.stringify(preferences)); }
  catch { if (!preferenceWriteWarning) { preferenceWriteWarning = true; notify('Settings could not be saved locally. Export configuration before closing.'); } }
}
function setPreparationTargets(next: PreparationTarget[]) {
  const previous = preparationTargets.find(item => item.selection_token === preparationTarget);
  preparationTarget = defaultPreparationTarget(next, preparationTarget, preparationTargetHint(previous) || targetHint);
  preparationTargets = next;
}
function preparationTargetLabel(target: PreparationTarget): string {
  return `${esc(target.display_id)} · ${esc(target.disk.friendly_name || 'Unnamed')}${target.volume_labels?.length ? ` · ${target.volume_labels.map(esc).join(', ')}` : ''} · ${target.disk.size === null ? 'unknown size' : formatBytes(target.disk.size)}`;
}
function preparationPrerequisites() {
  const target = preparationTargets.find(item => item.selection_token === preparationTarget);
  const next = deviceError ? 'Refresh device information before continuing.' : engineDownloadLocked() ? 'Wait for the verified engine download, or cancel it.' : busy || preparationRequest ? 'Installation preparation in progress.' : sourcesLoading ? 'Wait for the current library operation.' : refreshing ? 'Wait for device information to refresh.' : probingHelper ? 'Wait for the elevated helper check to finish.' : inspectingHost ? 'Wait for host inspection to finish.' : !target ? 'Choose a target device.' : pickingImages || releasingImages ? 'Wait for the current library operation.' : !engineArchive && capabilities?.engine_download !== true ? 'Choose the pinned engine archive in Advanced.' : 'Ready. Windows will ask for elevation. You will review the exact device before any write.';
  return `<dl class="preparation-prerequisites"><div><dt>Engine</dt><dd>${engineArchive ? `Verified ${esc(engineArchive.version)}` : capabilities?.engine_download === true ? 'Downloaded and verified when you continue' : 'Required'}</dd></div><div><dt>Target</dt><dd>${target ? `${esc(target.disk.friendly_name || target.display_id)} · candidate` : 'Required'}</dd></div><div><dt>Install</dt><dd>Empty bootable drive</dd></div></dl><p>${esc(next)}</p>`;
}
function log(title: string, detail: string, kind: Log['kind'] = 'info') { logs.unshift({ time: new Date().toISOString(), title, detail, kind }); }
function notify(message: string) { toast = message; clearTimeout(toastTimer); renderToast(); toastTimer = setTimeout(() => { toast = ''; renderToast(); }, 6000); }
function renderToast() { const node = document.querySelector('#toast'); if (node) { node.textContent = toast; node.classList.toggle('visible', !!toast); } }
function copyButton(value: string, label: string) {
  return `<button type="button" class="icon-button copy-button" data-copy-value="${esc(JSON.stringify(value))}" data-copy-label="${esc(label)}" aria-label="Copy ${esc(label)}" title="Copy ${esc(label)}">${icon('copy')}</button>`;
}
function copyable(value: string, label: string, className = '') {
  return `<span class="copy-value ${className}"><code>${esc(value)}</code>${copyButton(value, label)}</span>`;
}
function bindCopyEvents() {
  document.querySelectorAll<HTMLButtonElement>('[data-copy-value]').forEach(button => button.onclick = async () => {
    try {
      const value: string = JSON.parse(button.dataset.copyValue!);
      await navigator.clipboard.writeText(value);
      notify(`Copied ${button.dataset.copyLabel}.`);
    } catch { notify('Clipboard access failed. Select and copy the value manually.'); }
  });
}
function badge(state: string) { return state === 'ok' ? '<span class="badge teal">Eligible fixture</span>' : state === 'confirm' ? '<span class="badge amber">Review required</span>' : '<span class="badge red">Blocked</span>'; }
function deviceName(record?: DiskRecord) { return record ? esc(record.disk.model) : 'Choose a fixture drive'; }
function configText() {
  if (customConfig !== undefined) return customConfig;
  return configFormat === 'toml'
    ? `# ISOHopper configuration preview\n[boot]\nnetboot_xyz = ${options.netboot}\nsecure_boot_policy = "${options.policy}"\ntimeout = ${options.timeout}\ndefault = "last"\n\n[launcher]\nsystem_info = ${options.systemInfo}\nwarn_multi_disk = true\ntheme = "${options.theme}"\n\n[launcher.power]\nreboot = ${options.power.reboot}\nshutdown = ${options.power.shutdown}\nfirmware_setup = ${options.power.firmware_setup}\n\n[images]\nverify_hash = true\nverify_signature = "prefer"\n\n[extras]\nmemtest86plus = ${options.memtest}\n`
    : `# ISOHopper configuration preview\nboot:\n  netboot_xyz: ${options.netboot}\n  secure_boot_policy: ${options.policy}\n  timeout: ${options.timeout}\n  default: last\n\nlauncher:\n  system_info: ${options.systemInfo}\n  warn_multi_disk: true\n  theme: ${options.theme}\n  power:\n    reboot: ${options.power.reboot}\n    shutdown: ${options.power.shutdown}\n    firmware_setup: ${options.power.firmware_setup}\n\nimages:\n  verify_hash: true\n  verify_signature: prefer\n\nextras:\n  memtest86plus: ${options.memtest}\n`;
}
function render() {
  app.innerHTML = `<div class="app-shell">
    <aside class="sidebar"><a class="brand" href="#prepare" aria-label="ISOHopper home"><img src="/brand/icon.svg" alt=""/><span>ISOHopper <small>Studio</small></span></a>
      <nav aria-label="Main navigation">${nav.map(item => `<button class="nav-item ${tab === item.id ? 'active' : ''}" data-tab="${item.id}" aria-label="${item.label}" title="${item.label}" ${tab === item.id ? 'aria-current="page"' : ''}>${icon(item.icon)}<span>${item.label}</span>${item.id === 'images' ? `<span class="nav-count">${images.length}</span>` : ''}</button>`).join('')}</nav>
      <div class="sidebar-version">v0.1 · GPL-3.0-or-later</div>
    </aside>
    <div class="workspace">
      <div class="experimental">${icon('info')}<span>${isDemo ? 'Explicit browser demo · mock devices · no physical disk writes' : physicalPreparationEnabled() ? 'Experimental · physical preparation enabled · exact confirmation required' : 'Experimental · physical preparation unavailable'}</span><span class="source-mode">${esc(capabilities && isNative ? `Native · ${capabilities.platform}` : bridgeMode)}</span></div>
      <main id="main-content">${tab === 'prepare' ? prepareView() : tab === 'images' ? imagesView() : tab === 'settings' ? settingsView() : tab === 'activity' ? activityView() : launcherView()}</main>
    </div>
  </div><input id="file-input" type="file" accept=".iso,.img,.wim,.vhd,.vhdx,.efi" multiple hidden/><input id="folder-input" type="file" webkitdirectory multiple hidden/><div id="toast" class="toast" role="status" aria-live="polite"></div>${deviceDialog ? dialogView() : ''}${inventoryDialog ? inventoryView() : ''}`;
  bindEvents(); renderToast();
}
function titleBlock(_eyebrow: string, title: string, description: string, actions = '') { return `<div class="page-title"><div><h1>${title}</h1>${description ? `<p>${description}</p>` : ''}</div>${actions}</div>`; }
function prepareView() {
  const native = isNative && capabilities?.preparation_available;
  return `${titleBlock('', 'Prepare drive', isDemo ? 'Explore a simulated device. No physical disk writes.' : 'Install an empty bootable drive. Add your images to the drive afterwards.')}
    ${native ? nativePreparationPanel() : `<div class="prepare-grid"><div class="main-column"><section class="panel wizard-card"><div class="panel-heading"><h2>${isDemo ? 'Device simulation' : 'Installation unavailable'}</h2><span class="status-pill ${isDemo ? 'neutral' : 'warning'}">${isDemo ? 'DEMO' : 'READ ONLY'}</span></div><div class="wizard-body"><p>${isDemo ? 'This demo uses synthetic devices and never opens a disk.' : 'Physical installation requires the supported Windows desktop build and its elevated helper.'}</p><p>Your image library and configuration preview remain available.</p>${!isDemo ? '<button class="primary-button" disabled>Install ISOHopper</button>' : ''}</div></section>${targetPanel()}</div><aside class="detail-column">${layoutPanel()}</aside></div>`}`;
}
function dropZone() { return `<div class="add-images"><button class="secondary-button dropzone" id="dropzone" ${busy || pickingImages || releasingImages || !canImport() ? 'disabled' : ''}>${icon(pickingImages ? 'activity' : 'plus')}${pickingImages ? 'Reading selected images…' : 'Add images'}</button><button class="secondary-button" id="import-folder" ${busy || pickingImages || releasingImages || !canImport() ? 'disabled' : ''}>Import folder</button><span>${isNative ? 'Native imports stream large images without a fixed size cap.' : isDemo ? 'Local files are fingerprinted with SHA-256 for this preview.' : 'Local file import requires the native desktop runtime or explicit browser demo.'} Folder paths are relative to the selected directory.</span>${sourcesLoading ? `<span>${capabilities?.session_restore ? 'Restoring saved native files…' : 'Restoring retained native sources…'}</span>` : sourcesError ? `<p class="error-text">${esc(sourcesError)}</p><button class="text-button" id="retry-sources" ${nativeActionsLocked() ? 'disabled' : ''}>Retry source listing</button>` : ''}${sourceRestoreWarnings.length ? `<div class="source-restore-warnings" role="status">${sourceRestoreWarnings.map(warning => `<p>${esc(warning)}</p>`).join('')}</div>` : ''}</div>`; }
function imageTable(items: MediaImage[]) { return `<table class="image-table"><thead><tr><th scope="col">Relative path</th><th scope="col">Size</th><th scope="col">Source</th><th scope="col">SHA-256</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>${items.map(imageRow).join('')}</tbody></table>`; }
function imageRow(image: MediaImage) {
  return `<tr class="image-row"><td class="image-name">${esc(imagePath(image))}</td><td class="size-cell">${formatBytes(image.size)}<small class="exact-value">${exactBytes(image.size)}</small></td><td class="source-cell">${image.sample ? 'Sample' : image.origin === 'native' ? 'Native' : 'Browser'}${image.sourceId ? copyable(image.sourceId, `source ID for ${imagePath(image)}`, 'source-id') : ''}</td><td class="hash-cell">${image.sample ? '<span class="subtle">No file loaded</span>' : image.status === 'hashing' ? 'SHA-256: computing' : image.status === 'error' ? `<span class="error-text">${esc(image.error || 'Failed')}</span>` : `<code>${image.hash!}</code><small>Hash only · publisher not verified</small>`}</td><td class="row-actions">${image.hash ? copyButton(image.hash, `SHA-256 for ${imagePath(image)}`) : ''}<button class="icon-button remove-image" data-id="${image.id}" aria-label="Remove ${esc(imagePath(image))}" title="Remove image" ${nativeActionsLocked() ? 'disabled' : ''}>${icon('close')}</button></td></tr>`;
}
function optionRow(key: string, _glyph: string, title: string, detail: string, checked: boolean) { return `<label class="option-row"><input class="toggle-input" type="checkbox" data-option="${key}" ${checked ? 'checked' : ''} ${busy ? 'disabled' : ''}/><span class="option-copy"><strong>${title}</strong><small>${detail}</small></span></label>`; }
function powerSettings() {
  return `<fieldset class="power-settings"><legend>Firmware power actions</legend><p>Controls this local menu preview only. These settings are not applied to the installed engine or this computer.</p>${Object.entries(powerLabels).map(([key, label]) => `<label class="option-row"><input class="toggle-input" type="checkbox" data-power-option="${key}" ${options.power[key as keyof typeof options.power] ? 'checked' : ''}/><span class="option-copy"><strong>${label}</strong>${key === 'firmware_setup' ? '<small>Requires firmware support.</small>' : ''}</span></label>`).join('')}</fieldset>`;
}
function powerPreview() {
  const enabled = Object.entries(powerLabels).filter(([key]) => options.power[key as keyof typeof options.power]);
  if (!enabled.length) return '';
  return `<div class="launcher-power"><strong>Power</strong>${enabled.map(([key, label]) => `<div><button class="secondary-button" data-power-preview="${key}" aria-label="${label}">${label} <kbd>${key === 'reboot' ? 'R' : key === 'shutdown' ? 'S' : 'F'}</kbd></button>${key === 'firmware_setup' ? '<small>Requires firmware support</small>' : ''}</div>`).join('')}</div>`;
}
function nativeTargetPanel() {
  return `<section class="panel target-panel"><div class="panel-heading"><h2>Target device</h2><button class="text-button" id="refresh-drives" ${nativeActionsLocked() || !isNative ? 'disabled' : ''}>${refreshing ? 'Loading…' : 'Refresh'}</button></div>
    ${!isNative ? `<div class="inventory-note"><p>Native desktop runtime unavailable.</p><p>${nativeHost ? 'The desktop bridge did not initialize. Restart the application.' : 'Open the desktop application for local file import and host inventory.'}</p>${nativeHost ? '' : '<a class="text-button" href="?demo=1">Open browser demo</a>'}</div>` : ''}
    ${deviceError && isNative ? `<div class="error-notice">${esc(deviceError)}</div>` : ''}
    ${physicalPreparationEnabled() ? '<div class="inventory-note"><strong>Preparation requires exact confirmation</strong><p>Read-only inventory is not authorization to write. Review the helper-bound target and staged image below.</p></div>' : `<div class="inventory-note"><strong>Preparation unavailable</strong><p>${esc(capabilities?.preparation_unavailable_reason || preparationUnavailable)}</p></div>`}
    ${isNative && capabilities?.platform === 'windows' && capabilities.helper_probe === true ? `<div class="inventory-note"><button class="secondary-button" id="probe-helper" ${nativeActionsLocked() ? 'disabled' : ''}>${probingHelper ? 'Checking elevated helper…' : 'Check elevated helper'}</button><p>Requests Windows elevation for a read-only connection test. No disk access. Publisher not verified.</p>${helperStatus ? `<p id="helper-status" role="status">${esc(helperStatus)}</p>` : ''}</div>` : ''}
    ${hostInventory ? `<p class="inventory-note"><code>source=${esc(hostInventory.source)} · disks=${hostInventory.disks.length}</code><br/>Read-only observations. No device is selected for writing.</p>${hostInventory.warnings.length ? `<div class="inventory-warnings">${hostInventory.warnings.map(warning => `<p><code>${esc(warning.code)}${warning.disk_id ? ` [${esc(warning.disk_id)}]` : ''}</code>: ${esc(warning.message)}</p>`).join('')}</div>` : ''}<div class="native-device-list">${hostInventory.disks.map(disk => `<article class="host-device"><h3>${esc(disk.model || disk.id)}</h3><dl class="device-details"><div><dt>Device ID</dt><dd>${copyable(disk.id, `device ID for ${disk.model || disk.id}`)}</dd></div><div><dt>Serial</dt><dd>${disk.serial ? copyable(disk.serial, `serial for ${disk.id}`) : 'Not reported'}</dd></div><div><dt>Capacity</dt><dd>${formatBytes(disk.size_bytes)}<br/>${exactBytes(disk.size_bytes)}</dd></div><div><dt>Bus</dt><dd>${esc(disk.bus || 'Unknown')}</dd></div><div><dt>Logical sector</dt><dd>${disk.logical_sector_size} bytes</dd></div><div><dt>Physical sector</dt><dd>${typeof disk.physical_sector_size === 'number' ? `${disk.physical_sector_size} bytes` : 'Not reported'}</dd></div><div><dt>Safety complete</dt><dd>${typeof disk.safety_checks_complete === 'boolean' ? String(disk.safety_checks_complete) : 'Not reported'}</dd></div></dl></article>`).join('') || '<p class="empty-inline">No disks returned by the host adapter.</p>'}</div>` : ''}
    ${isNative && capabilities?.host_inventory ? `<button class="text-button inspect-host" id="inspect-host" ${nativeActionsLocked() ? 'disabled' : ''}>Inspect host devices (read only)</button>` : ''}
  </section>`;
}
function jobSourceManifest(job: PreparationSnapshot) {
  if (!job.source_manifest.length) return '';
  return `<section class="job-source-manifest" aria-label="Job source manifest"><div class="panel-heading"><h3>Job source manifest</h3><span class="count">${job.source_manifest.length}</span></div>
    <p class="inventory-note">${job.sources_released ? 'Source metadata from the verified staging image. Original handles released; these records are not reusable imports.' : 'Transferred source metadata. Staging may still be incomplete; these records are not reusable imports.'}</p>
    ${job.source_manifest.length ? `<div class="image-list"><table class="image-table"><thead><tr><th scope="col">Relative path</th><th scope="col">Size</th><th scope="col">SHA-256</th></tr></thead><tbody>${job.source_manifest.map(source => `<tr><td class="image-name">${esc(source.relative_path)}</td><td class="size-cell">${formatBytes(source.bytes)}<small class="exact-value">${exactBytes(source.bytes)}</small></td><td class="hash-cell">${copyable(source.sha256, `SHA-256 for staged ${source.relative_path}`)}</td></tr>`).join('')}</tbody></table></div>` : `<p class="inventory-note">${job.sources_released ? 'No images included.' : 'Available after all source transfers and stability checks complete.'}</p>`}
  </section>`;
}
function nativePreparationAllowed() {
  return !deviceError && !!(engineArchive || capabilities?.engine_download === true) && preparationTargets.some(item => item.selection_token === preparationTarget) && !installationRequested && !nativeActionsLocked();
}
function engineDownloadAllowed() {
  return isNative && capabilities?.engine_download === true && !nativeActionsLocked() && !preparationConfirming;
}
function engineSelectionView() {
  const job = engineDownloadJob;
  return `<div class="inventory-note"><details class="engine-advanced" ${engineAdvanced ? 'open' : ''}><summary>Advanced</summary><div class="engine-actions">${capabilities?.engine_download === true ? `<button class="secondary-button" id="download-engine" ${engineDownloadAllowed() ? '' : 'disabled'}>Download engine</button>` : ''}<button class="secondary-button" id="pick-engine" ${nativeActionsLocked() ? 'disabled' : ''}>Choose engine archive</button></div><p>Official Ventoy 1.1.18 Linux tar.gz only. SHA-256 pin checked locally. <a href="https://github.com/ventoy/Ventoy/releases/tag/v1.1.18" target="_blank" rel="noreferrer">Upstream release</a></p></details>${engineArchive ? `<p>${esc(engineArchive.name)} · ${exactBytes(engineArchive.bytes)}</p>${copyable(engineArchive.sha256, 'engine SHA-256', 'checksum')}` : '<p>No engine archive selected.</p>'}
    ${capabilities?.engine_download === true ? `${engineDownloadRequest ? '<p role="status">Starting engine download…</p>' : !engineDownloadLoaded && !engineDownloadStatusError ? '<p role="status">Reading engine download status…</p>' : ''}${job ? `<div class="engine-download-status" role="status"><dl class="device-details"><div><dt>Phase</dt><dd>${esc(job.phase)}</dd></div><div><dt>Progress</dt><dd>${exactBytes(job.completed_bytes)} / ${exactBytes(job.total_bytes)}</dd></div><div><dt>Source</dt><dd>${job.cache_hit ? 'Verified cache' : job.phase === 'checking_cache' ? 'Checking local cache' : 'New download'}</dd></div></dl><p>Expected SHA-256</p>${copyable(job.expected_sha256, 'expected engine SHA-256', 'checksum')}<p>${esc(job.message)}</p>${job.active ? `<button class="secondary-button" id="cancel-engine-download" ${job.cancel_requested || engineDownloadCancelling ? 'disabled' : ''}>${job.cancel_requested || engineDownloadCancelling ? 'Cancellation requested…' : 'Cancel download'}</button>` : ''}</div>` : ''}${engineDownloadError ? `<p class="error-text" role="alert">${esc(engineDownloadError)}</p>` : ''}${engineDownloadStatusError ? '<button class="secondary-button" id="retry-engine-status">Retry download status</button>' : ''}` : ''}</div>`;
}
function nativePreparationPanel() {
  const target = preparationTargets.find(item => item.selection_token === preparationTarget);
  const job = preparationEditing ? null : preparationJob;
  const step = job?.phase === 'succeeded' ? 3 : job && (!job.active || job.target_may_be_incomplete || job.bytes_written > 0 || ['writing_target', 'verifying_target'].includes(job.phase)) ? 2 : job || installationRequested || preparationRequest ? 1 : 0;
  const steps = ['Choose drive', 'Review & confirm', 'Install', 'Done'];
  const visibleTargets = visiblePreparationTargets(preparationTargets, showLargeDrives, preparationTarget);
  const hiddenTargets = preparationTargets.length - visibleTargets.length;
  const requiredSpace = (job?.target?.size_bytes || target?.disk.size || 0) * 2 + 256 * 1024 ** 2;
  const percent = job?.total_bytes ? Math.min(100, Math.floor(job.completed_bytes / job.total_bytes * 100)) : 0;
  return `<ol class="wizard-steps" aria-label="Installation steps">${steps.map((label, index) => `<li class="${index === step ? 'current' : index < step ? 'complete' : ''}" ${index === step ? 'aria-current="step"' : ''}><span class="step-number">${index < step ? '✓' : index + 1}</span><span>${label}</span></li>`).join('')}</ol>
    <div class="wizard-layout"><div class="main-column"><section class="panel native-preparation wizard-card">
      <div class="panel-heading"><div><span class="wizard-kicker">STEP ${step + 1} OF 4</span><h2>${step === 0 ? 'Choose your drive' : step === 1 ? 'Review your installation' : step === 2 ? job?.active ? 'Installing ISOHopper' : 'Installation stopped' : 'ISOHopper is installed'}</h2></div><span class="status-pill ${step === 3 ? 'success' : step === 2 && !job?.active ? 'warning' : 'neutral'}">${step === 3 ? 'VERIFIED' : step === 0 ? 'CANDIDATE' : step === 1 ? 'NO WRITES YET' : job?.active ? 'IN PROGRESS' : 'REVIEW STATUS'}</span></div>
      ${deviceError ? `<p class="error-notice" role="alert">${esc(deviceError)} Use Refresh in Device checks to retry.</p>` : ''}
      ${step === 0 ? `<div class="wizard-body"><p>Choose a USB or SD drive. All existing data on the selected drive will be erased.</p><label class="target-label" for="preparation-target">Target candidate (helper revalidates)<select id="preparation-target" ${nativeActionsLocked() ? 'disabled' : ''}><option value="">Choose a target</option>${visibleTargets.map(item => `<option value="${esc(item.selection_token)}" ${preparationTarget === item.selection_token ? 'selected' : ''}>${preparationTargetLabel(item)}</option>`).join('')}</select></label>
      <label class="large-drive-option"><input type="checkbox" id="show-large-drives" ${showLargeDrives ? 'checked' : ''}/> Show large drives (over 256 GiB)${hiddenTargets ? ` · ${hiddenTargets} hidden` : ''}</label>
      ${target ? `<div class="selected-target"><div class="target-title">${icon('drive')}<div><h3>${esc(target.disk.friendly_name || target.display_id)}</h3><p>${esc(target.volume_labels?.join(', ') || target.display_id)}</p></div><span class="status-pill neutral">Candidate</span></div><dl class="device-details"><div><dt>Device</dt><dd>${copyable(target.display_id, 'candidate device ID')}</dd></div><div><dt>Serial</dt><dd>${target.disk.serial_number ? copyable(target.disk.serial_number, 'candidate serial') : 'Not reported'}</dd></div><div><dt>Capacity</dt><dd>${target.disk.size === null ? 'Unknown' : `${formatBytes(target.disk.size)} · ${exactBytes(target.disk.size)}`}</dd></div><div><dt>Sector size</dt><dd>${target.disk.logical_sector_size ?? '?'} logical / ${target.disk.physical_sector_size ?? '?'} physical bytes</dd></div><div><dt>Bus type</dt><dd>${target.disk.bus_type ?? 'Unknown'}</dd></div></dl><details><summary>All candidate device fields</summary><pre>${esc(JSON.stringify({ ...target.disk, volume_labels: target.volume_labels ?? null }, null, 2))}</pre></details></div>` : '<div class="empty-inline">Select a candidate to review its identity and capacity.</div>'}
      <div id="preparation-prerequisites" role="status">${preparationPrerequisites()}</div></div><div class="wizard-actions"><p>Review the selected device and confirm before writing.</p><button class="primary-button" id="start-preparation" ${nativePreparationAllowed() ? '' : 'disabled'}>Install ISOHopper</button></div>` : ''}
      ${step === 1 && !job ? `<div class="wizard-body"><h3>${engineDownloadLocked() ? 'Getting the verified engine' : 'Preparing your installation'}</h3><p>${installationRequested ? 'The pinned engine is being downloaded and verified. Installation preparation will continue automatically; writing still requires your exact confirmation.' : 'Waiting for the elevated helper to validate the target and prepare an empty bootable image.'}</p></div>` : ''}
      ${preparationError ? `<p class="error-notice" role="alert">${esc(preparationError)}</p>` : ''}
      ${job ? `<div class="preparation-status"><div class="wizard-body">${step === 3 ? '<div class="success-banner"><strong>Write and full readback verified.</strong><p>Your empty bootable drive is ready. Add image files to its data partition, then safely eject it.</p></div>' : ''}
      ${job.target_may_be_incomplete ? '<div class="error-notice">The target may be incomplete. Do not rely on it as bootable media until a full installation succeeds.</div>' : ''}
      ${job.active && job.phase !== 'await_confirmation' ? `<div class="installation-progress" role="status"><div><strong>${step === 1 ? 'Preparing empty bootable image' : 'Writing and verifying your drive'}</strong><span>${percent}%</span></div><progress value="${job.completed_bytes}" max="${job.total_bytes || 1}" aria-label="Installation progress"></progress><p>${exactBytes(job.completed_bytes)} / ${exactBytes(job.total_bytes)}</p></div>` : ''}
      <p class="job-message" role="status">${esc(job.message)}</p>
      ${job.target ? `<section class="bound-target"><h3>Helper-bound target</h3><dl class="device-details"><div><dt>Model</dt><dd>${esc(target?.disk.serial_number === job.target.serial ? target.disk.friendly_name || 'Not reported' : 'Not reported by helper')}</dd></div><div><dt>Device number</dt><dd>${job.target.device_number}</dd></div><div><dt>Serial</dt><dd>${copyable(job.target.serial, 'target serial')}</dd></div><div><dt>Device ID</dt><dd>${job.target.device_id ? copyable(job.target.device_id, 'target device ID') : 'Not reported'}</dd></div><div><dt>Capacity</dt><dd>${exactBytes(job.target.size_bytes)}</dd></div><div><dt>Bus type</dt><dd>${job.target.bus_type}</dd></div><div><dt>Logical / physical sector</dt><dd>${job.target.logical_sector_size} / ${job.target.physical_sector_size} bytes</dd></div></dl></section>` : ''}
      ${job.active && job.phase === 'await_confirmation' ? `<div class="risk-box"><h3>Erase this entire drive?</h3><p>Writing destroys all existing data on the helper-bound target. There is no rollback. Check its serial and capacity before continuing.</p><label for="preparation-phrase">Enter the confirmation text:</label>${copyable(job.challenge || '', 'confirmation text', 'challenge')}<input id="preparation-phrase" value="${esc(preparationPhrase)}" autocomplete="off" spellcheck="false" aria-label="Write confirmation" ${capabilities?.physical_preparation && !preparationConfirming ? '' : 'disabled'}/><p>Type or paste the text above, then click Install ISOHopper.</p><button class="primary-button danger-button" id="confirm-preparation" ${preparationConfirmationAllowed() ? '' : 'disabled'}>Install ISOHopper</button></div>` : ''}
      <details class="installation-receipt" ${job.active && job.phase !== 'await_confirmation' ? '' : 'open'}><summary>${step === 3 ? 'Verified installation receipt' : 'Installation details and checksums'}</summary><dl class="device-details"><div><dt>Job ID</dt><dd>${copyable(job.job_id, 'preparation job ID')}</dd></div><div><dt>Phase</dt><dd>${esc(job.phase)}</dd></div><div><dt>Progress</dt><dd>${exactBytes(job.completed_bytes)} / ${exactBytes(job.total_bytes)}</dd></div><div><dt>Written / verified</dt><dd>${exactBytes(job.bytes_written)} / ${exactBytes(job.bytes_verified)}</dd></div><div><dt>Source handles released</dt><dd>${job.sources_released}</dd></div><div><dt>Target may be incomplete</dt><dd>${job.target_may_be_incomplete}</dd></div></dl>${job.image_sha256 ? `<p>Image SHA-256</p>${copyable(job.image_sha256, 'image SHA-256', 'checksum')}` : ''}${job.description_digest ? `<p>Description digest</p>${copyable(job.description_digest, 'description digest', 'checksum')}` : ''}${jobSourceManifest(job)}</details></div>
      <div class="wizard-actions">${job.active ? `<p>${step === 2 ? 'Cancellation can leave the drive incomplete.' : 'You can cancel before writing begins.'}</p><button class="secondary-button" id="cancel-preparation" ${job.cancel_requested ? 'disabled' : ''}>${job.cancel_requested ? 'Cancellation requested…' : 'Cancel preparation'}</button>` : `<button class="secondary-button" data-tab="activity">View activity</button><button class="primary-button" id="prepare-another">${step === 3 ? 'Prepare another drive' : 'Choose drive and retry'}</button>`}</div></div>` : ''}
    </section></div><aside class="wizard-summary"><section class="panel"><div class="panel-heading"><h2>Installation</h2></div><div class="wizard-body"><div class="summary-row"><span>Contents</span><strong>Empty bootable drive</strong></div><div class="summary-row"><span>Boot engine</span><strong>Ventoy 1.1.18</strong></div><p>Requires Windows elevation and local free space of twice the target capacity plus 256 MiB${requiredSpace > 256 * 1024 ** 2 && Number.isSafeInteger(requiredSpace) ? `: ${exactBytes(requiredSpace)}` : ''}.</p></div></section><section class="panel"><div class="panel-heading"><h2>Engine</h2><span class="status-pill ${engineArchive ? 'success' : 'neutral'}">${engineArchive ? 'Verified' : 'Pinned download'}</span></div><div id="engine-selection">${engineSelectionView()}</div></section><section class="panel"><div class="panel-heading"><h2>Device checks</h2><button class="text-button" id="refresh-drives" ${nativeActionsLocked() || installationRequested ? 'disabled' : ''}>${refreshing ? 'Loading…' : 'Refresh'}</button></div><div class="wizard-body"><p>A listed candidate is not write authorization. The elevated helper revalidates the selected device.</p>${capabilities?.helper_probe ? `<button class="secondary-button" id="probe-helper" ${nativeActionsLocked() || installationRequested ? 'disabled' : ''}>${probingHelper ? 'Checking elevated helper…' : 'Check elevated helper'}</button>${helperStatus ? `<p id="helper-status" role="status">${esc(helperStatus)}</p>` : ''}` : ''}${capabilities?.host_inventory ? `<button class="text-button" id="inspect-host" ${nativeActionsLocked() || installationRequested ? 'disabled' : ''}>Inspect host devices (read only)</button>` : ''}</div></section></aside></div>`;
}
function targetPanel() {
  if (!isDemo) return nativeTargetPanel();
  const disk = selected?.disk;
  const risks = selected?.verdict.risks || [];
  return `<section class="panel target-panel"><div class="panel-heading"><h2>Target device</h2><button class="text-button" id="refresh-drives" ${busy || engineDownloadLocked() || refreshing ? 'disabled' : ''}>${refreshing ? 'Loading…' : 'Refresh'}</button></div>
    ${deviceError ? `<div class="error-notice">${esc(deviceError)}</div>` : ''}
    <button class="selected-drive" id="choose-drive" ${busy || refreshing ? 'disabled' : ''}><span><strong>${deviceName(selected)}</strong><small>Change fixture device</small></span>${icon('down')}</button>
    ${selected && disk ? `<div class="inventory-note">Inventory: built-in fixtures. No OS device enumeration.</div><div class="drive-facts"><span>Guard status</span>${badge(selected.verdict.state)}</div><dl class="device-details"><div><dt>Device ID</dt><dd>${copyable(disk.id, `device ID for ${disk.model || disk.id}`)}</dd></div><div><dt>Serial</dt><dd>${copyable(disk.serial, `serial for ${disk.id}`)}</dd></div><div><dt>Capacity</dt><dd>${formatBytes(disk.size_bytes)}<br/>${exactBytes(disk.size_bytes)}</dd></div><div><dt>Bus</dt><dd>${esc(disk.bus.toUpperCase())}</dd></div><div><dt>Logical sector</dt><dd>${disk.logical_sector_size} bytes</dd></div><div><dt>Physical sector</dt><dd>${typeof disk.physical_sector_size === 'number' && disk.physical_sector_size > 0 ? `${disk.physical_sector_size} bytes` : 'Not reported'}</dd></div><div><dt>Layout</dt><dd>GPT / exFAT (planned)</dd></div></dl>` : ''}
    ${disk?.bus === 'sd' ? '<div class="inline-note">SD boot support depends on target firmware.</div>' : ''}
    ${risks.length ? `<div class="risk-box"><strong>Confirmation required</strong><ul>${risks.map(risk => `<li><code>${esc(risk.code)}</code>: ${esc(risk.message)}</li>`).join('')}</ul><label for="confirmation">Type this phrase to enable simulation:</label><code class="challenge">${esc(challengeFor(selected!))}</code><input id="confirmation" value="${esc(confirmation)}" autocomplete="off" spellcheck="false" autocapitalize="characters" aria-label="Disk confirmation phrase" placeholder="Type the phrase above" ${busy ? 'disabled' : ''}/><small id="confirmation-status">${confirmationMatches(selected!, confirmation) ? 'Phrase matches this fixture.' : 'Paste disabled. Enter does not submit.'}</small></div>` : ''}
    ${complete ? `<div class="completion"><strong>Simulation complete</strong><small>No disk was opened or modified.</small></div>` : ''}
    ${busy ? `<div class="run-progress"><div><strong>${esc(runTitle)}</strong><span>${progress}%</span></div><progress value="${progress}" max="100" aria-label="Simulation progress"></progress></div>` : ''}
    <button class="primary-button" id="simulate" ${runAllowed() ? '' : 'disabled'}>${busy ? 'Simulation in progress' : complete ? 'Run simulation again' : 'Simulate preparation'}</button>
    <p class="action-note">No physical disk writes.</p>${bridge.InspectDevices ? `<button class="text-button inspect-host" id="inspect-host" ${inspectingHost ? 'disabled' : ''}>Inspect host devices (read only)</button>` : ''}${pendingImages() ? '<p class="inline-note">Finish hashing or remove failed images to continue.</p>' : ''}${selected && sumBytes() > selected.disk.size_bytes - 130 * 1024 * 1024 ? '<p class="error-notice">Images exceed available space.</p>' : ''}
  </section>`;
}
function layoutPanel() {
  if (!isDemo) return `<section class="panel layout-panel"><div class="panel-heading"><h3>Partition plan</h3></div><p class="subtle">Unavailable until a native preparation job can validate and bind a plan to the selected device.</p></section>`;
  const partitions = plan?.partitions || [];
  return `<section class="panel layout-panel"><div class="panel-heading"><h3>Partition plan</h3><span class="subtle">GPT / 1 MiB alignment</span></div>${planLoading ? '<p class="subtle">Calculating partition boundaries…</p>' : planError ? `<p class="error-notice">${esc(planError)}</p>` : plan ? `<div class="geometry"><div class="geometry-summary">Logical sector: ${plan.logical_sector_size} bytes<br/>Device: ${exactBytes(plan.size_bytes)}</div>${partitions.map(part => `<section class="partition-details"><h4>${esc(part.name)}</h4><dl><div><dt>Start LBA</dt><dd>${part.start_lba.toLocaleString('en-GB')}</dd></div><div><dt>End LBA</dt><dd>${part.end_lba.toLocaleString('en-GB')}</dd></div><div><dt>Sectors</dt><dd>${(part.end_lba - part.start_lba + 1).toLocaleString('en-GB')}</dd></div><div><dt>Size</dt><dd>${exactBytes((part.end_lba - part.start_lba + 1) * plan!.logical_sector_size)}</dd></div></dl></section>`).join('')}</div>` : '<p class="subtle">Choose a device to calculate the layout.</p>'}</section>`;
}
function imagesView() { const filtered = images.filter(image => imagePath(image).toLowerCase().includes(query.toLowerCase())); return `${titleBlock('', 'Images', 'Local SHA-256 fingerprints. Publisher verification is not connected.', isDemo ? `<button class="secondary-button" id="load-samples" ${busy ? 'disabled' : ''}>Load samples</button>` : '')}<section class="panel library-panel">${dropZone()}<div class="library-toolbar">${isNative ? `<button class="text-button" id="refresh-sources" ${nativeActionsLocked() ? 'disabled' : ''}>Refresh</button>` : ''}<h2>Image library <span class="count">${images.length}</span></h2><button class="text-button" id="clear-images" ${nativeActionsLocked() || !images.length ? 'disabled' : ''}>${releasingImages ? 'Releasing sources…' : 'Clear library'}</button><label class="search-field">${icon('search')}<input id="image-search" type="search" value="${esc(query)}" aria-label="Search images" placeholder="Filter filenames"/></label></div><div class="image-list" id="filtered-images">${filtered.length ? imageTable(filtered) : '<div class="empty-library"><img src="/brand/icon.svg" alt=""/><h2>No images</h2><p>Add images or import a folder to keep your collection here.</p></div>'}</div><div class="panel-foot"><span>${isDemo ? 'Sample entries contain no files. ' : ''}${isNative ? capabilities?.session_restore ? 'Saved native sources are restored by the desktop. Review warnings for missing or changed files. This library is independent of drive installation.' : 'Native sources stay open until removed or the application exits. Reload restores the catalogue; hashes are from import time.' : 'Browser fingerprints are cleared on reload.'}</span><span>${formatBytes(sumBytes())} total</span></div></section>`; }
function settingsView() { return `${titleBlock('', 'Configuration', 'Edit and export YAML or TOML. Changes are not applied to a drive.')}<div class="settings-grid"><section class="panel"><div class="panel-heading"><h2>Boot settings</h2><span class="badge">Preview</span></div>${optionRow('netboot', 'globe', 'Include network boot', 'Add netboot.xyz to the planned boot menu.', options.netboot)}${optionRow('memtest', 'activity', 'Include memory test', 'Add a Memtest86+ entry to the preview.', options.memtest)}${optionRow('systemInfo', 'monitor', 'Show system information', 'Hardware details in the launcher preview.', options.systemInfo)}${powerSettings()}<label class="field-row"><span><strong>Boot timeout</strong><small>Seconds before default selection.</small></span><input id="timeout" type="number" min="0" max="300" value="${options.timeout}"/></label><label class="field-row"><span><strong>Secure Boot policy</strong><small>Configuration only; not enforced here.</small></span><select id="policy">${['enforce', 'prompt', 'off'].map(policy => `<option ${options.policy === policy ? 'selected' : ''}>${policy}</option>`).join('')}</select></label><label class="field-row"><span><strong>Launcher theme</strong><small>Used in the launcher preview.</small></span><select id="theme">${['midnight', 'aurora'].map(theme => `<option ${options.theme === theme ? 'selected' : ''}>${theme}</option>`).join('')}</select></label><div class="settings-note">${icon('info')} These settings and power-menu controls are not applied to Ventoy engine media.</div></section><section class="panel config-panel"><div class="panel-heading"><h2>Configuration source</h2><div class="segmented" aria-label="Configuration format"><button data-format="yaml" class="${configFormat === 'yaml' ? 'selected' : ''}">YAML</button><button data-format="toml" class="${configFormat === 'toml' ? 'selected' : ''}">TOML</button></div></div><div class="editor-label"><span class="status-dot"></span> isohopper.${configFormat === 'yaml' ? 'yml' : 'toml'}<span>LOCAL PREVIEW</span></div><textarea id="config-editor" aria-label="Configuration source" spellcheck="false">${esc(configText())}</textarea><div class="config-actions"><button class="secondary-button" id="validate-config">${icon('check')} Validate</button><button class="secondary-button" id="reset-config">Reset from settings</button><button class="primary-button compact" id="download-config">${icon('download')} Export</button></div>${configResult ? `<div class="config-result" role="status">${esc(configResult)}</div>` : ''}<p class="subtle editor-note">Changing form settings or format replaces manual edits. Export edits first.</p></section></div>`; }
function activityView() { return `${titleBlock('', 'Activity', isDemo ? 'File hashing and simulation events for this session.' : capabilities?.preparation_available ? 'Host inventory, file hashing and preparation events for this session.' : 'Host inventory and local file hashing events for this session.', '<button class="secondary-button" id="export-activity">'+icon('download')+' Export activity</button>')}<section class="panel activity-panel"><div class="panel-heading"><h2>This session <span class="count">${logs.length}</span></h2><button class="text-button" id="clear-activity">Clear activity</button></div>${logs.length ? logs.map(item => `<article class="log-row"><span class="log-symbol ${item.kind}">[${item.kind === 'success' ? 'OK' : item.kind === 'warning' ? 'WARN' : 'INFO'}]</span><div><strong>${esc(item.title)}</strong><p>${esc(item.detail)}</p></div><time>${item.time}</time></article>`).join('') : '<div class="empty-state">No events.</div>'}</section>`; }
function launcherView() {
  const entries = [...images.map(image => ({ name: imagePath(image), detail: image.sample ? 'Sample entry · no file loaded' : 'Local fingerprint · boot unavailable', icon: 'image' })), ...(options.netboot ? [{ name: 'Network boot', detail: 'netboot.xyz · planned', icon: 'globe' }] : []), ...(options.memtest ? [{ name: 'Memory diagnostics', detail: 'Memtest86+ · planned', icon: 'activity' }] : [])];
  launcherChoice = Math.min(launcherChoice, Math.max(0, entries.length - 1));
  return `${titleBlock('', 'Launcher preview', 'Visual menu preview; not installed on Ventoy engine media. Selecting an entry does not boot an image.', '<button class="secondary-button" data-tab="settings">Edit configuration</button>')}<section class="launcher-frame ${options.theme}"><div class="launcher-top"><strong><img class="launcher-brand" src="/brand/icon.svg" alt=""/> ISOHopper <span>Boot menu</span></strong><span>Theme: ${esc(options.theme)} · Timeout: ${options.timeout}s</span></div><div class="launcher-body"><div class="launcher-menu"><div class="boot-entries">${entries.map((entry, index) => `<button data-boot="${index}" class="boot-entry ${index === launcherChoice ? 'chosen' : ''}"><span><strong>${esc(entry.name)}</strong><small>${esc(entry.detail)}</small></span>${index === launcherChoice ? icon('check') : ''}</button>`).join('') || '<div class="empty-inline">No entries configured.</div>'}</div><div class="launcher-selection" role="status">${entries.length ? `Selected: ${esc(entries[launcherChoice].name)}. This is a visual preview only.` : 'No entries configured.'}</div></div>${options.systemInfo && isDemo ? `<aside class="system-card"><h3>System information (example)</h3><dl><div><dt>CPU</dt><dd>8 cores</dd></div><div><dt>Memory</dt><dd>16 GB</dd></div><div><dt>Firmware</dt><dd>UEFI</dd></div><div><dt>Secure Boot</dt><dd>Not detected</dd></div></dl><p>No host scan performed.</p></aside>` : ''}</div>${powerPreview()}<div class="launcher-hints"><span><kbd>↑</kbd><kbd>↓</kbd> Navigate preview</span><span><kbd>Enter</kbd> Select preview</span></div></section>`;
}
function dialogView() { return `<div class="modal-backdrop"><section class="device-dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><div class="panel-heading"><div><h2 id="dialog-title">Choose a fixture drive</h2></div><button class="icon-button" id="close-dialog" aria-label="Close drive picker">${icon('close')}</button></div><p class="dialog-description">Synthetic devices only. No physical drives are scanned.</p><div class="device-list">${disks.map(record => `<div class="device-choice ${selected?.disk.id === record.disk.id ? 'selected' : ''} ${record.verdict.state === 'blocked' ? 'blocked' : ''}"><button data-disk="${esc(record.disk.id)}" ${record.verdict.state === 'blocked' ? 'disabled' : ''}><span class="drive-art">${icon(record.disk.bus === 'sd' ? 'sd' : record.verdict.state === 'blocked' ? 'lock' : 'drive')}</span><span class="device-choice-copy"><strong>${deviceName(record)}</strong><small>${formatBytes(record.disk.size_bytes)} / ${exactBytes(record.disk.size_bytes)} · ${esc(record.disk.bus.toUpperCase())}<br/>ID=${esc(record.disk.id)} · serial=${esc(record.disk.serial) || 'UNAVAILABLE'}<br/>logical=${record.disk.logical_sector_size} B · physical=${typeof record.disk.physical_sector_size === 'number' ? record.disk.physical_sector_size : 'unknown'} B</small></span>${badge(record.verdict.state)}${selected?.disk.id === record.disk.id ? icon('check') : ''}</button>${record.verdict.state === 'blocked' ? `<div class="blocked-reasons">${(record.verdict.hard_blocks || []).map(reason => `<span><code>${esc(reason.code)}</code>: ${esc(reason.message)}</span>`).join('')}</div>` : ''}</div>`).join('')}</div><div class="dialog-foot">${icon('shield')} Blocked fixtures cannot be selected or overridden.</div></section></div>`; }
function inventoryView() {
  return `<div class="modal-backdrop inventory-backdrop"><section class="inventory-dialog" role="dialog" aria-modal="true" aria-labelledby="inventory-title"><div class="panel-heading"><h2 id="inventory-title">Host devices — read only</h2><button class="icon-button" id="close-inventory" aria-label="Close host inventory">${icon('close')}</button></div><p class="dialog-description">Actual OS inventory. These records cannot be selected for preparation. Unknown safety metadata remains unknown.</p>${inspectingHost ? '<p class="inventory-status" role="status">Reading host inventory…</p>' : inventoryError ? `<p class="error-notice">${esc(inventoryError)}</p>` : hostInventory ? `<div class="inventory-toolbar"><code>source=${esc(hostInventory.source)} disks=${hostInventory.disks.length} warnings=${hostInventory.warnings.length}</code><button class="secondary-button" id="export-inventory">Export JSON</button></div>${hostInventory.warnings.length ? `<div class="inventory-warnings">${hostInventory.warnings.map(warning => `<p><code>${esc(warning.code)}${warning.disk_id ? ` [${esc(warning.disk_id)}]` : ''}</code> ${esc(warning.message)}</p>`).join('')}</div>` : ''}<div class="host-device-list">${hostInventory.disks.length ? hostInventory.disks.map(disk => `<article class="host-device"><h3>${esc(disk.model || disk.id)}</h3><dl class="device-details"><div><dt>Device ID</dt><dd>${copyable(disk.id, `device ID for ${disk.model || disk.id}`)}</dd></div><div><dt>Serial</dt><dd>${disk.serial ? copyable(disk.serial, `serial for ${disk.id}`) : 'Not reported'}</dd></div><div><dt>Capacity</dt><dd>${formatBytes(disk.size_bytes)} / ${exactBytes(disk.size_bytes)}</dd></div><div><dt>Bus</dt><dd>${esc(disk.bus || 'Unknown')}</dd></div><div><dt>Logical sector</dt><dd>${disk.logical_sector_size} bytes</dd></div><div><dt>Physical sector</dt><dd>${typeof disk.physical_sector_size === 'number' && disk.physical_sector_size > 0 ? `${disk.physical_sector_size} bytes` : 'Not reported'}</dd></div><div><dt>Safety complete</dt><dd>${typeof disk.safety_checks_complete === 'boolean' ? String(disk.safety_checks_complete) : 'Not reported'}</dd></div></dl><details><summary>All reported fields</summary><pre>${esc(JSON.stringify(disk, null, 2))}</pre></details></article>`).join('') : '<p class="empty-inline">No disks returned by the host adapter.</p>'}</div>` : ''}</section></div>`;
}
async function inspectHost() {
  if (nativeActionsLocked() || !bridge.InspectDevices || !capabilities?.host_inventory) return;
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
  document.querySelector('#about-button')?.addEventListener('click', () => notify(`ISOHopper v0.1 · GPL-3.0-or-later · Original source © 2026 S33G. ${runtimeDescription()}`));
  document.querySelector('#inspect-host')?.addEventListener('click', inspectHost);
  document.querySelector('#close-inventory')?.addEventListener('click', closeInventory);
  document.querySelector('.inventory-backdrop')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeInventory(); });
  document.querySelector('#export-inventory')?.addEventListener('click', () => { if (hostInventory) download('isohopper-host-inventory.json', JSON.stringify(hostInventory, null, 2), 'application/json'); });
  document.querySelector('#choose-drive')?.addEventListener('click', () => { deviceDialog = true; render(); document.querySelector<HTMLButtonElement>('#close-dialog')?.focus(); });
  document.querySelector('#close-dialog')?.addEventListener('click', closeDialog);
  document.querySelector('.modal-backdrop:not(.inventory-backdrop)')?.addEventListener('click', event => { if (event.target === event.currentTarget) closeDialog(); });
  document.querySelectorAll<HTMLButtonElement>('[data-disk]').forEach(button => button.onclick = async () => { const record = disks.find(item => item.disk.id === button.dataset.disk); if (!isDemo || !record || record.verdict.state === 'blocked' || busy) return; selected = record; confirmation = ''; complete = false; deviceDialog = false; log('Fixture selected', `id=${record.disk.id} serial=${record.disk.serial} model=${record.disk.model} bytes=${record.disk.size_bytes} bus=${record.disk.bus} logical_sector=${record.disk.logical_sector_size} physical_sector=${record.disk.physical_sector_size ?? 'unknown'} verdict=${record.verdict.state} risks=${(record.verdict.risks || []).map(reason => reason.code).join(',') || 'none'}`, record.verdict.state === 'confirm' ? 'warning' : 'info'); await loadPlan(); });
  document.querySelector('#refresh-drives')?.addEventListener('click', loadDevices);
  document.querySelector('#probe-helper')?.addEventListener('click', probeHelper);
  bindEngineEvents();
  document.querySelector<HTMLSelectElement>('#preparation-target')?.addEventListener('change', event => { if (nativeActionsLocked() || installationRequested) return; preparationTarget = (event.target as HTMLSelectElement).value; targetHint = preparationTargetHint(preparationTargets.find(item => item.selection_token === preparationTarget)); preparationPhrase = ''; savePreferences(); render(); });
  document.querySelector<HTMLInputElement>('#show-large-drives')?.addEventListener('change', event => { showLargeDrives = (event.target as HTMLInputElement).checked; savePreferences(); render(); });
  document.querySelector('#start-preparation')?.addEventListener('click', startNativePreparation);
  document.querySelector('#prepare-another')?.addEventListener('click', () => { if (!nativeActionsLocked()) { preparationEditing = true; preparationPhrase = ''; preparationError = ''; void loadDevices(); } });
  document.querySelector('#cancel-preparation')?.addEventListener('click', cancelNativePreparation);
  document.querySelector('#confirm-preparation')?.addEventListener('click', confirmNativePreparation);
  const phrase = document.querySelector<HTMLInputElement>('#preparation-phrase');
  if (phrase) {
    phrase.oninput = () => { preparationPhrase = phrase.value; const button = document.querySelector<HTMLButtonElement>('#confirm-preparation'); if (button) button.disabled = !preparationConfirmationAllowed(); };
  }
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
  document.querySelector('#refresh-sources')?.addEventListener('click', () => { if (!nativeActionsLocked()) void restoreSources(); });
  document.querySelector('#retry-sources')?.addEventListener('click', () => { if (!nativeActionsLocked()) void restoreSources(); });
  document.querySelector('#import-folder')?.addEventListener('click', () => void browseImages('folder'));
  document.querySelector<HTMLInputElement>('#folder-input')!.onchange = event => void addFiles(Array.from((event.target as HTMLInputElement).files || []));
  document.querySelector<HTMLInputElement>('#file-input')!.onchange = event => void addFiles(Array.from((event.target as HTMLInputElement).files || []));
  bindImageActions();
  document.querySelectorAll<HTMLInputElement>('[data-option]').forEach(input => input.onchange = () => { (options as unknown as Record<string, boolean>)[input.dataset.option!] = input.checked; customConfig = undefined; configResult = ''; complete = false; savePreferences(); render(); });
  document.querySelectorAll<HTMLInputElement>('[data-power-option]').forEach(input => input.onchange = () => { options.power[input.dataset.powerOption as keyof typeof options.power] = input.checked; customConfig = undefined; configResult = ''; complete = false; savePreferences(); render(); });
  document.querySelectorAll<HTMLButtonElement>('[data-power-preview]').forEach(button => button.onclick = () => { const action = button.dataset.powerPreview as keyof typeof powerLabels; notify(`${powerLabels[action]}: preview only. No host action performed.`); });
  document.querySelector('#load-samples')?.addEventListener('click', () => { if (!isDemo || busy || releasingImages) return; if (!images.some(image => image.id === 'sample-linux')) images.push({ id: 'sample-linux', name: 'linux-desktop-demo.iso', size: 4_800_000_000, sample: true, status: 'sample' }); if (!images.some(image => image.id === 'sample-recovery')) images.push({ id: 'sample-recovery', name: 'recovery-toolkit-demo.img', size: 1_600_000_000, sample: true, status: 'sample' }); complete = false; log('Sample manifest loaded', 'Two illustrative entries. No image data loaded or downloaded.'); render(); });
  document.querySelector<HTMLInputElement>('#image-search')?.addEventListener('input', event => { query = (event.target as HTMLInputElement).value; const filtered = images.filter(image => imagePath(image).toLowerCase().includes(query.toLowerCase())); document.querySelector('#filtered-images')!.innerHTML = filtered.length ? imageTable(filtered) : '<div class="empty-inline">No matching images.</div>'; bindImageActions(); });
  document.querySelectorAll<HTMLButtonElement>('[data-format]').forEach(button => button.onclick = () => { configFormat = button.dataset.format === 'toml' ? 'toml' : 'yaml'; customConfig = undefined; configResult = ''; savePreferences(); render(); });
  document.querySelector<HTMLTextAreaElement>('#config-editor')?.addEventListener('input', event => { customConfig = (event.target as HTMLTextAreaElement).value; configResult = ''; savePreferences(); document.querySelector('.config-result')?.remove(); });
  document.querySelector<HTMLInputElement>('#timeout')?.addEventListener('change', event => { options.timeout = Math.max(0, Math.min(300, Math.trunc(Number((event.target as HTMLInputElement).value)) || 0)); customConfig = undefined; configResult = ''; savePreferences(); render(); });
  for (const key of ['policy', 'theme'] as const) document.querySelector<HTMLSelectElement>(`#${key}`)?.addEventListener('change', event => { const value = (event.target as HTMLSelectElement).value; if (key === 'policy' && (value === 'enforce' || value === 'prompt' || value === 'off')) options.policy = value; if (key === 'theme' && (value === 'midnight' || value === 'aurora')) options.theme = value; customConfig = undefined; configResult = ''; savePreferences(); render(); });
  document.querySelector('#validate-config')?.addEventListener('click', async () => { const text = configText(); const format = configFormat; try { const result = await bridge.CheckConfig(text, format); if (text !== configText() || format !== configFormat) return; configResult = result.valid ? `Native schema validation: valid.${result.warnings?.length ? ` Warnings: ${result.warnings.join('; ')}` : ' No warnings.'} Boot chain not validated.` : result.error || 'Configuration did not pass validation.'; log(result.valid ? 'Configuration validated' : 'Configuration validation result', configResult, result.valid ? 'success' : 'warning'); } catch (error) { configResult = `Validation unavailable: ${errorMessage(error)}`; } render(); });
  document.querySelector('#reset-config')?.addEventListener('click', () => { customConfig = undefined; configResult = ''; savePreferences(); render(); });
  document.querySelector('#download-config')?.addEventListener('click', () => { download(`isohopper.${configFormat === 'yaml' ? 'yml' : 'toml'}`, configText(), 'text/plain'); log('Configuration exported', `Downloaded the ${configFormat.toUpperCase()} preview. No target drive was modified.`); notify('Configuration preview exported.'); });
  document.querySelector('#export-activity')?.addEventListener('click', () => download('isohopper-session.json', JSON.stringify({ experimental: true, exported_at: new Date().toISOString(), bridge_mode: bridgeMode, runtime_capabilities: capabilities ?? null, preparation_snapshot: preparationJob, engine_download_snapshot: engineDownloadJob, events: logs }, null, 2), 'application/json'));
  document.querySelector('#clear-activity')?.addEventListener('click', () => { logs = []; render(); });
  document.querySelectorAll<HTMLButtonElement>('[data-boot]').forEach(button => button.onclick = () => { launcherChoice = Number(button.dataset.boot); render(); document.querySelector<HTMLButtonElement>(`[data-boot="${launcherChoice}"]`)?.focus(); });
}
function bindImageActions() {
  document.querySelectorAll<HTMLButtonElement>('.remove-image').forEach(button => button.onclick = () => void removeImages(new Set([button.dataset.id!])));
  const clear = document.querySelector<HTMLButtonElement>('#clear-images');
  if (clear) clear.onclick = () => void removeImages(new Set(images.map(image => image.id)));
  bindCopyEvents();
}
function bindEngineEvents() {
  bindCopyEvents();
  const advanced = document.querySelector<HTMLDetailsElement>('.engine-advanced');
  if (advanced) advanced.ontoggle = () => { engineAdvanced = advanced.open; };
  document.querySelector('#pick-engine')?.addEventListener('click', pickEngine);
  document.querySelector('#download-engine')?.addEventListener('click', startEngineDownload);
  document.querySelector('#cancel-engine-download')?.addEventListener('click', cancelEngineDownload);
  document.querySelector('#retry-engine-status')?.addEventListener('click', () => void pollEngineDownload());
}
// A progress tick replaces only the engine block. Do not reset another field's
// text, focus, selection, or a typed physical-write confirmation.
function renderEngineDownload() {
  const prerequisites = document.querySelector('#preparation-prerequisites');
  if (prerequisites) prerequisites.innerHTML = preparationPrerequisites();
  const block = document.querySelector('#engine-selection');
  if (block) { block.innerHTML = engineSelectionView(); bindEngineEvents(); }
  const disabled = (selector: string, value: boolean) => document.querySelectorAll<HTMLButtonElement | HTMLSelectElement>(selector).forEach(node => { node.disabled = value; });
  disabled('#start-preparation', !nativePreparationAllowed());
  disabled('#preparation-target', nativeActionsLocked() || installationRequested);
  disabled('#dropzone, #import-folder', busy || pickingImages || releasingImages || !canImport());
  disabled('#refresh-drives', nativeActionsLocked() || !isNative);
  disabled('#probe-helper', nativeActionsLocked());
  disabled('#inspect-host', nativeActionsLocked());
  disabled('#confirm-preparation', !preparationConfirmationAllowed());
  disabled('.remove-image', nativeActionsLocked());
  disabled('#clear-images', nativeActionsLocked() || !images.length);
  disabled('#retry-sources, #refresh-sources', nativeActionsLocked());
}
function scheduleEngineDownloadPoll() {
  clearTimeout(engineDownloadTimer);
  if (engineDownloadJob?.active) engineDownloadTimer = setTimeout(() => void pollEngineDownload(), 750);
}
async function acceptEngineDownload(next: EngineDownloadSnapshot | null) {
  const previous = engineDownloadJob;
  const recovering = engineDownloadStatusError;
  if (!next && previous?.active) throw new Error('Active engine download disappeared; completion is unknown.');
  engineDownloadJob = next;
  engineDownloadLoaded = true;
  engineDownloadStatusError = false;
  if (next && (next.job_id !== previous?.job_id || next.phase !== previous?.phase)) log('Engine download state', `job=${next.job_id} phase=${next.phase} bytes=${next.completed_bytes}/${next.total_bytes} cache_hit=${next.cache_hit} expected_sha256=${next.expected_sha256} ${next.message}`, next.phase === 'failed' ? 'warning' : next.phase === 'ready' ? 'success' : 'info');
  engineDownloadSyncing = true;
  try {
    if (next?.phase !== 'ready') engineSelectionJob = undefined;
    if (next?.phase === 'ready' && engineSelectionJob !== next.job_id) {
      // Only the current catalogue grants a reusable selection. Job history
      // deliberately contains no source capability.
      engineArchive = await bridge.SelectedEngineArchive?.() || null;
      engineSelectionJob = next.job_id;
      if (!engineArchive) engineDownloadError = 'Download verified. No retained engine archive; choose an archive or download again.';
    }
    if ((previous?.active || recovering) && !next?.active && !preparationJob?.active && capabilities?.preparation_available && !preparationTargets.length) {
      try { setPreparationTargets(await bridge.ListPreparationTargets?.() || []); }
      catch (error) { preparationError = errorMessage(error); }
      const target = document.querySelector<HTMLSelectElement>('#preparation-target');
      if (target) target.innerHTML = '<option value="">Choose a target</option>' + visiblePreparationTargets(preparationTargets, showLargeDrives, preparationTarget).map(item => `<option value="${esc(item.selection_token)}" ${preparationTarget === item.selection_token ? 'selected' : ''}>${preparationTargetLabel(item)}</option>`).join('');
    }
  } finally { engineDownloadSyncing = false; }
}
async function pollEngineDownload() {
  if (capabilities?.engine_download !== true || !bridge.EngineDownloadStatus || engineDownloadPolling) return;
  engineDownloadPolling = true;
  try {
    const next = await bridge.EngineDownloadStatus();
    engineDownloadError = '';
    await acceptEngineDownload(next);
  } catch (error) {
    engineDownloadLoaded = false;
    engineDownloadStatusError = true;
    engineDownloadError = `Download status unavailable; operation state retained. ${errorMessage(error)}`;
  } finally { engineDownloadPolling = false; renderEngineDownload(); scheduleEngineDownloadPoll(); await continueRequestedInstallation(); }
}
async function startEngineDownload() {
  if (!bridge.StartEngineDownload || !engineDownloadAllowed()) return;
  engineDownloadRequest = true; engineDownloadError = ''; renderEngineDownload();
  try { await acceptEngineDownload(await bridge.StartEngineDownload()); }
  catch (error) {
    // A rejected reply does not prove that native work never started.
    await pollEngineDownload();
    engineDownloadError = `Download could not start. ${errorMessage(error)}${engineDownloadStatusError ? ' Download status is unknown; retry status.' : ' Retry Download engine or choose an archive.'}`;
  } finally { engineDownloadRequest = false; renderEngineDownload(); scheduleEngineDownloadPoll(); }
}
async function cancelEngineDownload() {
  if (!bridge.CancelEngineDownload || !engineDownloadJob?.active || engineDownloadJob.cancel_requested || engineDownloadCancelling) return;
  const job = engineDownloadJob;
  installationRequested = false;
  engineDownloadCancelling = true; renderEngineDownload();
  try { await bridge.CancelEngineDownload(job.job_id); if (engineDownloadJob?.job_id === job.job_id && engineDownloadJob.active) engineDownloadJob.cancel_requested = true; }
  catch (error) { engineDownloadError = `Cancellation failed. ${errorMessage(error)}`; }
  finally { engineDownloadCancelling = false; render(); scheduleEngineDownloadPoll(); }
}
async function pickEngine() {
  if (nativeActionsLocked() || !bridge.PickEngineArchive) return;
  preparationRequest = true; preparationError = ''; render();
  try { const result = await bridge.PickEngineArchive(); if (result) { engineArchive = result; log('Engine archive selected', `version=${result.version} bytes=${result.bytes} sha256=${result.sha256}`); } }
  catch (error) { preparationError = errorMessage(error); }
  finally { preparationRequest = false; render(); }
}
async function startNativePreparation() {
  if (!bridge.StartPreparation || !nativePreparationAllowed()) return;
  preparationEditing = false;
  preparationJob = null;
  preparationError = ''; preparationPhrase = '';
  if (!engineArchive) {
    installationRequested = true;
    render();
    await startEngineDownload();
    await continueRequestedInstallation();
    return;
  }
  preparationRequest = true; render();
  try { preparationJob = await bridge.StartPreparation(preparationTarget, [], engineArchive.archive_id); busy = preparationJob.active; log('Native preparation started', `job=${preparationJob.job_id} sources=0 physical_write_enabled=${capabilities?.physical_preparation === true}`); schedulePreparationPoll(); }
  catch (error) { preparationError = errorMessage(error); }
  finally { preparationRequest = false; render(); }
}
async function continueRequestedInstallation() {
  if (!installationRequested || engineDownloadRequest || engineDownloadPolling || engineDownloadSyncing || engineDownloadJob?.active) return;
  if (engineDownloadJob?.phase === 'ready' && engineArchive) {
    installationRequested = false;
    await startNativePreparation();
  } else if (engineDownloadLoaded && !engineDownloadStatusError) {
    installationRequested = false;
    preparationError = engineDownloadError || 'Engine download did not complete. Retry installation when ready.';
    render();
  }
}
async function cancelNativePreparation() {
  if (!bridge.CancelPreparation || !preparationJob?.active) return;
  try { await bridge.CancelPreparation(preparationJob.job_id); preparationJob.cancel_requested = true; preparationPhrase = ''; schedulePreparationPoll(); }
  catch (error) { preparationError = errorMessage(error); }
  render();
}
async function confirmNativePreparation() {
  if (!bridge.ConfirmPreparation || !preparationConfirmationAllowed()) return;
  const { job_id: jobId, description_digest: digest } = preparationJob!;
  const challenge = preparationPhrase;
  preparationConfirming = true;
  render();
  try { await bridge.ConfirmPreparation(jobId, digest!, challenge); preparationPhrase = ''; schedulePreparationPoll(); }
  catch (error) { preparationError = errorMessage(error); }
  finally { preparationConfirming = false; render(); }
}

function schedulePreparationPoll() {
  clearTimeout(preparationTimer);
  if (preparationJob?.active) preparationTimer = setTimeout(() => void pollPreparation(), 750);
}
async function pollPreparation() {
  if (!bridge.PreparationStatus || preparationPolling) return;
  preparationPolling = true;
  try {
    const next = await bridge.PreparationStatus();
    const previous = preparationJob;
    if (!next && previous?.active) throw new Error('Active native job disappeared; completion is unknown.');
    if (JSON.stringify(next) !== JSON.stringify(previous)) {
      preparationJob = next; busy = next?.active === true;
      if (next && next.phase !== previous?.phase) log('Native preparation state', `job=${next.job_id} phase=${next.phase} written=${next.bytes_written} verified=${next.bytes_verified} target_may_be_incomplete=${next.target_may_be_incomplete} ${next.message}`, next.phase === 'failed' ? 'warning' : 'info');
      if (next?.sources_released && !previous?.sources_released) { await restoreSources(); engineArchive = await bridge.SelectedEngineArchive?.() || null; }
      render();
    }
  } catch (error) { preparationError = `Preparation status unavailable; operation state retained. ${errorMessage(error)}`; render(); }
  finally { preparationPolling = false; schedulePreparationPoll(); }
}
async function loadPreparation() {
  if (!isNative) return;
  if (capabilities?.preparation_available) await pollPreparation();
  if (capabilities?.engine_download === true) await pollEngineDownload();
  if (!capabilities?.preparation_available) return;
  engineArchive = await bridge.SelectedEngineArchive?.() || null;
  if (!preparationJob?.active && !engineDownloadLocked()) { setPreparationTargets(await bridge.ListPreparationTargets?.() || []); }
}
async function probeHelper() {
  if (nativeActionsLocked() || !isNative || capabilities?.platform !== 'windows' || capabilities.helper_probe !== true || !bridge.ProbeHelper) return;
  probingHelper = true;
  helperStatus = 'Waiting for Windows elevation and helper response. Cancel in the Windows prompt; Studio remains open until the check finishes.';
  render();
  try {
    const result = await bridge.ProbeHelper();
    helperStatus = result.status === 'cancelled' ? 'Windows elevation cancelled. No disk access.' : `Read-only helper connected and exited. protocol=${result.protocol} version=${result.helper_version} pid=${result.helper_pid} created=${result.helper_created} sha256=${result.helper_sha256} physical_preparation=false`;
    log('Elevated helper check', helperStatus, result.status === 'cancelled' ? 'info' : 'success');
  } catch (error) {
    helperStatus = `Helper check failed: ${errorMessage(error)}`;
    log('Elevated helper check failed', helperStatus, 'warning');
  } finally { probingHelper = false; render(); }
}
async function removeImages(rowIds: ReadonlySet<string>) {
  if (nativeActionsLocked()) return;
  releasingImages = true; render();
  try {
    const removed = images.filter(image => rowIds.has(image.id));
    images = await removeMediaImages(images, rowIds, bridge.ReleaseSources);
    complete = false;
    for (const image of removed) log('Image removed from collection', `path=${imagePath(image)}${image.sourceId ? ` source_id=${image.sourceId} status=${images.some(other => other.sourceId === image.sourceId) ? 'retained-by-another-row' : 'released'}` : ''}`);
  } catch (error) {
    const message = `Image removal failed; collection retained. ${errorMessage(error)}`;
    log('Source release failed', message, 'warning'); notify(message);
  } finally { releasingImages = false; render(); }
}
function closeDialog() { deviceDialog = false; render(); document.querySelector<HTMLButtonElement>('#choose-drive')?.focus(); }
document.addEventListener('keydown', event => {
  if (tab !== 'launcher' || deviceDialog || inventoryDialog || event.ctrlKey || event.metaKey || event.altKey || (event.target as HTMLElement)?.closest('input, textarea, select, [contenteditable]')) return;
  const entries = document.querySelectorAll<HTMLButtonElement>('[data-boot]');
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    if (!entries.length) return;
    event.preventDefault();
    launcherChoice = (launcherChoice + (event.key === 'ArrowDown' ? 1 : -1) + entries.length) % entries.length;
    render(); document.querySelector<HTMLButtonElement>(`[data-boot="${launcherChoice}"]`)?.focus();
  }
  const action = ({ r: 'reboot', s: 'shutdown', f: 'firmware_setup' } as Record<string, string>)[event.key.toLowerCase()];
  if (action) { const button = document.querySelector<HTMLButtonElement>(`[data-power-preview="${action}"]`); if (button) { event.preventDefault(); button.click(); } }
});
document.addEventListener('keydown', event => { if (!deviceDialog && !inventoryDialog) return; if (event.key === 'Escape') { if (inventoryDialog) closeInventory(); else closeDialog(); } if (event.key === 'Tab') { const dialog = document.querySelector(inventoryDialog ? '.inventory-dialog' : '.device-dialog'); const items = Array.from(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), summary') || []); const first = items[0]; const last = items[items.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); } } });
async function restoreSources() {
  if (!isNative || sourcesLoading || pickingImages || releasingImages) return;
  sourcesLoading = true; sourcesError = ''; sourceRestoreWarnings = []; render();
  try {
    let retained;
    if (capabilities?.session_restore === true) {
      if (!bridge.RestoreSession) throw new Error('Native session restoration is unavailable.');
      const restored = await bridge.RestoreSession();
      retained = restored.images;
      sourceRestoreWarnings = restored.warnings;
      for (const warning of sourceRestoreWarnings) log('Saved source skipped', warning, 'warning');
    } else {
      if (!bridge.ListSources) throw new Error('Native source listing is unavailable.');
      retained = await bridge.ListSources();
    }
    const restored = retained.map(record => nativeImageForDisplay(record, crypto.randomUUID()));
    // Rehydration is read-only: even conflicting imported destinations retain
    // their own visible rows and IDs so each handle can be released explicitly.
    images = [...images.filter(image => image.origin !== 'native'), ...restored];
    sourcesLoaded = true;
    log('Native sources restored', `count=${restored.length} restoration=${capabilities?.session_restore ? 'native-session' : 'retained-catalogue'}`);
  } catch (error) {
    sourcesError = `Native source listing failed: ${errorMessage(error)} Import is disabled until the catalogue is restored.`;
    log('Native source listing failed', sourcesError, 'warning');
  } finally { sourcesLoading = false; render(); }
}
async function loadDevices() {
  if (nativeActionsLocked()) return;
  refreshing = true; capabilities = undefined; deviceError = ''; confirmation = ''; complete = false; render();
  try {
    capabilities = await bridge.Capabilities();
    if (isNative) { await restoreSources(); await loadPreparation(); }
    if (isDemo) {
      disks = await bridge.ListDisks();
      selected = disks.find(record => record.disk.id === selected?.disk.id && record.verdict.state !== 'blocked') || disks.find(record => record.verdict.state === 'ok');
      log('Fixture devices refreshed', `source=fixtures count=${disks.length} devices=${disks.map(record => `${record.disk.id}:${record.verdict.state}`).join(', ')} host_enumeration=false`);
    } else {
      selected = undefined; plan = undefined;
      if (preparationJob?.active || engineDownloadLocked()) return;
      if (!capabilities.host_inventory || !bridge.InspectDevices) throw new Error('Host inventory is unavailable on this platform.');
      hostInventory = await bridge.InspectDevices(); disks = inspectionRecords(hostInventory);
      log('Host inventory read', `source=${hostInventory.source} disks=${disks.length} warnings=${hostInventory.warnings.length} read_only=true selectable=false`);
      for (const warning of hostInventory.warnings) log('Inventory warning', `${warning.code}${warning.disk_id ? ` [${warning.disk_id}]` : ''}: ${warning.message}`, 'warning');
    }
  } catch (error) {
    disks = []; selected = undefined; plan = undefined; hostInventory = undefined;
    deviceError = `Device list unavailable: ${errorMessage(error)}`; log('Device list unavailable', deviceError, 'warning');
  } finally { refreshing = false; await loadPlan(); render(); }
}
async function loadPlan() {
  if (!isDemo) { plan = undefined; planLoading = false; return; }
  const id = selected?.disk.id; plan = undefined; planError = ''; planLoading = !!id; render();
  if (!id) return;
  try { const next = await bridge.PlanDisk(id); if (selected?.disk.id !== id) return; plan = next; log('Partition plan calculated', `id=${id} bytes=${next.size_bytes} sector_size=${next.logical_sector_size} partitions=${next.partitions.map(part => `${part.name}[${part.start_lba}..${part.end_lba}]`).join(', ')} physical_writes=0`); }
  catch (error) { if (selected?.disk.id !== id) return; planError = `Layout unavailable: ${errorMessage(error)}`; }
  finally { if (selected?.disk.id === id) { planLoading = false; render(); } }
}
async function browseImages(mode: 'files' | 'folder' = 'files') {
  if (busy || pickingImages || releasingImages || !canImport()) return;
  const picker = mode === 'folder' ? bridge.PickDirectory : bridge.PickImages;
  if (!picker) { document.querySelector<HTMLInputElement>(mode === 'folder' ? '#folder-input' : '#file-input')?.click(); return; }
  pickingImages = true; complete = false; render();
  try {
    const selection = await picker();
    const picked = Array.isArray(selection) ? selection : selection.images;
    const warnings = Array.isArray(selection) ? [] : selection.warnings;
    for (const warning of warnings) log('Directory import warning', warning, 'warning');
    const incoming = picked.map(record => nativeImageForDisplay(record, crypto.randomUUID()));
    const result = await mergeNativeImages(images, incoming, bridge.ReleaseSources);
    images = result.images;
    for (const image of result.added) log(image.status === 'error' ? 'Native metadata rejected' : 'Native SHA-256 calculated', `path=${imagePath(image)} bytes=${image.size} source=native source_id=${image.sourceId || 'unavailable'} algorithm=SHA-256 status=${image.status === 'error' ? 'error' : 'hash-only'} digest=${image.hash || 'unavailable'} publisher_verified=false`, image.status === 'error' ? 'warning' : 'success');
    for (const image of result.skipped) log('Destination skipped', `path=${imagePath(image)} reason=destination-already-present${image.sourceId ? ` source_id=${image.sourceId} status=released-or-retained-by-existing-row` : ''}`, 'warning');
    if (result.releaseError) { log('Source release failed', result.releaseError, 'warning'); notify(`Duplicate source release failed: ${result.releaseError} Remove the error row to retry.`); }
    else if (warnings.length) notify(`${result.added.length} images added; ${warnings.length} directory warning(s). ${warnings[0]} See Activity for all warnings.`);
    else if (picked.length) notify(`${result.added.length} image${result.added.length === 1 ? '' : 's'} added. SHA-256 only; publisher not verified.`);
  } catch (error) {
    const message = `Native image selection failed. ${errorMessage(error)}`;
    log('Image selection failed', message, 'warning'); notify(message);
  } finally { pickingImages = false; render(); }
}
async function addFiles(files: File[]) {
  if (busy || pickingImages || releasingImages || !canImport()) return;
  complete = false; pickingImages = true; render();
  try {
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
  } finally { pickingImages = false; render(); }
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
