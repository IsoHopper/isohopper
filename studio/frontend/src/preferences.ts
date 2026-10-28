// SPDX-License-Identifier: GPL-3.0-or-later
export interface TargetHint { serial: string; size: number; bus: number }
export interface StudioOptions { netboot: boolean; systemInfo: boolean; memtest: boolean; timeout: number; theme: 'midnight' | 'aurora'; policy: 'enforce' | 'prompt' | 'off'; power: { reboot: boolean; shutdown: boolean; firmware_setup: boolean } }
export interface StudioPreferences { version: 1; options: StudioOptions; configFormat: 'yaml' | 'toml'; customConfig?: string; showLargeDrives: boolean; targetHint?: TargetHint }
export const preferencesKey = 'isohopper-preferences-v1';
const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
export function parsePreferences(text: string | null): StudioPreferences {
  const defaults: StudioPreferences = { version: 1, options: { netboot: true, systemInfo: true, memtest: true, timeout: 10, theme: 'midnight', policy: 'enforce', power: { reboot: true, shutdown: true, firmware_setup: true } }, configFormat: 'yaml', showLargeDrives: false };
  let value: Record<string, unknown>;
  try { value = object(JSON.parse(text || 'null')); } catch { return defaults; }
  if (value.version !== 1) return defaults;
  const options = object(value.options), power = object(options.power), hint = object(value.targetHint);
  for (const key of ['netboot', 'systemInfo', 'memtest'] as const) if (typeof options[key] === 'boolean') defaults.options[key] = options[key];
  for (const key of ['reboot', 'shutdown', 'firmware_setup'] as const) if (typeof power[key] === 'boolean') defaults.options.power[key] = power[key];
  if (Number.isSafeInteger(options.timeout) && Number(options.timeout) >= 0 && Number(options.timeout) <= 300) defaults.options.timeout = Number(options.timeout);
  if (options.theme === 'midnight' || options.theme === 'aurora') defaults.options.theme = options.theme;
  if (options.policy === 'enforce' || options.policy === 'prompt' || options.policy === 'off') defaults.options.policy = options.policy;
  if (value.configFormat === 'toml') defaults.configFormat = 'toml';
  if (typeof value.customConfig === 'string' && value.customConfig.length <= 131072) defaults.customConfig = value.customConfig;
  if (typeof value.showLargeDrives === 'boolean') defaults.showLargeDrives = value.showLargeDrives;
  if (typeof hint.serial === 'string' && hint.serial.trim() && hint.serial.length <= 4096 && Number.isSafeInteger(hint.size) && Number(hint.size) > 0 && (hint.bus === 7 || hint.bus === 12)) defaults.targetHint = { serial: hint.serial, size: Number(hint.size), bus: hint.bus };
  return defaults;
}
