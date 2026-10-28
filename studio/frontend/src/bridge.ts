// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { createNativeBridge, type NativeBridge, type NativeInvoke } from './native';
import { demoBridge, demoImages } from './demo';
declare global { interface Window { __TAURI__?: { core?: { invoke: NativeInvoke } }; __TAURI_INTERNALS__?: unknown } }
const invoke = window.__TAURI__?.core?.invoke;
export const nativeHost = window.__TAURI__ !== undefined || window.__TAURI_INTERNALS__ !== undefined;
export const isDemo = !nativeHost && new URLSearchParams(window.location.search).get('demo') === '1';
export const isNative = typeof invoke === 'function';
export const bridgeMode = isNative ? 'Native runtime' : isDemo ? 'Browser file I/O · demo hardware inventory' : 'Native desktop runtime unavailable';
export const initialImages = isDemo ? demoImages() : [];
const unavailable = async (): Promise<never> => { throw new Error('Native desktop runtime unavailable. Open the desktop application.'); };
export const bridge: NativeBridge = isNative ? createNativeBridge(invoke!) : isDemo ? demoBridge : {
  Capabilities: unavailable,
  ListDisks: unavailable,
  PlanDisk: unavailable,
  CheckConfig: unavailable
};
