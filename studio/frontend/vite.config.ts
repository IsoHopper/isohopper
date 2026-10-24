// SPDX-FileCopyrightText: 2026 S33G
// SPDX-License-Identifier: GPL-3.0-or-later
import { defineConfig } from 'vitest/config';
export default defineConfig({ base: './', test: { include: ['src/**/*.test.ts'] } });
