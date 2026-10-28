// SPDX-License-Identifier: GPL-3.0-or-later
export interface EngineDownloadSnapshot {
  job_id: string;
  phase: 'checking_cache' | 'downloading' | 'verifying' | 'ready' | 'failed' | 'cancelled';
  active: boolean;
  cancel_requested: boolean;
  completed_bytes: number;
  total_bytes: number;
  expected_sha256: string;
  version: string;
  cache_hit: boolean;
  message: string;
}
const fields = 'active,cache_hit,cancel_requested,completed_bytes,expected_sha256,job_id,message,phase,total_bytes,version';
export function engineDownloadSnapshot(value: unknown): EngineDownloadSnapshot {
  if (!value || typeof value !== 'object') throw new Error('Invalid native engine download response.');
  const v = value as EngineDownloadSnapshot;
  const activePhase = ['checking_cache', 'downloading', 'verifying'].includes(v.phase);
  if (Object.keys(v).sort().join(',') !== fields ||
      typeof v.job_id !== 'string' || !/^[a-f0-9]{64}$/.test(v.job_id) ||
      !['checking_cache', 'downloading', 'verifying', 'ready', 'failed', 'cancelled'].includes(v.phase) ||
      typeof v.active !== 'boolean' || v.active !== activePhase ||
      typeof v.cancel_requested !== 'boolean' || typeof v.cache_hit !== 'boolean' ||
      !Number.isSafeInteger(v.completed_bytes) || v.completed_bytes < 0 || v.completed_bytes > v.total_bytes ||
      v.total_bytes !== 20_320_548 || v.version !== '1.1.18' ||
      v.expected_sha256 !== 'd86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54' ||
      (v.phase === 'ready' && (v.completed_bytes !== v.total_bytes || v.cancel_requested)) ||
      (v.phase === 'cancelled' && !v.cancel_requested) ||
      typeof v.message !== 'string' || v.message.length > 8192) throw new Error('Invalid native engine download response.');
  return v;
}
