import { invoke } from '@tauri-apps/api/core';
import type { DetailedCacheInfo } from '../types';

export function getDetailedTranscodeCache(refresh = false): Promise<DetailedCacheInfo> {
  // The native command returns its most recent inventory snapshot immediately.
  // Filesystem reconciliation is single-flight background work, so a frontend
  // deadline would only mislabel a healthy but large cache as failed.
  return invoke<DetailedCacheInfo>('cmd_get_detailed_transcode_cache', { refresh });
}

export function transcodeCacheErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
