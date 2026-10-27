/**
 * Explicit, locally approved Production read. Not enabled or registered unless
 * the packaged Windows Desktop opts in and supplies its native approval provider.
 * Production banks derive only from the Host-selected Workspace ID.
 * This does not migrate, import, or disclose any Staging memory bank.
 */
import { createStagingSingleUserMemoryRecall } from './staging-project-memory-recall.js';
import type { StagingMemoryReaderOptions } from './staging-project-memory-recall.js';

export function createProductionSingleUserMemoryRecall(options: StagingMemoryReaderOptions) {
  return createStagingSingleUserMemoryRecall({ ...options, approvalToolName: 'project_memory_recall' });
}

export async function recallProductionHindsight(bank: string, query: string, limit: number):
  Promise<readonly StagingHindsightEntry[]> {
  if (!/^project-[a-f0-9]{24}$/.test(bank)) throw Error('Invalid project bank');
  // Fail closed: never fall back to the existing Production Hindsight service.
  const endpoint = process.env.LNWJUD_PRODUCTION_HINDSIGHT_URL?.trim();
  if (endpoint !== 'http://127.0.0.1:8888') throw Error('Production project-memory endpoint unavailable');
  const url = new URL(`/v1/default/banks/${bank}/memories/recall`, endpoint);
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, budget: 'low', max_tokens: 1024 }),
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw Error('Project memory backend unavailable');
  const payload: unknown = await response.json();
  if (typeof payload !== 'object' || payload === null
    || !('results' in payload) || !Array.isArray(payload.results)) throw Error('Invalid backend response');
  return payload.results.slice(0, limit).map((entry: unknown) => {
    if (typeof entry !== 'object' || entry === null) return { content: '', ref: '' };
    const record = entry as Record<string, unknown>;
    return {
      content: typeof record.text === 'string' ? record.text : typeof record.content === 'string' ? record.content : '',
      ref: typeof record.id === 'string' ? record.id : '',
    };
  });
}
