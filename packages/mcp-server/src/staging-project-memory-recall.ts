// Isolated Staging-only Windows single-user project memory read.
// Authorization is an exact native Desktop approval, NOT a remote MCP identity.
// This module never registers a tool or enables itself.
import { createHash } from 'node:crypto';
import type { HostMutationApprovalRequest, WorkspaceScope } from './tool-registry.js';

const WORKSPACE_ID = /^[A-Za-z0-9][\w.-]{0,127}$/;
const SENSITIVE = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:api[_-]?key|access[_-]?token|password|bearer)\b/i;

// Host-owned project identity, not a caller-supplied MCP parameter.
// The initial Staging mapping uses the registered Workspace ID as projectId.
// Existing Gateway banks with a different projectId are NOT silently imported.
export interface StagingApprovedProjectScope extends WorkspaceScope {
  readonly projectId: string;
  readonly approved: true;
}

export interface StagingHindsightEntry {
  readonly content: string;
  readonly ref: string;
}
export interface StagingMemoryRecallResult {
  readonly projectId: string;
  readonly results: readonly StagingHindsightEntry[];
  readonly authoritative: false;
}
export interface StagingMemoryReaderOptions {
  readonly enabled: () => boolean;
  readonly getSelectedWorkspace: () => Promise<StagingApprovedProjectScope | null>;
  readonly nativeApproval: (request: HostMutationApprovalRequest) => boolean | Promise<boolean>;
  readonly recallBank: (bank: string, query: string, limit: number) => Promise<readonly StagingHindsightEntry[]>;
}

export function createStagingSingleUserMemoryRecall(options: StagingMemoryReaderOptions):
  (query: string, limit?: number) => Promise<StagingMemoryRecallResult> {
  if (typeof options.enabled !== 'function'
    || typeof options.getSelectedWorkspace !== 'function'
    || typeof options.nativeApproval !== 'function'
    || typeof options.recallBank !== 'function') throw Error('Host authority unavailable');
  let inFlight = false;
  const denied = (): never => { throw Error('Project memory unavailable or denied'); };
  const scopeValid = (scope: StagingApprovedProjectScope | null): scope is StagingApprovedProjectScope =>
    scope !== null && scope.approved === true && WORKSPACE_ID.test(scope.workspaceId)
    && WORKSPACE_ID.test(scope.projectId)
    && typeof scope.rootPath === 'string' && scope.rootPath.length > 0;
  const same = (a: StagingApprovedProjectScope, b: StagingApprovedProjectScope | null): boolean =>
    scopeValid(b) && b.workspaceId === a.workspaceId && b.rootPath === a.rootPath
    && b.projectId === a.projectId;

  return async (query: string, limit = 5) => {
    if (!options.enabled() || typeof query !== 'string' || !query.trim()
      || query.length > 400 || SENSITIVE.test(query)
      || !Number.isInteger(limit) || limit < 1 || limit > 10 || inFlight) return denied();
    inFlight = true;
    try {
      const before = await options.getSelectedWorkspace();
      if (!scopeValid(before) || !options.enabled()) return denied();
      const approved = await options.nativeApproval({
        toolName: 'candidate_project_memory_recall',
        mutationKind: 'read',
        reason: 'Explicit single-use native Host approval for local project-memory disclosure',
        summary: `Read-only memory for project ${before.projectId} (workspace ${before.workspaceId}); exact query: ${JSON.stringify(query)}`,
        workspaceId: before.workspaceId,
        workspaceRoot: before.rootPath,
      });
      if (approved !== true || !options.enabled() || !same(before, await options.getSelectedWorkspace())) return denied();

      // Match original Gateway precisely: bank = SHA256(Host-approved projectId).
      // A foreign caller cannot choose projectId via MCP input.
      const bank = 'project-' + createHash('sha256').update(before.projectId).digest('hex').slice(0, 24);
      const records = await options.recallBank(bank, query, limit);
      if (!Array.isArray(records) || !options.enabled()
        || !same(before, await options.getSelectedWorkspace())) return denied();
      return {
        projectId: before.projectId,
        results: records.slice(0, limit).filter(
          record => typeof record?.content === 'string' && !SENSITIVE.test(record.content),
        ).map(record => ({ content: record.content.slice(0, 2000), ref: String(record.ref ?? '').slice(0, 128) })),
        authoritative: false as const,
      };
    } finally {
      inFlight = false;
    }
  };
}

export async function recallStagingHindsight(bank: string, query: string, limit: number):
  Promise<readonly StagingHindsightEntry[]> {
  if (!/^project-[a-f0-9]{24}$/.test(bank)) throw Error('Invalid project bank');
  // Fail closed: never fall back to the existing Production Hindsight service.
  const endpoint = process.env.LNWJUD_STAGING_HINDSIGHT_URL?.trim();
  if (endpoint !== 'http://127.0.0.1:18888') throw Error('Isolated Staging Hindsight endpoint unavailable');
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
