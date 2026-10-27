/**
 * Isolated Windows Staging-only automatic project-memory lifecycle.
 * This is an internal Host workflow, never a remote MCP read authorization.
 * Only allowlisted goal status metadata is retained; no files, prompts, queries,
 * paths, goal objectives, raw logs or credentials enter the memory bank.
 */
import { createHash } from 'node:crypto';

const ENDPOINT = 'http://127.0.0.1:18888';
const IDENTIFIER = /^[A-Za-z0-9][\w.-]{0,127}$/;
const SUPPORTED_STATUSES = ['active', 'blocked', 'completed', 'failed', 'cancelled'] as const;

export interface AutomaticMemoryWorkspace {
  readonly id: string;
  readonly realRootPath: string;
}
export interface AutomaticMemoryGoal {
  readonly id: string;
  readonly status: string;
  readonly revision: number;
}
export interface AutomaticMemoryContext {
  readonly workspaceId: string;
  readonly records: readonly string[];
  readonly refreshedAt: string;
}
export interface AutomaticProjectMemoryOptions {
  readonly enabled: () => boolean;
  readonly selectedWorkspace: () => Promise<AutomaticMemoryWorkspace | null>;
  readonly goalStatuses: (workspaceId: string) => Promise<readonly AutomaticMemoryGoal[]>;
  readonly onContext: (context: AutomaticMemoryContext) => void;
  readonly fetcher?: typeof fetch;
}

function projectBank(workspaceId: string): string {
  if (!IDENTIFIER.test(workspaceId)) throw Error('Invalid staging project ID');
  return 'project-' + createHash('sha256').update(workspaceId).digest('hex').slice(0, 24);
}
function isSameWorkspace(before: AutomaticMemoryWorkspace, after: AutomaticMemoryWorkspace | null): boolean {
  return after !== null && before.id === after.id && before.realRootPath === after.realRootPath;
}
function goalStatusRecord(workspaceId: string, goals: readonly AutomaticMemoryGoal[]): string {
  const allowed = goals.filter((goal) => /^(?:[0-9a-f]{8}-[0-9a-f-]{27,36})$/i.test(goal.id)
    && SUPPORTED_STATUSES.some((status) => status === goal.status)
    && Number.isSafeInteger(goal.revision) && goal.revision >= 0);
  const counts = SUPPORTED_STATUSES.map((status) =>
    status + '=' + allowed.filter((goal) => goal.status === status).length).join('; ');
  const revisions = [...allowed].sort((a, b) => a.id.localeCompare(b.id)).slice(0, 25)
    .map((goal) => goal.id + ':' + goal.status + ':r' + goal.revision).join(',');
  return 'Staging automatic project lifecycle, workspace ' + workspaceId
    + '. Goal status counts: ' + counts + '. Tracked goal IDs/status/revisions: ' + revisions;
}

export class StagingAutomaticProjectMemory {
  private readonly fetcher: typeof fetch;
  private readonly remembered = new Map<string, string>();
  private readonly restored = new Map<string, AutomaticMemoryContext>();
  private readonly pending = new Map<string, Promise<void>>();
  private closed = false;
  constructor(private readonly options: AutomaticProjectMemoryOptions) {
    this.fetcher = options.fetcher ?? fetch;
  }

  cached(workspaceId: string): AutomaticMemoryContext | null {
    return this.restored.get(workspaceId) ?? null;
  }

  /** Idempotent per-workspace in-process; failures are visible to the Host caller. */
  async syncSelected(): Promise<void> {
    if (this.closed || !this.options.enabled()) return;
    const workspace = await this.options.selectedWorkspace();
    if (!workspace || !IDENTIFIER.test(workspace.id) || !workspace.realRootPath) return;
    if (process.env.LNWJUD_STAGING_HINDSIGHT_URL?.trim()
      && process.env.LNWJUD_STAGING_HINDSIGHT_URL.trim() !== ENDPOINT) {
      throw Error('Staging automatic memory endpoint rejected');
    }
    const existing = this.pending.get(workspace.id);
    if (existing) return existing;
    const work = this.performSync(workspace);
    this.pending.set(workspace.id, work);
    try { await work; } finally {
      if (this.pending.get(workspace.id) === work) this.pending.delete(workspace.id);
    }
  }

  private async send<T>(url: string, init: RequestInit = {}): Promise<{ status: number; value: T | null }> {
    const response = await this.fetcher(url, {
      ...init, redirect: 'error', signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 404 && url.endsWith('/stats')) return { status: 404, value: null };
    if (!response.ok) throw Error('Staging automatic memory backend request failed (' + response.status + ')');
    return { status: response.status, value: await response.json() as T };
  }
  private async performSync(workspace: AutomaticMemoryWorkspace): Promise<void> {
    if (this.closed || !this.options.enabled()) return;
    const bank = projectBank(workspace.id);
    const base = ENDPOINT + '/v1/default/banks/' + bank;
    const stats = await this.send<Record<string, unknown>>(base + '/stats');
    // A selection change during the lookup must not create the old bank.
    if (!isSameWorkspace(workspace, await this.options.selectedWorkspace())
      || this.closed || !this.options.enabled()) return;
    if (stats.status === 404) {
      await this.send(base, {
        method: 'PUT', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'staging-automatic-project-memory-' + workspace.id,
          retain_extraction_mode: 'chunks',
          enable_observations: false,
        }),
      });
    }
    if (!isSameWorkspace(workspace, await this.options.selectedWorkspace())
      || this.closed || !this.options.enabled()) return;

    const goals = await this.options.goalStatuses(workspace.id);
    // Goal enumeration may be slow; never write after a project switch.
    if (!isSameWorkspace(workspace, await this.options.selectedWorkspace())
      || this.closed || !this.options.enabled()) return;
    const content = goalStatusRecord(workspace.id, goals);
    const fingerprint = createHash('sha256').update(content).digest('hex');
    if (this.remembered.get(workspace.id) !== fingerprint) {
      await this.send(base + '/memories', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          async: false,
          items: [{
            content,
            document_id: 'automatic-project-lifecycle-' + workspace.id,
            update_mode: 'replace',
            tags: ['staging-automatic-lifecycle'],
          }],
        }),
      });
      this.remembered.set(workspace.id, fingerprint);
    }
    if (!isSameWorkspace(workspace, await this.options.selectedWorkspace())
      || this.closed || !this.options.enabled()) return;

    const recall = await this.send<{ results?: Array<{ text?: unknown; content?: unknown }> }>(base + '/memories/recall', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'automatic project lifecycle goal statuses', budget: 'low', max_tokens: 1024 }),
    });
    if (!isSameWorkspace(workspace, await this.options.selectedWorkspace())
      || this.closed || !this.options.enabled()) return;
    const records = (recall.value?.results ?? []).slice(0, 8)
      .map((item) => typeof item.text === 'string' ? item.text : item.content)
      .filter((value): value is string => typeof value === 'string'
        && value.startsWith('Staging automatic project lifecycle, workspace ' + workspace.id + '.'))
      .map((value) => value.slice(0, 1600));
    const context = { workspaceId: workspace.id, records, refreshedAt: new Date().toISOString() };
    this.restored.set(workspace.id, context);
    this.options.onContext(context);
  }

  close(): void {
    this.closed = true;
    this.restored.clear();
    this.remembered.clear();
  }
}
