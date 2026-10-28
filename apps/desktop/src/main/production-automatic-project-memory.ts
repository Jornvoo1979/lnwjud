/**
 * Opt-in Windows Production capture of allowlisted project lifecycle metadata.
 * This never captures prompts, file contents, paths, credentials or chat text.
 * No MCP caller can enable capture, and reading still requires Native Consent.
 */
import { createHash } from 'node:crypto';

const ENDPOINT = 'http://127.0.0.1:8888';
const PROJECT_ID = /^[a-zA-Z0-9][\w.-]{0,127}$/;
const GOAL_ID = /^[0-9a-f]{8}-[0-9a-f-]{27,36}$/i;
const STATUSES = ['active', 'blocked', 'completed', 'failed', 'cancelled'] as const;

export interface ProductionMemoryWorkspace {
  readonly id: string;
  readonly realRootPath: string;
}
export interface ProductionMemoryGoal {
  readonly id: string;
  readonly status: string;
  readonly revision: number;
}
export interface ProductionAutomaticMemoryOptions {
  readonly enabled: () => boolean;
  readonly selectedWorkspace: () => Promise<ProductionMemoryWorkspace | null>;
  readonly goalStatuses: (workspaceId: string) => Promise<readonly ProductionMemoryGoal[]>;
  readonly fetcher?: typeof fetch;
}

export class ProductionAutomaticProjectMemory {
  private readonly fetcher: typeof fetch;
  private readonly remembered = new Map<string, string>();
  private readonly pending = new Map<string, Promise<void>>();
  private readonly queued = new Set<string>();
  private closed = false;

  constructor(private readonly options: ProductionAutomaticMemoryOptions) {
    this.fetcher = options.fetcher ?? fetch;
  }

  close(): void {
    this.closed = true;
    this.queued.clear();
    this.remembered.clear();
  }

  async syncSelected(): Promise<void> {
    if (!this.active()) return;
    const workspace = await this.options.selectedWorkspace();
    if (!workspace || !PROJECT_ID.test(workspace.id) || !workspace.realRootPath) return;
    // Fail closed. No redirect to Staging, a remote server, or a fallback.
    if (process.env.LNWJUD_PRODUCTION_HINDSIGHT_URL?.trim() !== ENDPOINT) {
      throw new Error('Production automatic memory endpoint unavailable');
    }
    const existing = this.pending.get(workspace.id);
    if (existing) {
      // A Goal may have changed while an earlier snapshot is being written.
      // Coalesce concurrent notifications into one trailing refresh.
      this.queued.add(workspace.id);
      return existing;
    }
    const operation = this.drainSync(workspace);
    this.pending.set(workspace.id, operation);
    return operation;
  }

  private async drainSync(workspace: ProductionMemoryWorkspace): Promise<void> {
    try {
      do {
        this.queued.delete(workspace.id);
        await this.performSync(workspace);
      } while (this.queued.has(workspace.id) && await this.stillSelected(workspace));
    } finally {
      this.queued.delete(workspace.id);
      this.pending.delete(workspace.id);
    }
  }

  private active(): boolean {
    return !this.closed && this.options.enabled();
  }

  private async stillSelected(before: ProductionMemoryWorkspace): Promise<boolean> {
    if (!this.active()) return false;
    const selected = await this.options.selectedWorkspace();
    return selected !== null
      && selected.id === before.id
      && selected.realRootPath === before.realRootPath;
  }

  private async request(url: string, method = 'GET', payload?: unknown): Promise<number> {
    const response = await this.fetcher(url, {
      method,
      ...(payload === undefined ? {} : {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 404 && url.endsWith('/stats')) return 404;
    if (!response.ok) throw new Error('Production automatic metadata backend unavailable');
    return response.status;
  }

  private async performSync(workspace: ProductionMemoryWorkspace): Promise<void> {
    if (!await this.stillSelected(workspace)) return;
    const bank = 'project-' + createHash('sha256').update(workspace.id).digest('hex').slice(0, 24);
    const base = ENDPOINT + '/v1/default/banks/' + bank;
    const status = await this.request(base + '/stats');
    if (!await this.stillSelected(workspace)) return;
    if (status === 404) {
      await this.request(base, 'PUT', {
        name: 'production-project-lifecycle-' + workspace.id,
        retain_extraction_mode: 'verbatim',
        enable_observations: false,
      });
    }
    if (!await this.stillSelected(workspace)) return;
    const goals = await this.options.goalStatuses(workspace.id);
    if (!await this.stillSelected(workspace)) return;
    // The Host repository returns at most 50 entries; never imply a full-project count.
    const safe = goals.slice(0, 50).filter((goal) => GOAL_ID.test(goal.id)
      && STATUSES.some((status) => status === goal.status)
      && Number.isSafeInteger(goal.revision) && goal.revision >= 0);
    const counts = STATUSES.map((status) =>
      status + '=' + safe.filter((goal) => goal.status === status).length).join('; ');
    const revisions = [...safe].sort((a, b) => a.id.localeCompare(b.id)).slice(0, 25)
      .map((goal) => goal.id + ':' + goal.status + ':r' + goal.revision).join(',');
    const content = 'Production project lifecycle, workspace ' + workspace.id
      + '. Sampled goal status counts (up to 50 host-listed goals): ' + counts
      + '. Sampled goal IDs/status/revisions: ' + revisions;
    const fingerprint = createHash('sha256').update(content).digest('hex');
    if (this.remembered.get(workspace.id) === fingerprint) return;
    if (!await this.stillSelected(workspace)) return;
    await this.request(base + '/memories', 'POST', {
      async: false,
      items: [{
        content,
        document_id: 'production-project-lifecycle-' + workspace.id,
        update_mode: 'replace',
        tags: ['production-project-lifecycle-metadata'],
      }],
    });
    this.remembered.set(workspace.id, fingerprint);
  }
}
