import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { StagingAutomaticProjectMemory, type AutomaticMemoryContext, type AutomaticMemoryGoal } from './staging-automatic-project-memory.js';

const workspaceA = { id: 'f0c39e2d-8817-4d35-9a22-6b4178c2de91', realRootPath: 'D:\\Synthetic\\A' };
const workspaceB = { id: 'e0c39e2d-8817-4d35-9a22-6b4178c2de92', realRootPath: 'D:\\Synthetic\\B' };
const goal = { id: 'e0c39e2d-8817-4d35-9a22-6b4178c2de95', status: 'active', revision: 3 };
function makeFakeBackend() {
  const banks = new Set<string>();
  const contents = new Map<string, string>();
  const seen: Array<{ url: string; method: string; body: string }> = [];
  const transport = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    const body = String(init?.body ?? '');
    seen.push({ url, method, body });
    expect(url.startsWith('http://127.0.0.1:18888/v1/default/banks/')).toBe(true);
    const bank = /\/banks\/(project-[0-9a-f]{24})/.exec(url)?.[1];
    if (!bank) return new Response('{}', { status: 404 });
    if (url.endsWith('/stats')) return new Response(banks.has(bank) ? '{}' : '{"detail":"missing"}', { status: banks.has(bank) ? 200 : 404 });
    if (method === 'PUT') { banks.add(bank); return new Response('{"bank_id":"' + bank + '"}'); }
    if (url.endsWith('/memories') && method === 'POST') {
      const payload = JSON.parse(body) as { items: Array<{ content: string }> };
      contents.set(bank, payload.items[0]!.content);
      return new Response('{"success":true}');
    }
    if (url.endsWith('/memories/recall') && method === 'POST') {
      return new Response(JSON.stringify({ results: [{ text: contents.get(bank) ?? 'unexpected' }] }));
    }
    return new Response('{}', { status: 404 });
  }) as unknown as typeof fetch;
  return { banks, contents, seen, transport };
}
afterEach(() => {
  delete process.env.LNWJUD_STAGING_HINDSIGHT_URL;
});
describe('isolated staging automatic project-memory metadata lifecycle', () => {
  it('fails closed unless Host owns the Staging opt-in and explicit workspace selection', async () => {
    const fake = makeFakeBackend();
    let enabled = false, selected: typeof workspaceA | null = workspaceA;
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => enabled, selectedWorkspace: async () => selected,
      goalStatuses: async () => [goal], onContext: () => {}, fetcher: fake.transport,
    });
    await manager.syncSelected();
    enabled = true; selected = null;
    await manager.syncSelected();
    expect(fake.seen).toHaveLength(0);
    manager.close();
  });

  it('creates only the hashed Host-selected bank, captures allowlisted goal metadata, and automatically restores it', async () => {
    const fake = makeFakeBackend();
    const contexts: AutomaticMemoryContext[] = [];
    const privateGoal = { ...goal, status: 'blocked', revision: 9, objective: 'password=should-never-leak' };
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => workspaceA,
      goalStatuses: async () => [privateGoal] as readonly AutomaticMemoryGoal[],
      onContext: (context) => contexts.push(context), fetcher: fake.transport,
    });
    await manager.syncSelected();
    const bank = 'project-' + createHash('sha256').update(workspaceA.id).digest('hex').slice(0, 24);
    expect([...fake.banks]).toEqual([bank]);
    const bankCreation = fake.seen.find(
      (request) => request.method === 'PUT' && request.url.endsWith('/' + bank),
    );
    expect(bankCreation).toBeDefined();
    expect(JSON.parse(bankCreation!.body)).toMatchObject({
      retain_extraction_mode: 'chunks',
      enable_observations: false,
    });
    expect(contexts).toHaveLength(1);
    expect(contexts[0]!.workspaceId).toBe(workspaceA.id);
    expect(contexts[0]!.records).toHaveLength(1);
    const payload = fake.seen.find((request) => request.url.endsWith('/memories'))?.body ?? '';
    expect(payload).toContain('"update_mode":"replace"');
    expect(payload).toContain('blocked');
    expect(payload).not.toContain('password');
    expect(payload).not.toContain('should-never-leak');
    expect(payload).not.toContain(workspaceA.realRootPath);
    expect(manager.cached(workspaceB.id)).toBeNull();
    manager.close();
    expect(manager.cached(workspaceA.id)).toBeNull();
  });

  it('does not create duplicate documents when the selected project state is unchanged', async () => {
    const fake = makeFakeBackend();
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => workspaceA,
      goalStatuses: async () => [goal], onContext: () => {}, fetcher: fake.transport,
    });
    await manager.syncSelected();
    await manager.syncSelected();
    expect(fake.seen.filter((request) => request.url.endsWith('/memories') && request.method === 'POST')).toHaveLength(1);
    manager.close();
  });

  it('blocks backend writes when a user switches projects before bank initialization', async () => {
    const fake = makeFakeBackend();
    let selected = workspaceA;
    const originalFetch = fake.transport;
    const transport = (async (input: string | URL | Request, init?: RequestInit) => {
      const result = await originalFetch(input, init);
      selected = workspaceB;
      return result;
    }) as typeof fetch;
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => selected,
      goalStatuses: async () => [goal], onContext: () => {}, fetcher: transport,
    });
    await manager.syncSelected();
    expect(fake.seen.filter((request) => request.url.endsWith('/memories'))).toHaveLength(0);
    manager.close();
  });

  it('prevents stale memory writes when the selected workspace changes during goal enumeration', async () => {
    const fake = makeFakeBackend();
    let selected = workspaceA;
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => true,
      selectedWorkspace: async () => selected,
      goalStatuses: async () => { selected = workspaceB; return [goal]; },
      onContext: () => { throw Error('Stale context must not be emitted'); },
      fetcher: fake.transport,
    });
    await manager.syncSelected();
    expect(fake.seen.filter((request) => request.url.endsWith('/memories')
      || request.url.endsWith('/memories/recall'))).toHaveLength(0);
    manager.close();
  });

  it('refuses any environment override towards Production without an HTTP request', async () => {
    const fake = makeFakeBackend();
    process.env.LNWJUD_STAGING_HINDSIGHT_URL = 'http://127.0.0.1:8888';
    const manager = new StagingAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => workspaceA,
      goalStatuses: async () => [], onContext: () => {}, fetcher: fake.transport,
    });
    await expect(manager.syncSelected()).rejects.toThrow(/endpoint rejected/);
    expect(fake.seen).toHaveLength(0);
    manager.close();
  });
});
