import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { ProductionAutomaticProjectMemory } from './production-automatic-project-memory.js';

const workspaceA = { id: 'f0c39e2d-8817-4d35-9a22-6b4178c2de91', realRootPath: 'D:\\ProjectA' };
const workspaceB = { id: 'e0c39e2d-8817-4d35-9a22-6b4178c2de92', realRootPath: 'D:\\ProjectB' };
const goal = { id: 'e0c39e2d-8817-4d35-9a22-6b4178c2de95', status: 'completed', revision: 9, objective: 'SECRET_SHOULD_NOT_APPEAR' };

afterEach(() => vi.unstubAllEnvs());

describe('opt-in Production lifecycle metadata only', () => {
  it('does not send requests when disabled, without selection, or with wrong backend endpoint', async () => {
    const fetcher = vi.fn() as unknown as typeof fetch;
    let enabled = false;
    let selected: typeof workspaceA | null = workspaceA;
    const capture = new ProductionAutomaticProjectMemory({
      enabled: () => enabled, selectedWorkspace: async () => selected,
      goalStatuses: async () => [goal], fetcher,
    });
    await capture.syncSelected();
    enabled = true;
    selected = null;
    await capture.syncSelected();
    selected = workspaceA;
    vi.stubEnv('LNWJUD_PRODUCTION_HINDSIGHT_URL', 'http://127.0.0.1:18888');
    await expect(capture.syncSelected()).rejects.toThrow(/endpoint unavailable/);
    expect(fetcher).not.toHaveBeenCalled();
    capture.close();
  });

  it('writes one idempotent, project-scoped metadata document without private fields', async () => {
    vi.stubEnv('LNWJUD_PRODUCTION_HINDSIGHT_URL', 'http://127.0.0.1:8888');
    const seen: Array<{ url: string; method: string; body: string }> = [];
    const fetcher = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const item = { url: String(url), method: init?.method ?? 'GET', body: String(init?.body ?? '') };
      seen.push(item);
      if (item.url.endsWith('/stats')) return new Response('{}', { status: 404 });
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
    const capture = new ProductionAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => workspaceA,
      goalStatuses: async () => [goal], fetcher,
    });
    await capture.syncSelected();
    await capture.syncSelected();
    const bank = 'project-' + createHash('sha256').update(workspaceA.id).digest('hex').slice(0, 24);
    expect(seen.every((request) => request.url.startsWith('http://127.0.0.1:8888/v1/default/banks/' + bank))).toBe(true);
    const posts = seen.filter((request) => request.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0]!.body).toContain('"update_mode":"replace"');
    expect(posts[0]!.body).toContain('completed');
    expect(posts[0]!.body).not.toContain('SECRET_SHOULD_NOT_APPEAR');
    expect(posts[0]!.body).not.toContain(workspaceA.realRootPath);
    capture.close();
  });

  it('does not write after a workspace switch while goal enumeration is in progress', async () => {
    vi.stubEnv('LNWJUD_PRODUCTION_HINDSIGHT_URL', 'http://127.0.0.1:8888');
    let selected = workspaceA;
    const seen: string[] = [];
    const fetcher = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      seen.push((init?.method ?? 'GET') + ' ' + String(url));
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
    const capture = new ProductionAutomaticProjectMemory({
      enabled: () => true, selectedWorkspace: async () => selected,
      goalStatuses: async () => { selected = workspaceB; return [goal]; }, fetcher,
    });
    await capture.syncSelected();
    expect(seen.every((entry) => entry.startsWith('GET '))).toBe(true);
    capture.close();
  });
});
