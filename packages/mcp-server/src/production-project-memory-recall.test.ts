import { afterEach, describe, expect, it, vi } from 'vitest';
import { createProductionSingleUserMemoryRecall, recallProductionHindsight } from './production-project-memory-recall.js';

const bank = 'project-' + 'a'.repeat(24);
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('Production project memory fail-closed boundary', () => {
  it('refuses backend reads unless the exact loopback Production endpoint is explicitly selected', async () => {
    const network = vi.fn();
    vi.stubGlobal('fetch', network);
    for (const endpoint of ['', 'http://127.0.0.1:18888', 'http://localhost:8888',
      'http://127.0.0.1:8888/private', 'http://0.0.0.0:8888']) {
      vi.stubEnv('LNWJUD_PRODUCTION_HINDSIGHT_URL', endpoint);
      await expect(recallProductionHindsight(bank, 'synthetic', 1)).rejects.toThrow(/Production project-memory endpoint unavailable/);
    }
    expect(network).not.toHaveBeenCalled();
  });

  it('requests native single-use Production tool approval and reads the Host-derived bank only', async () => {
    const approvals: string[] = [];
    const seen: string[] = [];
    const workspace = { workspaceId: 'ProductionAlpha', projectId: 'ProductionAlpha',
      rootPath: 'D:/ProductionAlpha', approved: true as const };
    const reader = createProductionSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => workspace,
      nativeApproval: async request => { approvals.push(request.toolName); return true; },
      recallBank: async (selectedBank) => { seen.push(selectedBank); return []; },
    });
    const result = await reader('project lifecycle', 2);
    expect(approvals).toEqual(['project_memory_recall']);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/^project-[a-f0-9]{24}$/);
    expect(result.projectId).toBe('ProductionAlpha');
  });

  it('never calls Production backend when Host denies native approval', async () => {
    const recallBank = vi.fn(async () => []);
    const reader = createProductionSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => ({ workspaceId: 'Alpha', projectId: 'Alpha',
        rootPath: 'D:/Alpha', approved: true }),
      nativeApproval: async () => false,
      recallBank,
    });
    await expect(reader('test')).rejects.toThrow(/denied/);
    expect(recallBank).not.toHaveBeenCalled();
  });

  it('denies and never touches the backend if the Host switches projects during approval', async () => {
    const workspaceA = { workspaceId: 'Alpha', projectId: 'Alpha', rootPath: 'D:/Alpha', approved: true as const };
    const workspaceB = { workspaceId: 'Beta', projectId: 'Beta', rootPath: 'D:/Beta', approved: true as const };
    let current = workspaceA;
    const recallBank = vi.fn(async () => []);
    const reader = createProductionSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => current,
      nativeApproval: async () => { current = workspaceB; return true; },
      recallBank,
    });
    await expect(reader('selected project')).rejects.toThrow(/denied/);
    expect(recallBank).not.toHaveBeenCalled();
  });

  it('refuses to disclose results after an in-flight Host workspace switch', async () => {
    const workspaceA = { workspaceId: 'Alpha', projectId: 'Alpha', rootPath: 'D:/Alpha', approved: true as const };
    const workspaceB = { workspaceId: 'Beta', projectId: 'Beta', rootPath: 'D:/Beta', approved: true as const };
    let current = workspaceA;
    const reader = createProductionSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => current,
      nativeApproval: async () => true,
      recallBank: async () => { current = workspaceB; return [{ content: 'secret-from-alpha', ref: 'fixture' }]; },
    });
    await expect(reader('selected project')).rejects.toThrow(/denied/);
  });

  it('uses only localhost Production backend for a valid bank and never staging', async () => {
    vi.stubEnv('LNWJUD_PRODUCTION_HINDSIGHT_URL', 'http://127.0.0.1:8888');
    const network = vi.fn(async (_url: URL) => ({
      ok: true, json: async () => ({ results: [{ text: 'synthetic', id: 'test' }] }),
    }));
    vi.stubGlobal('fetch', network);
    const result = await recallProductionHindsight(bank, 'synthetic', 1);
    expect(result).toEqual([{ content: 'synthetic', ref: 'test' }]);
    expect(String(network.mock.calls[0]?.[0])).toContain('http://127.0.0.1:8888/');
    expect(String(network.mock.calls[0]?.[0])).not.toContain('18888');
  });
});
