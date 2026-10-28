import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { createStagingSingleUserMemoryRecall } from './staging-project-memory-recall.js';

const initial = { workspaceId: 'StagingAlpha', projectId: 'approved-project-alpha', approved: true as const, rootPath: 'D:\\StagingAlpha' };
const bank = 'project-' + createHash('sha256').update(initial.projectId).digest('hex').slice(0, 24);

function fixture(): {
  read: ReturnType<typeof createStagingSingleUserMemoryRecall>;
  prompts: unknown[];
  banks: string[];
  setEnabled: (v: boolean) => void;
  setAllowed: (v: boolean) => void;
  changeWorkspace: () => void;
} {
  let enabled = true, allow = true, workspace = { ...initial };
  const prompts: unknown[] = [];
  const banks: string[] = [];
  const read = createStagingSingleUserMemoryRecall({
    enabled: () => enabled,
    getSelectedWorkspace: async () => workspace,
    nativeApproval: async request => { prompts.push(request); return allow; },
    recallBank: async (value, query) => { banks.push(value); return [{ content: 'Synthetic local memory: ' + query, ref: 'fixture' }]; },
  });
  return {
    read, prompts, banks,
    setEnabled: (v: boolean): void => { enabled = v; },
    setAllowed: (v: boolean): void => { allow = v; },
    changeWorkspace: (): void => { workspace = { ...initial, workspaceId: 'StagingBeta', rootPath: 'D:\\StagingBeta' }; },
  };
}

describe('Staging project-memory native read authorization', () => {
  it('denies by default when local Host opt-in is off and does not touch backend', async () => {
    const f = fixture(); f.setEnabled(false);
    await expect(f.read('test query')).rejects.toThrow(/denied/);
    expect(f.prompts).toHaveLength(0);
    expect(f.banks).toHaveLength(0);
  });

  it('requires exact native approval and limits read to Host-selected hashed bank', async () => {
    const f = fixture();
    const result = await f.read('release marker', 3);
    expect(f.prompts).toMatchObject([{ mutationKind: 'read', toolName: 'candidate_project_memory_recall',
      workspaceId: 'StagingAlpha', workspaceRoot: initial.rootPath }]);
    expect(JSON.stringify(f.prompts)).toContain('release marker');
    expect(f.banks).toEqual([bank]);
    expect(result).toMatchObject({ projectId: 'approved-project-alpha', authoritative: false,
      results: [{ content: 'Synthetic local memory: release marker' }] });
  });

  it('native denial fails before any bank read', async () => {
    const f = fixture(); f.setAllowed(false);
    await expect(f.read('test query')).rejects.toThrow(/denied/);
    expect(f.banks).toHaveLength(0);
  });

  it('rejects a Host workspace switch while approval is pending', async () => {
    let scope = { ...initial }, calls = 0;
    const read = createStagingSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => scope,
      nativeApproval: async () => { scope = { ...initial, workspaceId: 'StagingBeta', rootPath: 'D:\\StagingBeta' }; return true; },
      recallBank: async () => { calls++; return []; },
    });
    await expect(read('test query')).rejects.toThrow(/denied/);
    expect(calls).toBe(0);
  });

  it('blocks result release if workspace switches during backend response', async () => {
    let scope = { ...initial };
    const read = createStagingSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => scope,
      nativeApproval: async () => true,
      recallBank: async () => { scope = { ...initial, workspaceId: 'StagingBeta', rootPath: 'D:\\StagingBeta' }; return [{ content: 'secret test fixture', ref: 'f' }]; },
    });
    await expect(read('test query')).rejects.toThrow(/denied/);
  });

  it('denies if Host-approved project ID changes without a workspace change', async () => {
    let current = { ...initial }, bankCalls = 0;
    const read = createStagingSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => current,
      nativeApproval: async () => { current = { ...current, projectId: 'other-approved-project' }; return true; },
      recallBank: async () => { bankCalls++; return []; },
    });
    await expect(read('test query')).rejects.toThrow(/denied/);
    expect(bankCalls).toBe(0);
  });

  it('denies missing project ID or missing Host approval before showing consent', async () => {
    let scope = { ...initial, approved: false as boolean, projectId: '' };
    let prompts = 0, reads = 0;
    const read = createStagingSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => scope as typeof initial,
      nativeApproval: async () => { prompts++; return true; },
      recallBank: async () => { reads++; return []; },
    });
    await expect(read('test query')).rejects.toThrow(/denied/);
    scope = { ...scope, approved: true };
    await expect(read('test query')).rejects.toThrow(/denied/);
    expect(prompts).toBe(0);
    expect(reads).toBe(0);
  });

  it('requires fresh approval for every read and prevents concurrent approval reuse', async () => {
    let release!: () => void; let promptStarted!: () => void; let approvals = 0, calls = 0;
    const hold = new Promise<void>(resolve => { release = resolve; });
    const started = new Promise<void>(resolve => { promptStarted = resolve; });
    const read = createStagingSingleUserMemoryRecall({
      enabled: () => true,
      getSelectedWorkspace: async () => initial,
      nativeApproval: async () => { approvals++; if (approvals === 1) { promptStarted(); await hold; } return true; },
      recallBank: async () => { calls++; return []; },
    });
    const first = read('first');
    await started;
    await expect(read('second')).rejects.toThrow(/denied/);
    release();
    await first;
    await read('third');
    expect(approvals).toBe(2);
    expect(calls).toBe(2);
  });

  it('rejects invalid or sensitive queries without disclosure prompt', async () => {
    const f = fixture();
    await expect(f.read('')).rejects.toThrow(/denied/);
    await expect(f.read('password')).rejects.toThrow(/denied/);
    await expect(f.read('x'.repeat(401))).rejects.toThrow(/denied/);
    expect(f.prompts).toHaveLength(0);
  });
});
