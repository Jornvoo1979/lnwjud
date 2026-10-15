import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteWorkspaceWriterLease } from './workspace-writer-lease.js';

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((r) => rm(r, { recursive: true, force: true }))); });

async function fixture(now?: () => number): Promise<{ one: SqliteWorkspaceWriterLease; two: SqliteWorkspaceWriterLease }> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-workspace-lease-'));
  roots.push(root);
  const filename = path.join(root, 'fences.sqlite');
  return {
    one: new SqliteWorkspaceWriterLease(filename, now),
    two: new SqliteWorkspaceWriterLease(filename, now),
  };
}

describe('durable multi-session workspace writer lease', () => {
  it('prevents a lease from racing a mutation admitted while no lease existed', async () => {
    const { one, two } = await fixture();
    const admitted = await one.begin('workspace', 'unleased-client', 'session-one', 'unleased-call');
    expect(admitted).toMatchObject({ ok: true, value: { required: false, generation: 0 } });
    expect(await two.inspect('workspace')).toMatchObject({
      ok: true, value: { state: 'blocked', activeCalls: 1, generation: 0 },
    });
    expect(await two.acquire('workspace', 'new-owner', 'session-two', 60))
      .toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'unleased-call', 0);
    expect(await two.acquire('workspace', 'new-owner', 'session-two', 60))
      .toMatchObject({ ok: true, value: { generation: 1 } });
  });

  it('rejects lease proof when there is no active lease instead of silently ignoring it', async () => {
    const { one } = await fixture();
    expect(await one.begin('workspace', 'owner', 'session', 'forged-call', {
      leaseId: 'none', leaseToken: 'none', generation: 0,
    })).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
  });

  it('excludes independent processes/clients from the same workspace while allowing other workspaces', async () => {
    const { one, two } = await fixture();
    const acquired = await one.acquire('workspace', 'client-one', 'session-one', 60);
    expect(acquired.ok).toBe(true);
    if (!acquired.ok) return;
    expect(await two.acquire('workspace', 'client-two', 'session-two', 60)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'client-two', 'session-two', 'other-call')).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'client-one', 'wrong-session', 'other-call', acquired.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace-two', 'client-two', 'session-two', 'other-call')).toMatchObject({ ok: true, value: { required: false } });
    const admitted = await one.begin('workspace', 'client-one', 'session-one', 'owned-call', acquired.value);
    expect(admitted).toMatchObject({ ok: true, value: { required: true } });
    expect(await two.release('workspace', 'client-one', 'session-one', acquired.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'owned-call', acquired.value.generation);
    expect(await two.release('workspace', 'client-one', 'session-one', acquired.value)).toMatchObject({ ok: true });
    expect(await two.begin('workspace', 'client-two', 'session-two', 'next-call')).toMatchObject({ ok: true, value: { required: false } });
  });

  it('rotates fencing generation on expiry, rejects stale proof and recovers a stopped owner', async () => {
    let time = 0;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'session', 30);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    time = 40_000;
    const second = await two.acquire('workspace', 'new-owner', 'new-session', 30);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.value.generation).toBe(first.value.generation + 1);
    expect(await one.begin('workspace', 'owner', 'session', 'stale', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await one.release('workspace', 'owner', 'session', first.value)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    expect(await two.begin('workspace', 'new-owner', 'new-session', 'new-call', second.value)).toMatchObject({ ok: true });
    await two.end('workspace', 'new-call', second.value.generation);
  });

  it('refuses expiry takeover while a live prior invocation is still pinned', async () => {
    let time = 0;
    const { one, two } = await fixture(() => time);
    const first = await one.acquire('workspace', 'owner', 'session', 30);
    if (!first.ok) throw new Error('unexpected acquisition failure');
    expect(await one.begin('workspace', 'owner', 'session', 'running', first.value)).toMatchObject({ ok: true });
    time = 35_000;
    expect(await two.acquire('workspace', 'different', 'session-2', 30)).toMatchObject({ ok: false, error: { code: 'CONFLICT' } });
    await one.end('workspace', 'running', first.value.generation);
    expect(await two.acquire('workspace', 'different', 'session-2', 30)).toMatchObject({ ok: true });
  });
});
