import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ProcessManager } from './process-manager.js';
import { resolvePackagedWindowsNativeContainmentExecutable } from './windows-native-containment.js';

describe.skipIf(process.platform !== 'win32' || resolvePackagedWindowsNativeContainmentExecutable() === undefined)('native contained ProcessManager', () => {
  it('keeps descendants contained but refuses untrusted terminal receipt ownership release', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-direct-process-contained-'));
    try {
      const containedRoot = path.join(root, 'managed-processes');
      await mkdir(containedRoot);
      const childFile = path.join(root, 'nested-child.cjs');
      const finished = path.join(root, 'grandchild-done');
      await writeFile(childFile, [
        "const cp=require('node:child_process');",
        "cp.spawn(process.execPath,['-e',`setTimeout(()=>require('node:fs').writeFileSync(process.argv[1],'yes'),1100)`,process.argv[2]],{detached:true,stdio:'ignore'}).unref();",
      ].join('\n'));
      let callbacks = 0;
      const manager = new ProcessManager(undefined, undefined, undefined, undefined, containedRoot);
      const result = await manager.start({
        executable: process.execPath, args: [childFile, finished], cwd: root,
        containmentId: '107c1eb1-638e-4d7d-bf47-c47ed7b6d558', timeoutMs: process.env.CI ? 110000 : 15000,
      }, undefined, undefined, (): void => { callbacks++; });
      expect(result).toMatchObject({ ok: true, value: { state: 'running' } });
      if (!result.ok) return;
      await new Promise((resolve) => setTimeout(resolve, 200));
      const earlyStatus = manager.status(result.value.processId);
      if (earlyStatus.ok && earlyStatus.value.state !== 'running') {
        const diagnostics = manager.logs(result.value.processId, { tailLines: 20 });
        const stderrCodes = diagnostics.ok
          ? diagnostics.value.entries.filter((entry) => entry.stream === 'stderr').map((entry) => entry.text.trim()).filter(Boolean)
          : [];
        throw new Error(`Native containment left running state early: ${earlyStatus.value.state}; ${stderrCodes.join(' | ')}`);
      }
      expect(earlyStatus).toMatchObject({ ok: true, value: { state: 'running' } });
      await expect.poll(() => manager.status(result.value.processId).ok
        ? manager.status(result.value.processId).value.state : 'unknown', { timeout: process.env.CI ? 100000 : 12000 }).toBe('termination_unverified');
      expect(await readFile(finished, 'utf8')).toBe('yes');
      // Until an independently authenticated native channel exists, a disk receipt
      // must never trigger the verified-termination ownership-release callback.
      expect(callbacks).toBe(0);
      const receipt = JSON.parse(await readFile(path.join(containedRoot, '107c1eb1-638e-4d7d-bf47-c47ed7b6d558', 'containment.receipt.json'), 'utf8'));
      expect(receipt).toMatchObject({
        kind: 'windows_native_process_v1',
        activeProcesses: 0,
        outcome: 'completed',
        restrictedToken: true,
        assignedBeforeResume: true,
        killOnJobClose: true,
        pid: expect.any(Number),
        processCreationTime: expect.stringMatching(/^[0-9]+$/),
      });
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 50, retryDelay: 200 });
    }
  }, process.env.CI ? 130000 : 18000);
  it('fails closed when a receipt temporary path is pre-created while native child runs', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-native-temp-collision-'));
    try {
      const containedRoot = path.join(root, 'managed-processes');
      await mkdir(containedRoot);
      let callbacks = 0;
      const processId = '229e48e5-571d-4f3b-b33c-f3aafceef108';
      const manager = new ProcessManager(undefined, undefined, undefined, undefined, containedRoot);
      const ready = path.join(root, 'child-ready');
      const release = path.join(root, 'release-child');
      const script = [
        "const fs = require('node:fs');",
        "fs.writeFileSync(process.argv[1], 'ready');",
        "const interval = setInterval(() => { if (fs.existsSync(process.argv[2])) { clearInterval(interval); process.exit(0); } }, 20);",
      ].join('\n');
      const result = await manager.start({
        executable: process.execPath,
        args: ['-e', script, ready, release],
        cwd: root, containmentId: processId, timeoutMs: 20000,
      }, undefined, undefined, (): void => { callbacks++; });
      expect(result).toMatchObject({ ok: true });
      if (!result.ok) return;
      await expect.poll(async () => {
        try { return await readFile(ready, 'utf8'); } catch { return ''; }
      }, { timeout: 10000 }).toBe('ready');
      const temp = path.join(containedRoot, processId, 'containment.receipt.tmp');
      // The live child cannot exit until the test has created the hostile path.
      await writeFile(temp, 'untrusted-preexisting-data', { flag: 'wx' });
      await writeFile(release, 'go');
      await expect.poll(() => manager.status(processId).ok
        ? manager.status(processId).value.state : 'unknown', { timeout: 15000 }).toBe('termination_unverified');
      expect(await readFile(temp, 'utf8')).toBe('untrusted-preexisting-data');
      expect(callbacks).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 50, retryDelay: 200 });
    }
  }, 25000);

  it('does not treat a genuine child exit 125 as verified native-host completion', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-native-125-'));
    try {
      const containedRoot = path.join(root, 'managed-processes');
      await mkdir(containedRoot);
      const processId = '5e765b63-a0c4-452f-8362-b416fc50a8ab';
      let callbacks = 0;
      const manager = new ProcessManager(undefined, undefined, undefined, undefined, containedRoot);
      const result = await manager.start({
        executable: process.execPath,
        args: ['-e', 'setTimeout(() => process.exit(125), 100)'],
        cwd: root, containmentId: processId, timeoutMs: 20000,
      }, undefined, undefined, (): void => { callbacks++; });
      expect(result).toMatchObject({ ok: true });
      if (!result.ok) return;
      await expect.poll(() => {
        const state = manager.status(processId);
        return state.ok ? state.value.state : 'unknown';
      }, { timeout: 15000 }).toBe('termination_unverified');
      expect(callbacks).toBe(0);
      // Stop must return a bounded failure instead of waiting forever for a
      // terminal attestation that the native receipt cannot authenticate.
      const stopped = await manager.stop(processId);
      expect(stopped.ok).toBe(false);
      expect(manager.status(processId)).toMatchObject({ ok: true, value: { state: 'termination_unverified' } });
      expect(callbacks).toBe(0);
      const receipt = JSON.parse(await readFile(path.join(containedRoot, processId, 'containment.receipt.json'), 'utf8'));
      expect(receipt).toMatchObject({ kind: 'windows_native_process_v1', exitCode: 125 });
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 50, retryDelay: 200 });
    }
  }, 25000);

});
