import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GitService } from './git-service.js';
import { ok } from '@lnwjud/domain';
import type { ManagedWriterAdmissionPort } from './writer-admission.js';
import type { Workspace, WorkspaceRepository } from '@lnwjud/workspace';
import { resolvePackagedWindowsNativeContainmentExecutable } from '@lnwjud/process';

const temporaryRoots: string[] = [];
afterEach(async () => { await Promise.all(temporaryRoots.splice(0).map((x) => rm(x, { force:true, recursive:true, maxRetries:8, retryDelay:100 }))); });

describe.skipIf(process.platform !== 'win32' || resolvePackagedWindowsNativeContainmentExecutable() === undefined)('Windows native GitService writer admission', () => {
  it('keeps native Git writer ownership fenced without authenticated terminal proof', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'lnwjud-git-native-')));
    temporaryRoots.push(root);
    const workspaceRoot = path.join(root, 'project');
    const { mkdir } = await import('node:fs/promises');
    await mkdir(workspaceRoot);
    const workspace: Workspace = { id:'git-native',displayName:'Native',rootPath:workspaceRoot,realRootPath:workspaceRoot,createdAt:new Date(0).toISOString() };
    const repository: WorkspaceRepository = {
      async list() { return [workspace]; },
      async get(id) { return id === workspace.id ? workspace : null; },
      async insert() {}, async delete() {},
    };
    const nativeRoot = path.join(root, 'contained');
    const nativeReservations: string[] = [];
    let verifiedReleases = 0;
    const gate: ManagedWriterAdmissionPort = { async enter(input) {
      if (input.nativeReceiptPath !== undefined) nativeReservations.push(input.nativeReceiptPath);
      return ok({ id: 'native-git', releaseAfterVerifiedTermination: async () => { verifiedReleases++; } });
    } };
    const service = new GitService(repository, undefined, undefined, { writerAdmission:gate, nativeContainmentRoot:nativeRoot });
    const result = await service.run({ clientId:'test-git-native',clientName:'test' }, {
      args:['init','--initial-branch=dev'], workspaceId:workspace.id, timeoutMs:30_000,
    },undefined,{ mode:'standard',applicationApproved:true,bypassApplicationAuthorization:false,source:'host_approval' });
    // Disk-only terminal evidence cannot authorize a Git writer release.
    expect(result.ok).toBe(false);
    expect(verifiedReleases).toBe(0);
    const entries=await (await import('node:fs/promises')).readdir(nativeRoot);
    expect(nativeReservations).toEqual([path.join(nativeRoot, entries[0]!, 'containment.receipt.json')]);
    expect(entries).toHaveLength(1);
    const receipt=JSON.parse(await readFile(path.join(nativeRoot,entries[0]!,'containment.receipt.json'),'utf8')) as Record<string,unknown>;
    expect(receipt).toMatchObject({
      kind:'windows_native_process_v1',activeProcesses:0,outcome:'completed',exitCode:0,
      restrictedToken:true,assignedBeforeResume:true,killOnJobClose:true,
    });
  },45000);
});
