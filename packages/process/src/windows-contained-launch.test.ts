import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { prepareWindowsContainedLaunch, readWindowsContainmentReceipt } from './windows-contained-launch.js';

describe.skipIf(process.platform !== 'win32')('contained launch receipt', () => {
  it('prepares only the integrity-bound native host and refuses receipt downgrade', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud native containment prep '));
    try {
      const hostDir = path.join(root, 'host');
      await mkdir(hostDir);
      const host = path.join(hostDir, 'lnwjud-windows-host.exe');
      const bytes = Buffer.from('fixture-native-host');
      await writeFile(host, bytes);
      const sha256 = (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
      await writeFile(path.join(hostDir, 'NATIVE_HOST.json'), JSON.stringify({
        schemaVersion: 1, name: 'lnwjud-windows-host.exe', platform: 'win32', arch: 'x64',
        sha256, sizeBytes: bytes.byteLength, verified: true,
      }));
      const invocation = await prepareWindowsContainedLaunch({
        directory: path.join(root, 'task'), executable: process.execPath, cwd: root, timeoutMs: 10000,
        args: ['--version'],
        nativeHost: { executablePath: host, expectedSha256: sha256, expectedSizeBytes: bytes.byteLength },
      });
      expect(invocation.executable).toBe(host);
      expect(invocation.args[0]).toBe('--contained-process');
      expect(invocation.args).toHaveLength(3);
      expect(invocation.receiptKind).toBe('windows_native_process_v1');
      await writeFile(invocation.receiptPath, JSON.stringify({ kind: 'windows_job_v1', outcome: 'completed', exitCode: 0, activeProcesses: 0 }));
      expect(await readWindowsContainmentReceipt(invocation.receiptPath, invocation.receiptKind)).toBeUndefined();
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

// RED security regression: existing reader checks schema but lacks trusted ownership proof.
describe('native receipt authentication (RED until trusted binding lands)', () => {
  it('rejects a syntactically valid, untrusted native receipt', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-receipt-red-'));
    try {
      const filename = path.join(root, 'containment.receipt.json');
      await writeFile(filename, JSON.stringify({
        kind: 'windows_native_process_v1',
        outcome: 'completed',
        exitCode: 0,
        activeProcesses: 0,
        pid: 12345,
        processCreationTime: '123456789',
        restrictedToken: true,
        assignedBeforeResume: true,
        killOnJobClose: true,
        jobIdentity: '0123456789abcdef0123456789abcdef',
      }));
      expect(await readWindowsContainmentReceipt(filename, 'windows_native_process_v1')).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

// Matching the launch specification is a necessary correlation check, not producer authentication.
describe('native receipt spec correlation', () => {
  it('rejects a receipt from a different launch and accepts matching fields only with expected digest', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-receipt-correlation-'));
    try {
      const filename = path.join(root, 'containment.receipt.json');
      const specDigest = 'a'.repeat(64);
      await writeFile(filename, JSON.stringify({
        kind: 'windows_native_process_v1', outcome: 'completed', exitCode: 0, activeProcesses: 0,
        pid: 12345, processCreationTime: '123456789', restrictedToken: true,
        assignedBeforeResume: true, killOnJobClose: true,
        jobIdentity: '0123456789abcdef0123456789abcdef', specDigest,
      }));
      expect(await readWindowsContainmentReceipt(filename, 'windows_native_process_v1')).toBeUndefined();
      expect(await readWindowsContainmentReceipt(filename, 'windows_native_process_v1', 'b'.repeat(64))).toBeUndefined();
      expect(await readWindowsContainmentReceipt(filename, 'windows_native_process_v1', specDigest)).toMatchObject({ specDigest });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
