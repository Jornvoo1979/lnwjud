import { createHash } from 'node:crypto';
import { lstat, mkdir, open, readdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import {
  verifyWindowsNativeContainmentExecutable,
  type WindowsNativeContainmentExecutable,
} from './windows-native-containment.js';

export type WindowsContainmentReceiptKind = 'windows_job_v1' | 'windows_native_process_v1';

export interface WindowsContainedLaunch {
  readonly executable: string;
  readonly args: readonly string[];
  readonly receiptPath: string;
  readonly cancelPath: string;
  readonly receiptKind: 'windows_native_process_v1';
  readonly specDigest: string;
}

export interface LegacyWindowsContainmentReceipt {
  readonly kind: 'windows_job_v1';
  readonly outcome: 'completed' | 'cancelled' | 'timed_out';
  readonly exitCode: number;
  readonly activeProcesses: 0;
}

export interface WindowsNativeProcessReceipt {
  readonly kind: 'windows_native_process_v1';
  readonly outcome: 'completed' | 'cancelled' | 'timed_out';
  readonly exitCode: number;
  readonly activeProcesses: 0;
  readonly pid: number;
  readonly processCreationTime: string;
  readonly restrictedToken: true;
  readonly assignedBeforeResume: true;
  readonly killOnJobClose: true;
  readonly jobIdentity: string;
  readonly specDigest: string;
}

export type WindowsContainmentReceipt = LegacyWindowsContainmentReceipt | WindowsNativeProcessReceipt;

export async function prepareWindowsContainedLaunch(input: {
  readonly directory: string;
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly windowsVerbatimArguments?: boolean;
  readonly nativeHost: WindowsNativeContainmentExecutable;
}): Promise<WindowsContainedLaunch> {
  if (process.platform !== 'win32') throw new Error('WINDOWS_CONTAINMENT_UNSUPPORTED');
  if (![input.directory, input.executable, input.cwd].every((value) => path.isAbsolute(value))) throw new Error('WINDOWS_CONTAINMENT_ABSOLUTE_PATH_REQUIRED');
  if (!verifyWindowsNativeContainmentExecutable(input.nativeHost)) throw new Error('WINDOWS_NATIVE_CONTAINMENT_IDENTITY_UNVERIFIED');
  // Desktop-managed containment directories may be pre-provisioned.
  // The exclusive containment.json write below prevents reusing a completed specification.
  await mkdir(input.directory, { recursive: true, mode: 0o700 });
  const specPath = path.join(input.directory, 'containment.json');
  const receiptPath = path.join(input.directory, 'containment.receipt.json');
  const cancelPath = path.join(input.directory, 'containment.cancel');
  // A pre-provisioned directory is permitted; stale terminal/cancel artifacts are not.
  const existing = await readdir(input.directory);
  if (existing.includes('containment.receipt.json') || existing.includes('containment.receipt.tmp')
    || existing.includes('containment.cancel')) throw new Error('WINDOWS_CONTAINMENT_STALE_ARTIFACT');
  const spec = JSON.stringify({
    version: 2,
    executable: input.executable,
    arguments: input.args,
    cwd: input.cwd,
    timeoutMs: input.timeoutMs,
    windowsVerbatimArguments: input.windowsVerbatimArguments === true,
    receiptKind: 'windows_native_process_v1',
  });
  const digest = createHash('sha256').update(spec).digest('hex');
  await writeFile(specPath, spec, { flag: 'wx', mode: 0o600 });
  return {
    executable: input.nativeHost.executablePath,
    args: ['--contained-process', input.directory, digest],
    receiptPath,
    cancelPath,
    receiptKind: 'windows_native_process_v1',
    specDigest: digest,
  };
}

export async function readWindowsContainmentReceipt(
  filename: string,
  expectedKind?: WindowsContainmentReceiptKind,
  expectedSpecDigest?: string,
): Promise<WindowsContainmentReceipt | undefined> {
  try {
    // Reject symlinks and oversized receipts before parsing attacker-controlled content.
    // A verified task/lease attestation is still required for producer authentication.
    const entry = await lstat(filename);
    if (!entry.isFile() || entry.isSymbolicLink()) return undefined;
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    const file = await open(filename, flags);
    let content: string;
    try {
      const before = await file.stat();
      if (!before.isFile() || before.size > 16 * 1024
        || before.dev !== entry.dev || before.ino !== entry.ino) return undefined;
      const bytes = Buffer.alloc(16 * 1024 + 1);
      const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
      if (bytesRead > 16 * 1024) return undefined;
      const after = await file.stat();
      if (!after.isFile() || after.size !== before.size || after.mtimeMs !== before.mtimeMs || bytesRead !== before.size) return undefined;
      content = bytes.toString('utf8', 0, bytesRead);
    } finally {
      await file.close();
    }
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    const item = parsed as Record<string, unknown>;
    if (expectedKind !== undefined && item.kind !== expectedKind) return undefined;
    if (item.kind === 'windows_job_v1') {
      if (item.activeProcesses !== 0
        || (item.outcome !== 'completed' && item.outcome !== 'cancelled' && item.outcome !== 'timed_out')
        || typeof item.exitCode !== 'number' || !Number.isInteger(item.exitCode)) return undefined;
      return { kind: 'windows_job_v1', activeProcesses: 0, outcome: item.outcome, exitCode: item.exitCode };
    }
    if (item.kind !== 'windows_native_process_v1'
      || item.activeProcesses !== 0
      || (item.outcome !== 'completed' && item.outcome !== 'cancelled' && item.outcome !== 'timed_out')
      || typeof item.exitCode !== 'number' || !Number.isInteger(item.exitCode)
      || typeof item.pid !== 'number' || !Number.isInteger(item.pid) || item.pid < 1
      || typeof item.processCreationTime !== 'string' || !/^[0-9]+$/.test(item.processCreationTime)
      || item.restrictedToken !== true
      || item.assignedBeforeResume !== true
      || item.killOnJobClose !== true
      || typeof item.jobIdentity !== 'string' || !/^[0-9a-f]{32}$/i.test(item.jobIdentity)
      || typeof expectedSpecDigest !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSpecDigest)
      || item.specDigest !== expectedSpecDigest) return undefined;
    return {
      kind: 'windows_native_process_v1',
      outcome: item.outcome,
      exitCode: item.exitCode,
      activeProcesses: 0,
      pid: item.pid,
      processCreationTime: item.processCreationTime,
      restrictedToken: true,
      assignedBeforeResume: true,
      killOnJobClose: true,
      jobIdentity: item.jobIdentity,
      specDigest: expectedSpecDigest,
    };
  } catch { return undefined; }
}
