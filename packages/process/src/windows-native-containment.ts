import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

export interface WindowsNativeContainmentExecutable {
  readonly executablePath: string;
  readonly expectedSha256: string;
  readonly expectedSizeBytes: number;
}

interface NativeHostManifest {
  readonly schemaVersion: 1;
  readonly name: 'lnwjud-windows-host.exe';
  readonly platform: 'win32';
  readonly arch: 'x64';
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly verified: true;
}

export function resolvePackagedWindowsNativeContainmentExecutable(): WindowsNativeContainmentExecutable | undefined {
  if (process.platform !== 'win32' || process.arch !== 'x64') return undefined;
  const resourcesPath = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  const githubWorkspace = process.env.CI === 'true' && process.env.GITHUB_ACTIONS === 'true'
    ? process.env.GITHUB_WORKSPACE
    : undefined;
  const candidates = [
    resourcesPath === undefined ? undefined : path.join(resourcesPath, 'native-host', 'windows', 'x64', 'lnwjud-windows-host.exe'),
    githubWorkspace === undefined ? undefined : path.join(githubWorkspace, 'apps', 'desktop', 'build', 'native-host', 'windows', 'x64', 'lnwjud-windows-host.exe'),
    path.resolve(path.dirname(process.execPath), 'resources', 'native-host', 'windows', 'x64', 'lnwjud-windows-host.exe'),
  ].filter((candidate): candidate is string => candidate !== undefined);

  for (const candidate of candidates) {
    const verified = readVerifiedWindowsNativeContainmentExecutable(candidate);
    if (verified !== undefined) return verified;
    if (existsSync(candidate)) return undefined; // Existing first candidate must never be bypassed by a later one.
  }
  return undefined;
}

export function verifyWindowsNativeContainmentExecutable(
  identity: WindowsNativeContainmentExecutable,
): boolean {
  const verified = readVerifiedWindowsNativeContainmentExecutable(identity.executablePath);
  return verified !== undefined
    && verified.expectedSha256 === identity.expectedSha256
    && verified.expectedSizeBytes === identity.expectedSizeBytes;
}

function readVerifiedWindowsNativeContainmentExecutable(
  executablePath: string,
): WindowsNativeContainmentExecutable | undefined {
  try {
    const executable = path.resolve(executablePath);
    const binaryStat = lstatSync(executable);
    if (!binaryStat.isFile() || binaryStat.isSymbolicLink() || realpathSync(executable) !== executable) return undefined;
    const manifestPath = path.join(path.dirname(executable), 'NATIVE_HOST.json');
    const manifestStat = lstatSync(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || realpathSync(manifestPath) !== manifestPath) return undefined;
    const parsed: unknown = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (!isManifest(parsed) || parsed.name !== path.basename(executable)) return undefined;
    const bytes = readFileSync(executable);
    if (bytes.byteLength !== parsed.sizeBytes) return undefined;
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (sha256 !== parsed.sha256.toLowerCase()) return undefined;
    return { executablePath: executable, expectedSha256: sha256, expectedSizeBytes: bytes.byteLength };
  } catch {
    return undefined;
  }
}

function isManifest(value: unknown): value is NativeHostManifest {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return item.schemaVersion === 1
    && item.name === 'lnwjud-windows-host.exe'
    && item.platform === 'win32'
    && item.arch === 'x64'
    && item.verified === true
    && typeof item.sha256 === 'string'
    && /^[0-9a-f]{64}$/i.test(item.sha256)
    && typeof item.sizeBytes === 'number'
    && Number.isSafeInteger(item.sizeBytes)
    && item.sizeBytes > 0;
}
