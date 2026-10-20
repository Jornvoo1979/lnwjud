import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') {
  process.stdout.write('Skipping Windows native host build on a non-Windows host.\n');
  process.exit(0);
}

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const nativeRoot = path.resolve(desktopRoot, '..', '..', 'native', 'windows-host');
const project = path.join(nativeRoot, 'lnwjud-windows-host.csproj');
const arch = process.env.LNWJUD_RUNTIME_ARCH ?? process.arch;
if (arch !== 'x64') throw new Error(`Unsupported Windows native host architecture: ${arch}`);

const publishDirectory = path.join(nativeRoot, 'bin', 'win-x64');
rmSync(publishDirectory, { recursive: true, force: true });
mkdirSync(publishDirectory, { recursive: true });
execFileSync('dotnet', [
  'publish', project,
  '--configuration', 'Release',
  '--runtime', 'win-x64',
  '--self-contained', 'true',
  '--output', publishDirectory,
  '/p:PublishSingleFile=true',
  '/p:IncludeNativeLibrariesForSelfExtract=true',
  '/p:EnableWindowsTargeting=true',
], { stdio: 'inherit', windowsHide: true });

const binary = path.join(publishDirectory, 'lnwjud-windows-host.exe');
if (!existsSync(binary)) throw new Error('dotnet publish did not produce lnwjud-windows-host.exe');

const output = path.join(desktopRoot, 'build', 'native-host', 'windows', arch);
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
const staged = path.join(output, 'lnwjud-windows-host.exe');
copyFileSync(binary, staged);
const bytes = readFileSync(staged);
const manifest = {
  schemaVersion: 1,
  name: 'lnwjud-windows-host.exe',
  platform: 'win32',
  arch,
  sha256: createHash('sha256').update(bytes).digest('hex'),
  sizeBytes: bytes.byteLength,
  verified: true,
};
writeFileSync(path.join(output, 'NATIVE_HOST.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
writeFileSync(path.join(output, 'LICENSE'), readFileSync(path.join(nativeRoot, 'README.md'), 'utf8'), 'utf8');
process.stdout.write(`Staged Windows native host for ${arch}: ${staged}\n`);
