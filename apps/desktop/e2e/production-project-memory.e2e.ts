/**
 * Acceptance of the *packaged* Windows Desktop's opt-in memory path. All state
 * and the fake Hindsight endpoint live on the disposable GitHub Actions runner.
 * This never reads or writes the user's real Production memory database.
 */
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { _electron, expect, test, type ElectronApplication } from '@playwright/test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { settleFirstRunAndOpenHome } from './first-run-helpers.js';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packagedExecutable = process.env.LNWJUD_PACKAGED_EXECUTABLE?.trim();

test('packaged Windows Production memory requires per-read native consent and Host-scoped bank', async () => {
  test.skip(process.platform !== 'win32' || !packagedExecutable,
    'Only a packaged Windows Candidate can prove the Production opt-in boundary');
  test.setTimeout(180_000);

  const dataRoot = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-production-memory-data-'));
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'lnwjud-production-memory-workspace-'));
  const requests: string[] = [];
  let app: ElectronApplication | undefined;
  let client: Client | undefined;
  let backend: Server | undefined;

  try {
    await writeFile(path.join(fixtureRoot, 'package.json'),
      JSON.stringify({ name: 'isolated-memory-test-fixture', version: '1.0.0' }), 'utf8');
    // A temporary synthetic endpoint is required; binding failure must be reported,
    // not silently redirected to a different port or any installed Hindsight service.
    backend = createServer((request, response): void => {
      requests.push(request.url ?? '');
      request.resume();
      request.once('end', (): void => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ results: [{ text: 'synthetic-package-only-memory', id: 'fixture' }] }));
      });
    });
    await new Promise<void>((resolve, reject) => {
      backend!.once('error', reject);
      backend!.listen(8888, '127.0.0.1', (): void => resolve());
    });

    app = await _electron.launch({
      executablePath: packagedExecutable!,
      args: [`--user-data-dir=${dataRoot}`],
      cwd: desktopRoot,
      env: {
        ...process.env,
        APPDATA: dataRoot,
        LNWJUD_DATA_PATH: dataRoot,
        LNWJUD_WORKSPACE: fixtureRoot,
        LNWJUD_E2E_FIXTURE: '1',
        LNWJUD_E2E_NODE_PATH: process.execPath,
        LNWJUD_PRODUCTION_PROJECT_MEMORY_READ: '1',
        LNWJUD_PRODUCTION_HINDSIGHT_URL: 'http://127.0.0.1:8888',
      },
      timeout: 45_000,
    });
    expect(await app.evaluate(({ app: electron }) => electron.isPackaged)).toBe(true);
    const page = await app.firstWindow();
    await settleFirstRunAndOpenHome(page);
    const workspaceId = (await page.getByTestId('workspace-id').textContent())?.trim();
    expect(workspaceId).toBeTruthy();
    if (!workspaceId) throw new Error('No Host-selected Workspace ID in packaged Desktop');

    await expect(page.getByTestId('mcp-status')).toHaveText(/Agent พร้อมทำงาน|Agent ready/, { timeout: 30_000 });
    const endpointText = (await page.getByTestId('mcp-endpoint').textContent())?.trim();
    if (!endpointText || endpointText === '—') throw new Error('Packaged Desktop MCP endpoint missing');
    const endpoint = new URL(endpointText);
    expect(endpoint.hostname).toBe('127.0.0.1');
    client = new Client(
      { name: 'packaged-production-memory-acceptance', version: '1.0.0' },
      { versionNegotiation: { mode: { pin: '2026-07-28' } } },
    );
    await client.connect(new StreamableHTTPClientTransport(endpoint));

    const tools = (await client.listTools()).tools.map((tool) => tool.name);
    expect(tools).toContain('project_memory_recall');

    // A rejected native Desktop approval must never call the synthetic backend.
    const denyWindow = app.waitForEvent('window');
    const deniedCall = client.callTool({ name: 'project_memory_recall', arguments: { query: 'synthetic deny fixture' } });
    const denyPage = await denyWindow;
    await expect(denyPage.getByRole('alertdialog')).toBeVisible({ timeout: 20_000 });
    await expect(denyPage.locator('.mutation-approval-detail')).toContainText(workspaceId);
    await expect(denyPage.locator('.mutation-approval-detail')).toContainText('synthetic deny fixture');
    expect(requests).toHaveLength(0);
    await denyPage.getByRole('button', { name: /^(ยกเลิก|Cancel)$/ }).click();
    const denied = await deniedCall;
    expect(denied.isError).toBe(true);
    expect(requests).toHaveLength(0);

    // A new read must prompt again. Real rendered approval is required.
    const approveWindow = app.waitForEvent('window');
    const acceptedCall = client.callTool({ name: 'project_memory_recall', arguments: { query: 'synthetic approve fixture' } });
    const approvePage = await approveWindow;
    await expect(approvePage.getByRole('alertdialog')).toBeVisible({ timeout: 20_000 });
    await expect(approvePage.locator('.mutation-approval-detail')).toContainText(workspaceId);
    await expect(approvePage.locator('.mutation-approval-detail')).toContainText('synthetic approve fixture');
    expect(requests).toHaveLength(0);
    await approvePage.getByRole('button', { name: /^(อนุญาตครั้งนี้|Approve once)$/ }).click();
    const accepted = await acceptedCall;
    expect(accepted.isError).not.toBe(true);
    expect(JSON.stringify(accepted)).toContain('synthetic-package-only-memory');
    const expectedBank = 'project-' + createHash('sha256').update(workspaceId).digest('hex').slice(0, 24);
    expect(requests).toEqual([`/v1/default/banks/${expectedBank}/memories/recall`]);
    expect(JSON.stringify(accepted)).toContain(workspaceId);
  } finally {
    if (client !== undefined) await client.close().catch(() => undefined);
    if (app !== undefined) await app.close().catch(() => undefined);
    if (backend !== undefined) {
      backend.closeAllConnections();
      await new Promise<void>((resolve) => { backend!.close((): void => resolve()); });
    }
    await Promise.all([
      rm(dataRoot, { recursive: true, force: true }),
      rm(fixtureRoot, { recursive: true, force: true }),
    ]);
  }
});
