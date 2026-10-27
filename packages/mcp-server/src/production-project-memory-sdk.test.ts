import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { describe, expect, it, vi } from 'vitest';
import { permissionProfiles, type PermissionProfile } from '@lnwjud/permissions';
import type { FileActor } from '@lnwjud/application';
import { ActivityTracker, type ActivitySinkEvent } from './activity-tracker.js';
import { createMcpServer } from './server.js';
import type { McpApplicationServices } from './tool-registry.js';

const actor: FileActor = { clientId: 'production-memory-security-test', clientName: 'production-memory-security-test' };
const name = 'project_memory_recall';
const scope = { workspaceId: 'Alpha', rootPath: 'D:/IsolatedAlpha' };

async function connected(options: Parameters<typeof createMcpServer>[0]) {
  const server = createMcpServer(options);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'production-memory-test', version: '1.0.0' });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

describe('Optional Production MCP tool Host authorization and audit boundary', () => {
  it('is not registered without Host permission, audit and selected-workspace providers', async () => {
    const run = vi.fn(async () => ({ results: [] }));
    const f = await connected({ actor, services: {} as McpApplicationServices, productionProjectMemoryRecall: run });
    try {
      const listed = await f.client.listTools();
      expect(listed.tools.some(tool => tool.name === name)).toBe(false);
      expect(run).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });

  it('blocks denied READ profile before invoking local memory and audits the denial', async () => {
    const run = vi.fn(async () => ({ results: [] }));
    const tracker = new ActivityTracker();
    const denied: PermissionProfile = { ...permissionProfiles.safe,
      defaults: { ...permissionProfiles.safe.defaults, READ: 'DENY' } };
    const f = await connected({
      actor, services: {} as McpApplicationServices, productionProjectMemoryRecall: run,
      activeWorkspaceScopeProvider: async () => scope,
      profileProvider: () => denied, activityTracker: tracker,
    });
    try {
      const result = await f.client.callTool({ name, arguments: { query: 'test fixture' } });
      expect(result.isError).toBe(true);
      expect(run).not.toHaveBeenCalled();
      expect(tracker.telemetrySnapshot().byTool[name]?.errors).toBe(1);
    } finally { await f.close(); }
  });

  it('records allowed and failed calls without persisting raw query or backend response', async () => {
    const events: ActivitySinkEvent[] = [];
    const tracker = new ActivityTracker({ record: async event => { events.push(event); } });
    const run = vi.fn(async () => ({ results: [{ content: 'synthetic-only fixture memory' }] }));
    const f = await connected({
      actor, services: {} as McpApplicationServices, productionProjectMemoryRecall: run,
      activeWorkspaceScopeProvider: async () => scope,
      profileProvider: () => permissionProfiles.safe, activityTracker: tracker,
    });
    try {
      const response = await f.client.callTool({ name, arguments: { query: 'private_test_query_string' } });
      expect(response.isError).not.toBe(true);
      expect(run).toHaveBeenCalledOnce();
      expect(events.map(x => x.phase)).toEqual(['started', 'completed']);
      expect(events[1]?.resultCode).toBe('SUCCESS');
      expect(events.every(x => JSON.stringify(x).includes('private_test_query_string') === false)).toBe(true);
      expect(events.every(x => JSON.stringify(x).includes('synthetic-only fixture memory') === false)).toBe(true);
      expect(events[1]?.workspaceId).toBe('Alpha');
    } finally { await f.close(); }
  });

  it('denies when Host invocation guard blocks request even with read profile allowed', async () => {
    const run = vi.fn(async () => ({ results: [] }));
    const f = await connected({
      actor, services: {} as McpApplicationServices, productionProjectMemoryRecall: run,
      activeWorkspaceScopeProvider: async () => scope,
      profileProvider: () => permissionProfiles.safe,
      activityTracker: new ActivityTracker(),
      invocationGuardProvider: () => 'host blocked',
    });
    try {
      const result = await f.client.callTool({ name, arguments: { query: 'test fixture' } });
      expect(result.isError).toBe(true);
      expect(run).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });
});
