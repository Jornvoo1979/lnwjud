import { afterEach, describe, expect, it, vi } from 'vitest';
import { recallStagingHindsight } from './staging-project-memory-recall.js';

const bank = 'project-' + 'a'.repeat(24);

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('Staging Hindsight endpoint isolation', () => {
  it('fails closed when no dedicated endpoint is configured', async () => {
    vi.stubEnv('LNWJUD_STAGING_HINDSIGHT_URL', '');
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(recallStagingHindsight(bank, 'synthetic', 1)).rejects.toThrow(/Isolated Staging/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    'http://127.0.0.1:8888',
    'http://localhost:18888',
    'http://127.0.0.1:18080',
    'http://127.0.0.1:18888/private',
    'http://0.0.0.0:18888',
    'https://127.0.0.1:18888',
  ])('rejects non-isolated endpoint %s before network access', async (endpoint) => {
    vi.stubEnv('LNWJUD_STAGING_HINDSIGHT_URL', endpoint);
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(recallStagingHindsight(bank, 'synthetic', 1)).rejects.toThrow(/Isolated Staging/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reads only the Host-derived bank at the dedicated test endpoint', async () => {
    vi.stubEnv('LNWJUD_STAGING_HINDSIGHT_URL', 'http://127.0.0.1:18888');
    const fetchMock = vi.fn(async (url: URL) => {
      expect(url.protocol).toBe('http:');
      return {
        ok: true,
        json: async (): Promise<{ results: { text: string; id: string }[] }> => ({ results: [{ text: 'synthetic only', id: 'fixture' }] }),
      };
    });
    vi.stubGlobal('fetch', fetchMock);
    const result = await recallStagingHindsight(bank, 'synthetic', 1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`http://127.0.0.1:18888/v1/default/banks/${bank}/memories/recall`);
    expect(result).toEqual([{ content: 'synthetic only', ref: 'fixture' }]);
  });
});
