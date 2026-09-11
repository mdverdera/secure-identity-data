import { describe, it, expect, vi, beforeEach } from 'vitest';
import { dpopFetch, ApiError } from '@/lib/api/api-client';
import { generateDpopKeyPair } from '@/lib/dpop/dpop-key';

describe('API Client — dpopFetch', () => {
  let session: { accessToken: string; dpopKeyPair: CryptoKeyPair };

  beforeEach(async () => {
    session = {
      accessToken: 'eyJhbGciOiJSUzI1NiJ9.test.token',
      dpopKeyPair: await generateDpopKeyPair(),
    };
  });

  it('includes Authorization: DPoP <token> header', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ userId: 'user-001', fullName: 'Demo User', email: 'demo@example.test' }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await dpopFetch('https://localhost:7100/api/profile', session);

    const [, options] = mockFetch.mock.calls[0];
    expect(options.headers['Authorization']).toMatch(/^DPoP /);
    expect(options.headers['Authorization']).toContain(session.accessToken);

    vi.unstubAllGlobals();
  });

  it('includes DPoP proof header', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });
    vi.stubGlobal('fetch', mockFetch);

    await dpopFetch('https://localhost:7100/api/profile', session);

    const [, options] = mockFetch.mock.calls[0];
    const dpopHeader = options.headers['DPoP'];
    expect(dpopHeader).toBeTruthy();
    // DPoP proof is a three-part JWT
    const parts = dpopHeader.split('.');
    expect(parts).toHaveLength(3);

    vi.unstubAllGlobals();
  });

  it('generates a fresh DPoP proof for each call (unique jti)', async () => {
    const capturedHeaders: string[] = [];
    const mockFetch = vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
      capturedHeaders.push((opts.headers as Record<string, string>)['DPoP']);
      return Promise.resolve({ ok: true, json: async () => ({}) });
    });
    vi.stubGlobal('fetch', mockFetch);

    await dpopFetch('https://localhost:7100/api/profile', session);
    await dpopFetch('https://localhost:7100/api/identity', session);

    expect(capturedHeaders[0]).not.toBe(capturedHeaders[1]);

    vi.unstubAllGlobals();
  });

  it('throws ApiError with status 401 on Unauthorized response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'invalid_token' }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await expect(dpopFetch('https://localhost:7100/api/profile', session)).rejects.toThrow(ApiError);
    await expect(dpopFetch('https://localhost:7100/api/profile', session))
      .rejects.toMatchObject({ status: 401, code: 'unauthorized' });

    vi.unstubAllGlobals();
  });

  it('throws ApiError with status 403 on Forbidden response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: 'insufficient_scope' }),
    });
    vi.stubGlobal('fetch', mockFetch);

    await expect(dpopFetch('https://localhost:7100/api/identity', session)).rejects.toThrow(ApiError);
    await expect(dpopFetch('https://localhost:7100/api/identity', session))
      .rejects.toMatchObject({ status: 403, code: 'forbidden' });

    vi.unstubAllGlobals();
  });

  it('returns parsed JSON on success', async () => {
    const expectedData = { userId: 'user-001', fullName: 'Demo User', email: 'demo@example.test' };
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => expectedData,
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await dpopFetch('https://localhost:7100/api/profile', session);
    expect(result).toEqual(expectedData);

    vi.unstubAllGlobals();
  });
});
