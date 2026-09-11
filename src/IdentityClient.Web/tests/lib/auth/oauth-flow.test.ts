import { describe, it, expect, beforeEach, vi } from 'vitest';
import { buildAuthorizationUrl, validateCallback, OAuthError } from '@/lib/auth/oauth-flow';

// ─── Mock sessionStorage ────────────────────────────────────────────────────
const sessionStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; },
  };
})();

Object.defineProperty(globalThis, 'sessionStorage', {
  value: sessionStorageMock,
  writable: true,
});

describe('OAuth Flow — buildAuthorizationUrl', () => {
  beforeEach(() => {
    sessionStorageMock.clear();
  });

  it('returns a URL string starting with the authorization endpoint', async () => {
    const url = await buildAuthorizationUrl();
    expect(url).toContain('/oauth/authorize');
  });

  it('includes response_type=code', async () => {
    const url = await buildAuthorizationUrl();
    expect(url).toContain('response_type=code');
  });

  it('includes client_id', async () => {
    const url = await buildAuthorizationUrl();
    expect(url).toContain('client_id=secure-demo-client');
  });

  it('includes redirect_uri', async () => {
    const url = await buildAuthorizationUrl();
    expect(url).toContain('redirect_uri=');
  });

  it('includes state parameter', async () => {
    const url = await buildAuthorizationUrl();
    const parsed = new URL(url);
    const state = parsed.searchParams.get('state');
    expect(state).toBeTruthy();
    expect(state!.length).toBeGreaterThan(0);
  });

  it('includes code_challenge', async () => {
    const url = await buildAuthorizationUrl();
    const parsed = new URL(url);
    const challenge = parsed.searchParams.get('code_challenge');
    expect(challenge).toBeTruthy();
  });

  it('includes code_challenge_method=S256', async () => {
    const url = await buildAuthorizationUrl();
    expect(url).toContain('code_challenge_method=S256');
  });

  it('generates a unique state on each call', async () => {
    const url1 = await buildAuthorizationUrl();
    sessionStorageMock.clear();
    const url2 = await buildAuthorizationUrl();
    const state1 = new URL(url1).searchParams.get('state');
    const state2 = new URL(url2).searchParams.get('state');
    expect(state1).not.toBe(state2);
  });

  it('stores state and code_verifier in sessionStorage', async () => {
    await buildAuthorizationUrl();
    expect(sessionStorage.getItem('oauth_state')).toBeTruthy();
    expect(sessionStorage.getItem('oauth_code_verifier')).toBeTruthy();
  });
});

describe('OAuth Flow — validateCallback', () => {
  beforeEach(() => {
    sessionStorageMock.clear();
  });

  it('returns code and codeVerifier on valid state', async () => {
    await buildAuthorizationUrl();
    const storedState = sessionStorage.getItem('oauth_state')!;

    const result = validateCallback({ code: 'AUTH_CODE_123', state: storedState });
    expect(result.code).toBe('AUTH_CODE_123');
    expect(typeof result.codeVerifier).toBe('string');
    expect(result.codeVerifier.length).toBeGreaterThan(0);
  });

  it('clears sessionStorage after consuming the transaction', async () => {
    await buildAuthorizationUrl();
    const storedState = sessionStorage.getItem('oauth_state')!;

    validateCallback({ code: 'CODE', state: storedState });

    expect(sessionStorage.getItem('oauth_state')).toBeNull();
    expect(sessionStorage.getItem('oauth_code_verifier')).toBeNull();
  });

  it('throws state_mismatch when state does not match', async () => {
    await buildAuthorizationUrl();
    let caught: OAuthError | null = null;
    try {
      validateCallback({ code: 'CODE', state: 'WRONG_STATE_VALUE' });
    } catch (e) {
      caught = e as OAuthError;
    }
    expect(caught).toBeInstanceOf(OAuthError);
    expect(caught?.message).toContain('State parameter mismatch');
  });

  it('throws invalid_state when no transaction is stored', () => {
    expect(() =>
      validateCallback({ code: 'CODE', state: 'some-state' })
    ).toThrow(OAuthError);
  });

  it('throws on error response from authorization server', () => {
    expect(() =>
      validateCallback({ code: null, state: null, error: 'access_denied', error_description: 'User denied access' })
    ).toThrow(OAuthError);
  });

  it('throws missing_code when code is absent', () => {
    expect(() =>
      validateCallback({ code: null, state: 'some-state' })
    ).toThrow('Authorization code not present');
  });

  it('throws missing_state when state is absent', () => {
    expect(() =>
      validateCallback({ code: 'CODE', state: null })
    ).toThrow('State parameter not present');
  });

  it('OAuthError has the correct error code', async () => {
    await buildAuthorizationUrl();
    try {
      validateCallback({ code: 'CODE', state: 'WRONG' });
    } catch (e) {
      expect(e).toBeInstanceOf(OAuthError);
      expect((e as OAuthError).code).toBe('state_mismatch');
    }
  });
});
