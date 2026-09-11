import { describe, it, expect, beforeAll } from 'vitest';
import { generateDpopKeyPair, exportPublicKeyAsJwk, DPOP_SIGN_ALGORITHM } from '@/lib/dpop/dpop-key';
import { generateDpopProof } from '@/lib/dpop/dpop-proof';

/** Decodes a base64url-encoded string to a UTF-8 string */
function base64UrlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
}

/** Parses a JWT string into its header and payload objects */
function parseJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [headerB64, payloadB64] = jwt.split('.');
  return {
    header: JSON.parse(base64UrlDecode(headerB64)),
    payload: JSON.parse(base64UrlDecode(payloadB64)),
  };
}

describe('DPoP Proof — generateDpopProof', () => {
  let keyPair: CryptoKeyPair;

  beforeAll(async () => {
    keyPair = await generateDpopKeyPair();
  });

  it('returns a three-part JWT string (header.payload.signature)', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'POST', htu: 'https://localhost:7001/oauth/token' });
    const parts = proof.split('.');
    expect(parts).toHaveLength(3);
    expect(parts[0].length).toBeGreaterThan(0);
    expect(parts[1].length).toBeGreaterThan(0);
    expect(parts[2].length).toBeGreaterThan(0);
  });

  // ── Header claims ──────────────────────────────────────────────────────────

  it('header.typ is "dpop+jwt"', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { header } = parseJwt(proof);
    expect(header['typ']).toBe('dpop+jwt');
  });

  it('header.alg is "ES256"', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { header } = parseJwt(proof);
    expect(header['alg']).toBe('ES256');
  });

  it('header.jwk contains the public key (kty, crv, x, y)', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { header } = parseJwt(proof);
    const jwk = header['jwk'] as Record<string, unknown>;
    expect(jwk).toBeDefined();
    expect(jwk['kty']).toBe('EC');
    expect(jwk['crv']).toBe('P-256');
    expect(typeof jwk['x']).toBe('string');
    expect(typeof jwk['y']).toBe('string');
  });

  it('header.jwk does NOT contain the private key parameter d', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { header } = parseJwt(proof);
    const jwk = header['jwk'] as Record<string, unknown>;
    expect(jwk['d']).toBeUndefined();
  });

  // ── Payload claims ────────────────────────────────────────────────────────

  it('payload.jti is a non-empty string', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { payload } = parseJwt(proof);
    expect(typeof payload['jti']).toBe('string');
    expect((payload['jti'] as string).length).toBeGreaterThan(0);
  });

  it('payload.jti is unique across calls (replay protection)', async () => {
    const p1 = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const p2 = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { payload: pl1 } = parseJwt(p1);
    const { payload: pl2 } = parseJwt(p2);
    expect(pl1['jti']).not.toBe(pl2['jti']);
  });

  it('payload.htm matches the provided HTTP method (uppercase)', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'post', htu: 'https://localhost:7001/oauth/token' });
    const { payload } = parseJwt(proof);
    expect(payload['htm']).toBe('POST');
  });

  it('payload.htu matches the provided URI', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const { payload } = parseJwt(proof);
    expect(payload['htu']).toBe('https://localhost:7100/api/profile');
  });

  it('payload.htu strips query string and fragment', async () => {
    const proof = await generateDpopProof(keyPair, {
      htm: 'GET',
      htu: 'https://localhost:7100/api/profile?foo=bar#frag',
    });
    const { payload } = parseJwt(proof);
    expect(payload['htu']).toBe('https://localhost:7100/api/profile');
  });

  it('payload.iat is a Unix timestamp within ±5 seconds of now', async () => {
    const beforeMs = Date.now();
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const afterMs = Date.now();
    const { payload } = parseJwt(proof);
    const iat = payload['iat'] as number;
    expect(iat).toBeGreaterThanOrEqual(Math.floor(beforeMs / 1000) - 1);
    expect(iat).toBeLessThanOrEqual(Math.ceil(afterMs / 1000) + 1);
  });

  // ── Access token hash (ath) ───────────────────────────────────────────────

  it('payload.ath is absent when no accessToken is provided', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'POST', htu: 'https://localhost:7001/oauth/token' });
    const { payload } = parseJwt(proof);
    expect(payload['ath']).toBeUndefined();
  });

  it('payload.ath is present when accessToken is provided', async () => {
    const proof = await generateDpopProof(keyPair, {
      htm: 'GET',
      htu: 'https://localhost:7100/api/profile',
      accessToken: 'eyJhbGciOiJSUzI1NiJ9.example.token',
    });
    const { payload } = parseJwt(proof);
    expect(payload['ath']).toBeDefined();
    expect(typeof payload['ath']).toBe('string');
  });

  it('payload.ath is BASE64URL(SHA-256(ASCII(token)))', async () => {
    const accessToken = 'eyJhbGciOiJSUzI1NiJ9.test.token';
    const proof = await generateDpopProof(keyPair, {
      htm: 'GET',
      htu: 'https://localhost:7100/api/profile',
      accessToken,
    });
    const { payload } = parseJwt(proof);

    // Compute expected ath manually
    const tokenBytes = new TextEncoder().encode(accessToken);
    const hashBuffer = await crypto.subtle.digest('SHA-256', tokenBytes);
    const expected = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    expect(payload['ath']).toBe(expected);
  });

  // ── Signature verification ────────────────────────────────────────────────

  it('signature is valid and verifiable with the public key', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const parts = proof.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;

    // Decode the base64url signature
    const sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
    const pad = sigB64.length % 4 === 0 ? '' : '='.repeat(4 - (sigB64.length % 4));
    const sigBytes = Uint8Array.from(atob(sigB64 + pad), (c) => c.charCodeAt(0));

    const signingBytes = new TextEncoder().encode(signingInput);
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.publicKey,
      sigBytes,
      signingBytes,
    );
    expect(isValid).toBe(true);
  });

  it('signature is invalid when tampered with', async () => {
    const proof = await generateDpopProof(keyPair, { htm: 'GET', htu: 'https://localhost:7100/api/profile' });
    const parts = proof.split('.');
    // Tamper by changing one character in the payload
    const tamperedPayload = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'a' ? 'b' : 'a');
    const tamperedInput = `${parts[0]}.${tamperedPayload}`;

    const sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
    const pad = sigB64.length % 4 === 0 ? '' : '='.repeat(4 - (sigB64.length % 4));
    const sigBytes = Uint8Array.from(atob(sigB64 + pad), (c) => c.charCodeAt(0));

    const tamperedBytes = new TextEncoder().encode(tamperedInput);
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.publicKey,
      sigBytes,
      tamperedBytes,
    );
    expect(isValid).toBe(false);
  });
});
