import { describe, it, expect } from 'vitest';
import { generateDpopKeyPair, exportPublicKeyAsJwk } from '@/lib/dpop/dpop-key';
import { computeJwkThumbprint } from '@/lib/dpop/jwk-thumbprint';

describe('DPoP Key — generateDpopKeyPair', () => {
  it('returns a CryptoKeyPair', async () => {
    const keyPair = await generateDpopKeyPair();
    expect(keyPair).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.publicKey).toBeDefined();
  });

  it('private key type is EC', async () => {
    const keyPair = await generateDpopKeyPair();
    expect(keyPair.privateKey.type).toBe('private');
  });

  it('public key type is EC', async () => {
    const keyPair = await generateDpopKeyPair();
    expect(keyPair.publicKey.type).toBe('public');
  });

  it('private key is not extractable', async () => {
    const keyPair = await generateDpopKeyPair();
    expect(keyPair.privateKey.extractable).toBe(false);
  });

  it('public key is extractable', async () => {
    const keyPair = await generateDpopKeyPair();
    expect(keyPair.publicKey.extractable).toBe(true);
  });

  it('private key algorithm is ECDSA P-256', async () => {
    const keyPair = await generateDpopKeyPair();
    const algo = keyPair.privateKey.algorithm as EcKeyAlgorithm;
    expect(algo.name).toBe('ECDSA');
    expect(algo.namedCurve).toBe('P-256');
  });
});

describe('DPoP Key — exportPublicKeyAsJwk', () => {
  it('returns kty=EC', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);
    expect(jwk.kty).toBe('EC');
  });

  it('returns crv=P-256', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);
    expect(jwk.crv).toBe('P-256');
  });

  it('contains x and y coordinates', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    expect(typeof jwk.x).toBe('string');
    expect(typeof jwk.y).toBe('string');
  });

  it('does NOT contain the private key parameter d', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey) as Record<string, unknown>;
    expect(jwk['d']).toBeUndefined();
  });
});

describe('JWK Thumbprint — computeJwkThumbprint', () => {
  it('produces a non-empty base64url string', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);
    const thumbprint = await computeJwkThumbprint(jwk);
    expect(thumbprint).toBeTruthy();
    expect(thumbprint).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('is deterministic — same key produces same thumbprint', async () => {
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);
    const t1 = await computeJwkThumbprint(jwk);
    const t2 = await computeJwkThumbprint(jwk);
    expect(t1).toBe(t2);
  });

  it('different keys produce different thumbprints', async () => {
    const kp1 = await generateDpopKeyPair();
    const kp2 = await generateDpopKeyPair();
    const jwk1 = await exportPublicKeyAsJwk(kp1.publicKey);
    const jwk2 = await exportPublicKeyAsJwk(kp2.publicKey);
    const t1 = await computeJwkThumbprint(jwk1);
    const t2 = await computeJwkThumbprint(jwk2);
    expect(t1).not.toBe(t2);
  });

  it('canonical JSON has members in lexicographic order (crv, kty, x, y)', async () => {
    // Validate canonical structure by checking what JSON.stringify produces
    // when given keys in the correct order — this mirrors the server implementation
    const { publicKey } = await generateDpopKeyPair();
    const jwk = await exportPublicKeyAsJwk(publicKey);

    // Construct canonical JSON manually and verify the thumbprint matches
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(canonical));
    const expected = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const actual = await computeJwkThumbprint(jwk);
    expect(actual).toBe(expected);
  });

  it('throws if crv is missing', async () => {
    const incompleteJwk: JsonWebKey = { kty: 'EC', x: 'abc', y: 'def' };
    await expect(computeJwkThumbprint(incompleteJwk)).rejects.toThrow();
  });
});
