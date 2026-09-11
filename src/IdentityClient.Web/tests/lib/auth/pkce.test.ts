import { describe, it, expect } from 'vitest';
import { generateCodeVerifier, computeCodeChallenge } from '@/lib/auth/pkce';

// ─────────────────────────────────────────────────────────────────────────────
// RFC 7636 Appendix B test vector:
//   verifier:   dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
//   challenge:  E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
// ─────────────────────────────────────────────────────────────────────────────
const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('PKCE — generateCodeVerifier', () => {
  it('returns a string of length 43 (32 bytes → base64url)', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(43);
  });

  it('contains only URL-safe base64url characters', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('contains no base64 padding characters', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).not.toContain('=');
    expect(verifier).not.toContain('+');
    expect(verifier).not.toContain('/');
  });

  it('produces unique values on each call', () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    const v3 = generateCodeVerifier();
    expect(v1).not.toBe(v2);
    expect(v1).not.toBe(v3);
    expect(v2).not.toBe(v3);
  });
});

describe('PKCE — computeCodeChallenge (S256)', () => {
  it('matches the RFC 7636 Appendix B test vector', async () => {
    const challenge = await computeCodeChallenge(RFC_VERIFIER);
    expect(challenge).toBe(RFC_CHALLENGE);
  });

  it('returns a base64url string (no padding, no +, no /)', async () => {
    const challenge = await computeCodeChallenge(generateCodeVerifier());
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(challenge).not.toContain('=');
  });

  it('produces different challenges for different verifiers', async () => {
    const v1 = generateCodeVerifier();
    const v2 = generateCodeVerifier();
    const c1 = await computeCodeChallenge(v1);
    const c2 = await computeCodeChallenge(v2);
    expect(c1).not.toBe(c2);
  });

  it('is deterministic — same verifier always produces same challenge', async () => {
    const verifier = generateCodeVerifier();
    const c1 = await computeCodeChallenge(verifier);
    const c2 = await computeCodeChallenge(verifier);
    expect(c1).toBe(c2);
  });
});
