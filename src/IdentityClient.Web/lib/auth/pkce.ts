/**
 * PKCE (Proof Key for Code Exchange) — RFC 7636
 *
 * Implements the S256 method:
 *   code_verifier  = cryptographically random 43–128 character URL-safe string
 *   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
 *
 * The code_verifier is generated using the Web Crypto API (crypto.getRandomValues)
 * to ensure cryptographic randomness. It is never sent to the server except at the
 * token exchange step, where it proves the client initiated the authorization request.
 *
 * The plain method is intentionally unsupported — S256 is required per OAuth 2.1.
 */

/** Length in bytes for the random verifier. 32 bytes → 43 base64url chars. */
const VERIFIER_BYTE_LENGTH = 32;

/**
 * Encodes a byte array as a base64url string (no padding).
 * Used for both the code_verifier and code_challenge.
 */
function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generates a cryptographically random PKCE code_verifier.
 * Returns a 43-character base64url-encoded string (from 32 random bytes).
 * Each call produces a unique value — do not reuse across authorization requests.
 */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(VERIFIER_BYTE_LENGTH);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Computes the S256 code_challenge from a code_verifier.
 * BASE64URL(SHA-256(ASCII(code_verifier)))
 *
 * Uses the Web Crypto API subtleCrypto.digest for the SHA-256 hash.
 */
export async function computeCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}
