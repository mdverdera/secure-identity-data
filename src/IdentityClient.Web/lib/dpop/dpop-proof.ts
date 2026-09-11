/**
 * DPoP Proof JWT generation — RFC 9449
 *
 * A DPoP proof is a short-lived JWT that binds an HTTP request to a specific
 * EC key pair. It is signed with the client's private key and must be generated
 * fresh for every request (unique jti + current iat).
 *
 * JWT Header:
 *   typ: "dpop+jwt"
 *   alg: "ES256"
 *   jwk: { kty, crv, x, y }   ← public key, NO private key
 *
 * JWT Payload:
 *   jti:  unique identifier (UUID) — replay protection
 *   htm:  HTTP method (uppercase)
 *   htu:  HTTP target URI (scheme + host + path, no query/fragment)
 *   iat:  issued-at (Unix seconds)
 *   ath:  BASE64URL(SHA-256(ASCII(access_token)))  ← only when presenting a token
 */

import { exportPublicKeyAsJwk, DPOP_SIGN_ALGORITHM } from './dpop-key';

function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlEncodeJson(obj: object): string {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  return base64UrlEncode(bytes);
}

/**
 * Computes the access token hash (ath) for a DPoP proof.
 * ath = BASE64URL(SHA-256(ASCII(access_token)))
 * Required when presenting a DPoP-bound access token to a resource server.
 */
async function computeAth(accessToken: string): Promise<string> {
  const bytes = new TextEncoder().encode(accessToken);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

export interface DpopProofOptions {
  /** HTTP method, uppercase: "GET", "POST", etc. */
  htm: string;
  /**
   * HTTP target URI — scheme + host + path only.
   * No query string, no fragment. Must match the server's request URI.
   */
  htu: string;
  /** Raw access token string, if presenting to a resource server. */
  accessToken?: string;
}

/**
 * Generates a fresh DPoP proof JWT.
 *
 * Must be called once per request — the jti and iat are unique to each call.
 * Never reuse a proof across requests.
 *
 * @param keyPair - The session DPoP key pair. Private key is used to sign.
 * @param options - HTTP method, URI, and optional access token for ath.
 * @returns A signed DPoP proof JWT string.
 */
export async function generateDpopProof(
  keyPair: CryptoKeyPair,
  options: DpopProofOptions,
): Promise<string> {
  const publicJwk = await exportPublicKeyAsJwk(keyPair.publicKey);

  // JWT header
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y,
    },
  };

  // JWT payload
  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: options.htm.toUpperCase(),
    htu: normalizeHtu(options.htu),
    iat: Math.floor(Date.now() / 1000),
  };

  if (options.accessToken) {
    payload['ath'] = await computeAth(options.accessToken);
  }

  const signingInput =
    base64UrlEncodeJson(header) + '.' + base64UrlEncodeJson(payload);

  const signingBytes = new TextEncoder().encode(signingInput);
  const signatureBuffer = await crypto.subtle.sign(
    DPOP_SIGN_ALGORITHM,
    keyPair.privateKey,
    signingBytes,
  );

  const signature = base64UrlEncode(new Uint8Array(signatureBuffer));
  return `${signingInput}.${signature}`;
}

/**
 * Normalises the htu: strips query string and fragment.
 * The server validates scheme + authority + path only.
 */
function normalizeHtu(uri: string): string {
  try {
    const url = new URL(uri);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    // If it's not a valid URL, return as-is and let the server reject it
    return uri;
  }
}
