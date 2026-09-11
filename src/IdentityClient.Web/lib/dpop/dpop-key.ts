/**
 * DPoP EC P-256 key pair management.
 *
 * Generates a non-extractable CryptoKeyPair using the Web Crypto API.
 * The private key is marked non-extractable — even XSS code cannot export the raw bytes.
 * Only the public key is ever serialised (as JWK) for embedding in DPoP proof headers.
 *
 * RFC 9449 — DPoP: Demonstrating Proof of Possession
 * Algorithm: ES256 (ECDSA with SHA-256, NIST P-256 curve)
 */

/** The EC P-256 algorithm parameters used for key generation and signing. */
export const DPOP_KEY_ALGORITHM: EcKeyGenParams = {
  name: 'ECDSA',
  namedCurve: 'P-256',
};

export const DPOP_SIGN_ALGORITHM: EcdsaParams = {
  name: 'ECDSA',
  hash: { name: 'SHA-256' },
};

/**
 * Generates a fresh EC P-256 DPoP key pair.
 *
 * - Private key: non-extractable — cannot be exported from the browser's crypto engine.
 * - Public key: extractable — used to build the `jwk` header in DPoP proofs.
 *
 * A new key pair should be generated once per session. The same key pair is reused
 * across requests within the session so the cnf.jkt binding in the access token remains valid.
 */
export async function generateDpopKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    DPOP_KEY_ALGORITHM,
    /* extractable private key: */ false,
    /* usages: */ ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>;
}

/**
 * Exports the public key as a JWK object.
 * Only the public key (kty, crv, x, y) is included — no private key material.
 *
 * The returned JWK is embedded in DPoP proof headers and used to compute the
 * cnf.jkt thumbprint that is bound into the access token.
 */
export async function exportPublicKeyAsJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  // Safety: remove 'd' if somehow present (should never occur for a public key)
  const { d: _d, ...publicJwk } = jwk as JsonWebKey & { d?: string };
  return publicJwk;
}
