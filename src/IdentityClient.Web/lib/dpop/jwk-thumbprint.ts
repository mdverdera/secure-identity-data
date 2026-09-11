/**
 * JWK Thumbprint — RFC 7638
 *
 * Computes SHA-256(canonical_json(jwk)) as a base64url string.
 * Used to derive the cnf.jkt claim embedded in the access token by the Identity Provider.
 *
 * Canonical JSON for EC P-256 (RFC 7638 §3):
 *   Members in lexicographic order, no whitespace.
 *   {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
 *
 * This must remain bit-for-bit identical to the server-side implementation in
 * IdentityProvider.Api/Infrastructure/DPoP/JwkThumbprintService.cs and
 * IdentityData.Api/Infrastructure/DPoP/JwkThumbprintService.cs.
 */

function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Computes the RFC 7638 JWK thumbprint for an EC P-256 public key.
 *
 * @param jwk - The public JWK (must contain kty, crv, x, y)
 * @returns Base64URL(SHA-256(canonical_json))
 *
 * Canonical form: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
 * (keys in lexicographic order: crv, kty, x, y)
 */
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  if (!jwk.crv || !jwk.x || !jwk.y) {
    throw new Error('JWK must contain crv, x, and y for P-256 thumbprint computation');
  }

  // RFC 7638 §3: only the required members for the key type, in lexicographic order.
  // For EC P-256: crv, kty, x, y
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}
