/**
 * DPoP API Client
 *
 * Wraps fetch to automatically attach:
 *   Authorization: DPoP <access-token>
 *   DPoP: <fresh-proof-jwt>
 *
 * A fresh DPoP proof is generated for every request. The same proof must never
 * be reused — the resource server tracks jti values to prevent replay attacks.
 *
 * Security: DPoP proof generation requires the private key, so this client
 * must run in the browser (where the key pair lives). It cannot be moved to
 * a Next.js server route without also moving the private key there.
 */

import { generateDpopProof } from '../dpop/dpop-proof';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface DpopSession {
  accessToken: string;
  dpopKeyPair: CryptoKeyPair;
}

/**
 * Makes a DPoP-authenticated GET request to the given URL.
 *
 * Attaches:
 *   Authorization: DPoP <access-token>
 *   DPoP: <fresh proof, signed with private key, bound to this URI>
 *
 * @throws ApiError on 4xx/5xx responses
 * @throws Error on network failure
 */
export async function dpopFetch<T>(
  url: string,
  session: DpopSession,
  method: string = 'GET',
): Promise<T> {
  // Generate a fresh proof for this specific request (htm + htu + ath)
  const dpopProof = await generateDpopProof(session.dpopKeyPair, {
    htm: method,
    htu: url,
    accessToken: session.accessToken,
  });

  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `DPoP ${session.accessToken}`,
      DPoP: dpopProof,
    },
  });

  if (!response.ok) {
    let code = 'api_error';
    let message = `Request failed with status ${response.status}.`;

    try {
      const body = await response.json();
      code = body.error ?? code;
      message = body.detail ?? body.title ?? body.error_description ?? message;
    } catch {
      // ignore parse errors
    }

    if (response.status === 401) {
      throw new ApiError(401, 'unauthorized', 'Authentication required. Please sign in again.');
    }
    if (response.status === 403) {
      throw new ApiError(403, 'forbidden', 'You do not have permission to access this resource.');
    }

    throw new ApiError(response.status, code, message);
  }

  return response.json() as Promise<T>;
}
