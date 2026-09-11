/**
 * OAuth Authorization Code + PKCE + DPoP flow orchestration.
 *
 * This module coordinates:
 *   1. Building the authorization URL with PKCE and state
 *   2. Validating the callback parameters (state check — CSRF protection)
 *   3. Exchanging the authorization code for a DPoP-bound access token
 *
 * Security:
 *   - state is validated before the code exchange (CSRF protection)
 *   - code_verifier is single-use (consumed from sessionStorage on callback)
 *   - DPoP proof is generated fresh for the token endpoint POST
 *   - No client_secret — this is a public client using PKCE
 */

import { generateCodeVerifier, computeCodeChallenge } from './pkce';
import { generateState, storeOAuthTransaction, consumeOAuthTransaction } from './state';
import { authConfig, endpoints } from './auth-config';
import { generateDpopProof } from '../dpop/dpop-proof';

// ─────────────────────────────────────────────────────────────────────────────
// OAuth Error types
// ─────────────────────────────────────────────────────────────────────────────

export class OAuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token response model
// ─────────────────────────────────────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1 — Build authorization URL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Prepares and stores the OAuth transaction, returning the authorization URL
 * to redirect the browser to.
 *
 * Generates a fresh code_verifier, code_challenge (S256), and state.
 * Stores the verifier and state in sessionStorage for the callback.
 */
export async function buildAuthorizationUrl(): Promise<string> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await computeCodeChallenge(codeVerifier);
  const state = generateState();

  storeOAuthTransaction(state, codeVerifier);

  const params = new URLSearchParams({
    client_id: authConfig.clientId,
    redirect_uri: authConfig.redirectUri,
    response_type: 'code',
    scope: authConfig.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return `${endpoints.authorization}?${params.toString()}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 — Validate callback
// ─────────────────────────────────────────────────────────────────────────────

export interface CallbackParams {
  code: string | null;
  state: string | null;
  error?: string | null;
  error_description?: string | null;
}

export interface ValidatedCallback {
  code: string;
  codeVerifier: string;
}

/**
 * Validates the OAuth callback.
 * - Checks for error parameters from the authorization server
 * - Validates the state against the stored value (CSRF protection)
 * - Consumes and returns the stored code_verifier (single-use)
 *
 * @throws OAuthError on any validation failure
 */
export function validateCallback(params: CallbackParams): ValidatedCallback {
  // Check for error response from authorization server
  if (params.error) {
    throw new OAuthError(
      params.error,
      params.error_description ?? `Authorization failed: ${params.error}`,
    );
  }

  if (!params.code) {
    throw new OAuthError('missing_code', 'Authorization code not present in callback.');
  }

  if (!params.state) {
    throw new OAuthError('missing_state', 'State parameter not present in callback.');
  }

  // Consume the stored OAuth transaction (clears sessionStorage)
  const stored = consumeOAuthTransaction();

  if (!stored) {
    throw new OAuthError(
      'invalid_state',
      'No OAuth transaction found. The authorization request may have expired.',
    );
  }

  if (stored.state !== params.state) {
    throw new OAuthError(
      'state_mismatch',
      'State parameter mismatch. This may indicate a CSRF attack. Please try signing in again.',
    );
  }

  return { code: params.code, codeVerifier: stored.codeVerifier };
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3 — Exchange authorization code for tokens
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Exchanges an authorization code for a DPoP-bound access token.
 *
 * Sends a POST to the token endpoint with:
 * - grant_type=authorization_code
 * - code + redirect_uri + client_id + code_verifier (PKCE)
 * - DPoP: <fresh proof JWT> signed with the session EC key pair
 *
 * @throws OAuthError on server error responses
 * @throws Error on network failure
 */
export async function exchangeCodeForToken(
  code: string,
  codeVerifier: string,
  dpopKeyPair: CryptoKeyPair,
): Promise<TokenResponse> {
  const dpopProof = await generateDpopProof(dpopKeyPair, {
    htm: 'POST',
    htu: endpoints.token,
  });

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: authConfig.redirectUri,
    client_id: authConfig.clientId,
    code_verifier: codeVerifier,
  });

  const response = await fetch(endpoints.token, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'DPoP': dpopProof,
    },
    body: body.toString(),
  });

  if (!response.ok) {
    let errorCode = 'token_request_failed';
    let errorDescription = `Token request failed with status ${response.status}.`;

    try {
      const errorBody = await response.json();
      errorCode = errorBody.error ?? errorCode;
      errorDescription = errorBody.error_description ?? errorDescription;
    } catch {
      // ignore parse errors
    }

    throw new OAuthError(errorCode, errorDescription);
  }

  return response.json() as Promise<TokenResponse>;
}
