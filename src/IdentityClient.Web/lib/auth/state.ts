/**
 * OAuth state parameter — CSRF protection for the authorization redirect.
 *
 * The state value is generated before the browser is redirected to the
 * authorization endpoint. On callback, the returned state is compared
 * against the stored value. A mismatch aborts the flow.
 *
 * State is stored in sessionStorage for the duration of the redirect loop
 * and cleared immediately after successful validation.
 */

const STATE_BYTE_LENGTH = 32;
const STATE_KEY = 'oauth_state';
const CODE_VERIFIER_KEY = 'oauth_code_verifier';

/** Base64url-encode a Uint8Array */
function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generates a cryptographically random OAuth state value.
 * 32 bytes → 43 base64url characters.
 */
export function generateState(): string {
  const bytes = new Uint8Array(STATE_BYTE_LENGTH);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** Persists the OAuth transaction state to sessionStorage. */
export function storeOAuthTransaction(state: string, codeVerifier: string): void {
  sessionStorage.setItem(STATE_KEY, state);
  sessionStorage.setItem(CODE_VERIFIER_KEY, codeVerifier);
}

/**
 * Retrieves and clears the stored OAuth transaction state.
 * Returns null if no transaction is in progress.
 * Clears the values immediately — single use only.
 */
export function consumeOAuthTransaction(): { state: string; codeVerifier: string } | null {
  const state = sessionStorage.getItem(STATE_KEY);
  const codeVerifier = sessionStorage.getItem(CODE_VERIFIER_KEY);

  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(CODE_VERIFIER_KEY);

  if (!state || !codeVerifier) return null;
  return { state, codeVerifier };
}
