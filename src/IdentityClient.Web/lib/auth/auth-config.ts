/**
 * OAuth / API configuration loaded from environment variables.
 *
 * All NEXT_PUBLIC_* values are safe to expose to the browser — they are
 * endpoint URLs and a public client_id. No secrets are stored here.
 *
 * A browser-based OAuth public client MUST NOT hold a client_secret.
 * PKCE provides the required proof-of-possession for public clients (RFC 7636).
 */

function required(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

export const authConfig = {
  /** Base URL of IdentityProvider.Api */
  identityProviderUrl: process.env.NEXT_PUBLIC_IDENTITY_PROVIDER_URL ?? 'https://localhost:7001',

  /** Base URL of IdentityData.Api */
  identityApiUrl: process.env.NEXT_PUBLIC_IDENTITY_API_URL ?? 'https://localhost:7100',

  /** OAuth client_id — public, not a secret */
  clientId: process.env.NEXT_PUBLIC_CLIENT_ID ?? 'secure-demo-client',

  /** Exact redirect URI registered in the Identity Provider */
  redirectUri: process.env.NEXT_PUBLIC_REDIRECT_URI ?? 'http://localhost:3000/callback',

  /** Space-separated OAuth scopes to request */
  scope: process.env.NEXT_PUBLIC_OAUTH_SCOPE ?? 'openid profile identity.read',
} as const;

/** Derived endpoint URLs */
export const endpoints = {
  authorization: `${authConfig.identityProviderUrl}/oauth/authorize`,
  token: `${authConfig.identityProviderUrl}/oauth/token`,
  jwks: `${authConfig.identityProviderUrl}/.well-known/jwks.json`,
  discovery: `${authConfig.identityProviderUrl}/.well-known/openid-configuration`,
  profile: `${authConfig.identityApiUrl}/api/profile`,
  identity: `${authConfig.identityApiUrl}/api/identity`,
} as const;
