# Phase 4 — Next.js / React Secure Identity Client

## Overview

Phase 4 adds a browser-based client (`IdentityClient.Web`) to the existing `secure-identity-data-poc` repository. The client demonstrates a complete, standards-compliant browser OAuth flow using:

- **OAuth 2.1 Authorization Code + PKCE** (RFC 7636, S256)
- **DPoP sender-constrained tokens** (RFC 9449, EC P-256 / ES256)
- **Web Crypto API** for all cryptographic operations
- **Next.js App Router** as the browser application framework

All cryptographic operations run in the browser. No client secret exists — this is a public client.

---

## Architecture

```
Browser
  │
  │  1. Generate PKCE code_verifier (Web Crypto — getRandomValues)
  │  2. Compute code_challenge = BASE64URL(SHA-256(verifier))
  │  3. Generate EC P-256 DPoP key pair (non-extractable private key)
  │  4. Generate state (crypto random — CSRF protection)
  │  5. Store state + code_verifier in sessionStorage
  │  6. Redirect browser to authorization endpoint
  │
  ▼
IdentityProvider.Api  (https://localhost:7001)
  │  GET /oauth/authorize?client_id=...&code_challenge=...&state=...
  │  → 302 http://localhost:3000/callback?code=AUTH_CODE&state=STATE
  │
  ▼
Next.js /callback  (http://localhost:3000/callback)
  │  7. Validate state (CSRF check — abort on mismatch)
  │  8. Generate DPoP proof for POST /oauth/token
  │     Header: typ=dpop+jwt, alg=ES256, jwk={public key}
  │     Payload: jti, htm=POST, htu=.../oauth/token, iat
  │  9. POST /oauth/token with code + code_verifier + DPoP header
  │
  ▼
IdentityProvider.Api
  │  Validates PKCE, validates DPoP proof, embeds cnf.jkt in access token
  │  → { access_token (DPoP-bound), token_type: "DPoP", expires_in: 900 }
  │
  ▼
React State (in-memory, never localStorage)
  │  10. Store access token + DPoP key pair in React context
  │  11. For each resource request:
  │      - Generate fresh DPoP proof (new jti, current iat, ath=SHA256(token))
  │      - Attach: Authorization: DPoP <token>  +  DPoP: <proof>
  │
  ▼
IdentityData.Api  (https://localhost:7100)
  │  Validates full RFC 9449 chain: proof sig, htm, htu, iat, ath, jti replay, cnf.jkt
  │  → Profile / Identity data
```

### Responsibility Matrix

| Responsibility | Owner | Reason |
|---|---|---|
| PKCE code_verifier generation | Browser (Web Crypto) | Client-generated, must never reach the server before token exchange |
| PKCE code_challenge | Browser (Web Crypto `subtle.digest`) | Derived from verifier |
| EC P-256 DPoP key pair | Browser (Web Crypto — non-extractable) | Private key must stay in browser |
| DPoP proof signing | Browser | Requires private key |
| OAuth state | Browser (sessionStorage, cleared after use) | CSRF protection |
| access token storage | Browser (React in-memory state) | Security-first: no localStorage |
| Resource API calls | Browser | DPoP proofs require the private key |
| PKCE validation | IdentityProvider.Api | Server-side S256 verification |
| DPoP token endpoint validation | IdentityProvider.Api | Embeds cnf.jkt into token |
| DPoP resource server validation | IdentityData.Api | Full RFC 9449 chain |
| CORS policy | Both .NET APIs | Explicit origin: http://localhost:3000 |

### Why No BFF (Backend-for-Frontend)?

A Next.js server-side BFF would be architecturally preferable for production (HttpOnly cookies, server-side token exchange). However, this POC explicitly demonstrates **browser-based DPoP** — the private key is generated and held in the browser, and every DPoP proof is signed there. Moving proof generation to a BFF would require either sending the private key to the server (defeating DPoP) or re-architecting to a confidential client pattern. The browser-DPoP approach is what this POC exists to demonstrate.

---

## OAuth Flow — Step by Step

### Step 1: Authorization Request

User clicks "Sign in" → [`/app/login/page.tsx`](../src/IdentityClient.Web/app/login/page.tsx)

```
buildAuthorizationUrl() — lib/auth/oauth-flow.ts
  generateCodeVerifier()    → 32 crypto-random bytes → base64url (43 chars)
  computeCodeChallenge()    → SHA-256(verifier) → base64url
  generateState()           → 32 crypto-random bytes → base64url
  storeOAuthTransaction()   → sessionStorage: {state, code_verifier}
  
Redirect to:
  https://localhost:7001/oauth/authorize
    ?client_id=secure-demo-client
    &redirect_uri=http://localhost:3000/callback
    &response_type=code
    &scope=openid profile identity.read
    &state=<random>
    &code_challenge=<S256>
    &code_challenge_method=S256
```

### Step 2: Authorization Response

The Identity Provider auto-authenticates the demo user and redirects:
```
302 → http://localhost:3000/callback?code=AUTH_CODE&state=STATE
```

### Step 3: Callback Processing

[`/app/callback/page.tsx`](../src/IdentityClient.Web/app/callback/page.tsx)

```
generateDpopKeyPair()       → EC P-256, non-extractable private key
validateCallback()          → state check (CSRF protection), consume code_verifier
exchangeCodeForToken()      →
  generateDpopProof(keyPair, { htm: 'POST', htu: '.../oauth/token' })
    → Header: { typ:'dpop+jwt', alg:'ES256', jwk:{public} }
    → Payload: { jti:uuid, htm:'POST', htu:'...', iat:now }
    → Signature: ES256 with private key
  POST /oauth/token
    Content-Type: application/x-www-form-urlencoded
    DPoP: <proof>
    Body: grant_type=authorization_code&code=...&code_verifier=...&redirect_uri=...&client_id=...
```

### Step 4: Resource Requests

[`lib/api/api-client.ts`](../src/IdentityClient.Web/lib/api/api-client.ts)

For every request to `/api/profile` or `/api/identity`:
```
dpopFetch(url, { accessToken, dpopKeyPair })
  generateDpopProof(keyPair, { htm:'GET', htu:url, accessToken })
    → Payload includes: ath = BASE64URL(SHA-256(ASCII(access_token)))
  
  fetch(url, {
    headers: {
      Authorization: 'DPoP <token>',
      DPoP: '<fresh proof>'
    }
  })
```

---

## PKCE Implementation

File: [`lib/auth/pkce.ts`](../src/IdentityClient.Web/lib/auth/pkce.ts)

```
code_verifier  = BASE64URL(32 random bytes)   [43 chars]
code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))   [S256 method]
```

Verified against RFC 7636 Appendix B test vector:
- verifier: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
- challenge: `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`

---

## DPoP Implementation

### Key Generation

File: [`lib/dpop/dpop-key.ts`](../src/IdentityClient.Web/lib/dpop/dpop-key.ts)

```typescript
crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  /* extractable: */ false,   // ← private key non-extractable
  ['sign', 'verify']
)
```

The `extractable: false` flag prevents any code — including XSS payloads — from exporting the raw private key bytes.

### JWK Thumbprint (RFC 7638)

File: [`lib/dpop/jwk-thumbprint.ts`](../src/IdentityClient.Web/lib/dpop/jwk-thumbprint.ts)

Canonical JSON form:
```json
{"crv":"P-256","kty":"EC","x":"...","y":"..."}
```
Members in lexicographic order: `crv`, `kty`, `x`, `y`. This matches the server-side `JwkThumbprintService.cs` exactly.

`thumbprint = BASE64URL(SHA-256(UTF-8(canonical_json)))`

### Proof Generation

File: [`lib/dpop/dpop-proof.ts`](../src/IdentityClient.Web/lib/dpop/dpop-proof.ts)

JWT Header:
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

JWT Payload (token endpoint):
```json
{ "jti": "uuid-v4", "htm": "POST", "htu": "https://localhost:7001/oauth/token", "iat": 1234567890 }
```

JWT Payload (resource server):
```json
{ "jti": "uuid-v4", "htm": "GET", "htu": "https://localhost:7100/api/profile", "iat": 1234567890, "ath": "BASE64URL(SHA-256(access_token))" }
```

Every proof has a fresh `jti` (UUID) and current `iat`. Proofs are never reused.

---

## Security Model

### Token Storage

| Storage | Used | Reason |
|---|---|---|
| `localStorage` | Never | Persists across sessions; XSS-accessible |
| `sessionStorage` | Only for OAuth transaction (state + code_verifier, cleared after callback) | Tab-scoped; single-use |
| React state (in-memory) | Yes — access token + DPoP key pair | Lost on refresh; not XSS-persistent |
| HttpOnly cookies | Not used (no BFF) | Would require server-side proxy |

**Limitation:** The access token is lost on page refresh. The user must re-authenticate. This is the intentional secure default for a browser-DPoP POC.

### DPoP Private Key Protection

The `CryptoKey` object created with `extractable: false` cannot be exported — not even by malicious JavaScript running in the same browser context. An XSS attacker can call `generateDpopProof()` using the existing key, but cannot extract the raw key material.

Even if an attacker obtains the DPoP-bound access token (e.g., via memory inspection), they cannot present it without also being able to generate valid DPoP proofs — which requires the private key.

### CSRF Protection

The `state` parameter is a 256-bit cryptographically random value stored in `sessionStorage`. It is validated in `validateCallback()` before the authorization code exchange proceeds. A mismatch throws `OAuthError('state_mismatch', ...)` and aborts the flow.

### XSS Considerations

XSS is the primary threat to a browser-based client. Mitigations in this implementation:
- Private key is non-extractable (Web Crypto)
- Access token in React state only (no localStorage)
- DPoP binding: even if an attacker obtains the token, they cannot use it without the private key
- The token has a 15-minute TTL

### CORS Configuration

Both backends use an explicit origin allowlist — `http://localhost:3000` only. `AllowAnyOrigin()` is not used.

**IdentityProvider.Api CORS** (POST to `/oauth/token`, GET to discovery endpoints):
```csharp
policy.WithOrigins("http://localhost:3000")
      .WithMethods("GET", "POST", "OPTIONS")
      .WithHeaders("Content-Type", "DPoP", "Authorization")
      .AllowCredentials()
```

**IdentityData.Api CORS** (GET to `/api/profile`, `/api/identity`):
```csharp
policy.WithOrigins("http://localhost:3000")
      .WithMethods("GET", "OPTIONS")
      .WithHeaders("Content-Type", "Authorization", "DPoP")
      .AllowCredentials()
```

### Redirect URI

Registered exact match: `http://localhost:3000/callback`

The `OAuthClient.IsRedirectUriAllowed()` method uses `StringComparison.Ordinal` — no wildcard matching, no prefix matching.

---

## Project Structure

```
src/IdentityClient.Web/
├── app/
│   ├── layout.tsx               # Root layout — AuthProvider + Nav
│   ├── page.tsx                 # Home page — POC overview + architecture
│   ├── login/page.tsx           # Initiates OAuth flow
│   ├── callback/page.tsx        # Handles OAuth redirect (state check, token exchange)
│   ├── profile/page.tsx         # GET /api/profile with DPoP
│   ├── identity/page.tsx        # GET /api/identity with DPoP
│   └── security/page.tsx        # Security mechanism display
├── components/
│   └── Nav.tsx                  # Responsive nav — auth-aware
├── context/
│   └── auth-context.tsx         # AuthProvider, useAuth, AuthState reducer
├── lib/
│   ├── auth/
│   │   ├── auth-config.ts       # Env vars + endpoint URLs
│   │   ├── pkce.ts              # PKCE verifier/challenge (Web Crypto)
│   │   ├── state.ts             # OAuth state (sessionStorage)
│   │   └── oauth-flow.ts        # Auth URL, callback validation, token exchange
│   ├── dpop/
│   │   ├── dpop-key.ts          # EC P-256 key pair generation
│   │   ├── jwk-thumbprint.ts    # RFC 7638 JWK thumbprint
│   │   └── dpop-proof.ts        # DPoP proof JWT generation
│   └── api/
│       ├── api-client.ts        # DPoP-authenticated fetch wrapper
│       └── identity-api.ts      # /api/profile and /api/identity typed calls
└── tests/
    ├── lib/auth/
    │   ├── pkce.test.ts
    │   └── oauth-flow.test.ts
    ├── lib/dpop/
    │   ├── dpop-key.test.ts
    │   └── dpop-proof.test.ts
    └── lib/api/
        └── api-client.test.ts
```

---

## Configuration

Copy `.env.local.example` to `.env.local`:

```bash
NEXT_PUBLIC_IDENTITY_PROVIDER_URL=https://localhost:7001
NEXT_PUBLIC_IDENTITY_API_URL=https://localhost:7100
NEXT_PUBLIC_CLIENT_ID=secure-demo-client
NEXT_PUBLIC_REDIRECT_URI=http://localhost:3000/callback
NEXT_PUBLIC_OAUTH_SCOPE=openid profile identity.read
```

All values are public endpoint URLs and a public client_id — no secrets. A browser-based public client must not hold a confidential client secret.

---

## Local Development

### Prerequisites

- .NET 10 SDK
- Node.js 18+ (tested with v22)
- PostgreSQL (or Docker Compose)

### Start all services

**Terminal 1 — Identity Provider:**
```bash
dotnet run --project src/IdentityProvider.Api
# → https://localhost:7001
```

**Terminal 2 — Identity Data API:**
```bash
dotnet run --project src/IdentityData.Api
# → https://localhost:7100
```

**Terminal 3 — Next.js Client:**
```bash
cd src/IdentityClient.Web
cp .env.local.example .env.local
npm install
npm run dev
# → http://localhost:3000
```

### Test the flow

1. Open `http://localhost:3000`
2. Click **Sign in**
3. Browser redirects to `https://localhost:7001/oauth/authorize`
4. Identity Provider redirects to `http://localhost:3000/callback`
5. Callback page validates state, exchanges code, stores DPoP-bound token
6. Profile and Identity pages call the protected API with DPoP proofs

---

## Testing

### Frontend tests

```bash
cd src/IdentityClient.Web
npm test
```

Covers:
- PKCE verifier generation, S256 challenge (including RFC 7636 Appendix B test vector)
- OAuth authorization URL construction, state generation, callback validation
- DPoP key generation (type, extractability, algorithm)
- JWK thumbprint canonical JSON
- DPoP proof structure (typ, alg, jwk, jti, htm, htu, iat, ath)
- DPoP proof signature validity
- API client header injection, 401/403 handling, fresh proof per request

### Backend tests

```bash
dotnet test SecureIdentityData.slnx
```

All 133 existing backend tests continue to pass after the Phase 4 changes.

### Negative security tests (backend — existing Phase 3 tests)

The existing integration tests verify:
- Bearer scheme rejected for DPoP-bound tokens
- Wrong DPoP key rejected
- Invalid signature rejected
- Wrong HTTP method rejected
- Wrong URI rejected
- Invalid `ath` rejected
- Replayed proof rejected
- Missing scope rejected
- Expired token rejected

---

## Backend Changes Made in Phase 4

Three minimal changes were required — no security semantics changed:

### 1. `InMemoryClientStore.cs` — redirect URI

Changed registered redirect URI from `https://localhost:3000/callback` to `http://localhost:3000/callback`.

**Why:** Next.js development server runs HTTP (not HTTPS) on port 3000. Using a self-signed cert for local development adds unnecessary complexity without security benefit.

**Impact:** API contract unchanged. No new endpoints. Integration tests updated to match.

### 2. `IdentityProvider.Api/Program.cs` — CORS

Added `AddCors` + `UseCors("NextJsClient")` with `WithOrigins("http://localhost:3000")`.

**Why:** The browser makes cross-origin requests to the token endpoint from `http://localhost:3000`.

**Note:** The authorization endpoint is a browser navigation (redirect), not a cross-origin AJAX call — CORS does not apply to it. CORS applies only to the fetch calls: token endpoint POST, discovery GET, JWKS GET.

### 3. `IdentityData.Api/Program.cs` — CORS

Same as above — added CORS for `/api/profile` and `/api/identity`.

---

## Limitations

- **Token lost on refresh:** Access token and DPoP key pair live in React state. Page refresh requires re-authentication. A production system would use a server-side BFF with HttpOnly cookie token storage.
- **No refresh tokens:** The Identity Provider does not issue refresh tokens. Re-authentication is required when the 15-minute token expires. This is correct for a browser public client in the absence of a secure refresh token mechanism.
- **No end-session endpoint:** The Identity Provider does not implement a formal `end_session_endpoint`. Logout clears client state only.
- **Self-signed certificates:** HTTPS between the browser and `localhost:7001` / `localhost:7100` requires accepting the .NET development certificate. This is standard for local development.
- **HTTP redirect URI:** Using `http://localhost:3000/callback` instead of HTTPS is acceptable for `localhost` per RFC 8252 §8.3.

---

## Security Considerations for Production

A production deployment of a browser-based OAuth client should consider:

1. **BFF (Backend-for-Frontend):** Move token exchange to a server route; store tokens in HttpOnly, Secure, SameSite=Strict cookies; the private DPoP key would be generated in the browser but proofs would be sent to the BFF to attach headers.
2. **Confidential client upgrade:** Use a server-side BFF as a confidential client to participate in dynamic client registration or use a client assertion instead.
3. **Content Security Policy:** Strict CSP headers to mitigate XSS.
4. **HTTPS everywhere:** Production redirect URIs must be HTTPS.
5. **Key rotation:** DPoP key pairs should be rotated periodically.
6. **Token binding to session:** Consider binding the DPoP key pair to the browser session more explicitly.
