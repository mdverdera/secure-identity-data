# Architecture — Secure Identity & Trusted Data API (Phase 1)

## Overview

Phase 1 implements an OAuth 2.1 Authorization Code + PKCE identity provider using Clean Architecture with a CQRS application layer.

## Layer Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│  API Layer (Controllers, Program.cs, Middleware)                │
│  HTTP adapters only — no business logic                         │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer (Features / CQRS)                           │
│  Commands, Queries, Handlers, Validators                        │
│  Depends on Domain interfaces and Infrastructure interfaces     │
├─────────────────────────────────────────────────────────────────┤
│  Domain Layer (Entities, Exceptions)                            │
│  Pure C# — zero external dependencies                          │
├─────────────────────────────────────────────────────────────────┤
│  Infrastructure Layer (Cryptography, JWT, Persistence)          │
│  Implements application interfaces                              │
│  PkceService, RsaSigningKeyProvider, JwtService, In-memory stores │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow

```
HTTP GET /oauth/authorize
        │
        ▼
AuthorizationController.Authorize()
        │  dispatches
        ▼
MediatR.Send(AuthorizeUserCommand)
        │
        ├── ValidationBehavior (FluentValidation)
        │       validates: client_id, redirect_uri, response_type=code,
        │                  scope, code_challenge, code_challenge_method=S256
        ▼
AuthorizeUserCommandHandler
        │
        ├── IClientStore.FindByClientIdAsync()     — validate client
        ├── client.IsRedirectUriAllowed()          — exact-match redirect_uri
        ├── client.AreScopesAllowed()              — scope validation
        ├── IUserStore.GetDemoUserAsync()          — demo: auto-authenticate
        ├── RandomNumberGenerator.GetBytes(32)     — 256-bit auth code
        └── IAuthorizationCodeStore.StoreAsync()   — persist with PKCE binding
        │
        ▼
302 Redirect → redirect_uri?code=...&state=...
```

```
HTTP POST /oauth/token
        │
        ▼
TokenController.Token()
        │  dispatches
        ▼
MediatR.Send(ExchangeAuthorizationCodeCommand)
        │
        ├── ValidationBehavior (FluentValidation)
        │       validates: grant_type=authorization_code, code, redirect_uri,
        │                  client_id, code_verifier (43–128 chars)
        ▼
ExchangeAuthorizationCodeCommandHandler
        │
        ├── IAuthorizationCodeStore.FindAsync()    — code exists?
        ├── authCode.IsExpired()                   — not expired?
        ├── authCode.Used                          — not already used?
        ├── clientId match                         — same client?
        ├── redirectUri match                      — same redirect_uri?
        ├── IPkceService.ValidateCodeVerifier()    — S256 PKCE check
        ├── authCode.MarkUsed()                    — single-use enforcement
        └── IJwtService.GenerateAccessToken()      — RS256 JWT
        │
        ▼
200 { access_token, token_type, expires_in, scope }
```

## Security Controls

| Control | Mechanism |
|---|---|
| Authorization code entropy | `RandomNumberGenerator.GetBytes(32)` → 256 bits |
| Authorization code TTL | 2 minutes (`expires_at`) |
| Single-use enforcement | `used` flag + code removal on replay |
| Redirect URI validation | Exact string match — no wildcards |
| PKCE algorithm | S256 only — `plain` is `invalid_request` |
| JWT signing | RS256 (2048-bit RSA) |
| JWT TTL | 15 minutes (configurable) |
| JWT replay prevention | `jti` (UUID) per token |
| Key identification | `kid` in JWT header matches JWK |
| Private key exposure | Never logged, never in HTTP response |
| Stack trace leakage | `GlobalExceptionMiddleware` maps all exceptions to OAuth error format |
| Scope escalation | Validated against `client.AllowedScopes` before code is issued |

## PKCE S256 Implementation

```
Client side:
  code_verifier  = 32 random bytes → base64url (43 chars, no padding)
  code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))

Authorization request:  send code_challenge
Token request:          send code_verifier

Server validation:
  computed = BASE64URL(SHA256(ASCII(code_verifier)))
  assert CryptographicOperations.FixedTimeEquals(computed, stored_challenge)
```

`FixedTimeEquals` is used for the comparison to prevent timing side-channel attacks.

## RSA Key Management (Phase 1 vs Production)

| Environment | Key Storage |
|---|---|
| Phase 1 (local dev) | `RSA.Create(2048)` — in-memory, ephemeral |
| Production (Phase 5) | AWS KMS / Secrets Manager — private key never in memory |

The `ISigningKeyProvider` abstraction means the production implementation is a drop-in replacement for the in-memory one — no handler or service code changes required.

## CQRS Rationale

OAuth has a natural command/query boundary:

- **Commands** (state-changing): `AuthorizeUserCommand`, `ExchangeAuthorizationCodeCommand`
- **Queries** (read-only): `GetJwksQuery`, `GetOpenIdConfigurationQuery`

MediatR's pipeline behaviors provide a clean extension point for cross-cutting concerns (validation today; audit logging, rate limiting in future phases) without coupling them to individual handlers.

## In-Memory Store Notes

All stores are registered as singletons and use `ConcurrentDictionary` for thread safety within a single process. They are **not** suitable for multi-instance or production deployments. Phase 5 will replace them with Supabase-backed implementations behind the same interfaces.
