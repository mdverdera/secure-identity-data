# Phase 3 — DPoP Sender-Constrained Access Tokens: Implementation Plan

## Top-Level Overview

Phase 1 delivered a functioning OAuth 2.1 Authorization Server (`IdentityProvider.Api`) with
Authorization Code + PKCE, RS256 JWT issuance, JWK/discovery endpoints, and a full test suite.

**Phase 2 (`IdentityData.Api`) has not yet been implemented.** Only an empty directory skeleton
exists at `src/IdentityData.Api/Domain/ValueObjects/`. Phase 2 is a prerequisite for Phase 3,
so it must be built first as **Sub-Task 1** of this plan.

Phase 3 then upgrades the bearer-token flow into a DPoP sender-constrained flow (RFC 9449),
requiring changes to both projects and the addition of four test projects.

### Key Findings from Code Research

- **Runtime**: .NET 10, C# 13
- **Identity Provider packages**: `System.IdentityModel.Tokens.Jwt` 8.9.0, `Microsoft.IdentityModel.Tokens` 8.9.0, `MediatR` 12.5.0, `FluentValidation` 11.11.0
- **JWT issuance**: `JwtService` issues RS256 tokens via `RsaSigningKeyProvider`; `TokenModels` record `TokenResult` has `TokenType = "Bearer"` default
- **Token endpoint**: `TokenController` reads `grant_type`, `code`, `redirect_uri`, `client_id`, `code_verifier` from form body; returns `TokenResponse` DTO
- **Discovery**: `GetOpenIdConfigurationQueryHandler` builds the discovery doc — needs `dpop_signing_alg_values_supported` added
- **No Docker/Compose files present** — must be added as part of this plan
- **Test projects for Phase 2 exist as empty directories** — `.csproj` files must be created

---

## Sub-Task 1 — Build IdentityData.Api (Phase 2 Foundation)

**Status:** `[ ] pending`

### Intent
Phase 2 is a prerequisite for Phase 3. Without a working Resource Server, DPoP validation
cannot be demonstrated end-to-end. This sub-task builds the minimum Phase 2 Resource Server
that Phase 3 will then extend with DPoP.

### Expected Outcomes
- `src/IdentityData.Api/` is a fully functional ASP.NET Core Web API project
- JWT Bearer authentication validates tokens issued by `IdentityProvider.Api`
- Two protected endpoints: `GET /api/profile`, `GET /api/identity`
- Scope authorization enforcing `identity.read`
- CQRS with MediatR: `GetProfileQuery`, `GetIdentityAttributesQuery`
- Entity Framework Core + PostgreSQL (Supabase) for identity data
- Audit logging
- Swagger functional
- Docker support (Dockerfile + docker-compose.yml at root)
- `.csproj` files created for `IdentityData.UnitTests` and `IdentityData.IntegrationTests`
- Solution file `SecureIdentityData.slnx` updated to include all new projects

### Todo List
1. Create `src/IdentityData.Api/IdentityData.Api.csproj` with required NuGet packages
2. Create `src/IdentityData.Api/Program.cs` — Serilog, EF Core, JWT Bearer auth, Swagger
3. Create `src/IdentityData.Api/appsettings.json` and `appsettings.Development.json`
4. Create `Domain/Entities/` — `IdentityRecord`, `AuditLog`
5. Create `Domain/ValueObjects/` — `IdentityAttribute`
6. Create `Application/Features/Profile/Queries/GetProfile/` — query + handler + result
7. Create `Application/Features/Identity/Queries/GetIdentityAttributes/` — query + handler + result
8. Create `Infrastructure/Persistence/` — `IdentityDataDbContext`, migrations, seeding
9. Create `Infrastructure/Authentication/` — JWT Bearer options (JWK-based key discovery)
10. Create `Common/Middleware/GlobalExceptionMiddleware.cs`
11. Create `Common/Behaviors/ValidationBehavior.cs`
12. Create `Common/Extensions/ServiceCollectionExtensions.cs`
13. Create `Controllers/ProfileController.cs` and `Controllers/IdentityController.cs`
14. Create `Dockerfile` for `IdentityData.Api`
15. Create `docker-compose.yml` at root (both APIs + PostgreSQL)
16. Create `tests/IdentityData.UnitTests/IdentityData.UnitTests.csproj` and initial unit tests
17. Create `tests/IdentityData.IntegrationTests/IdentityData.IntegrationTests.csproj` and integration tests
18. Update `SecureIdentityData.slnx` to include all new projects
19. Build solution — fix any errors
20. Run all tests — fix any failures

### Relevant Context
- Follow exactly the same Clean Architecture layers as `IdentityProvider.Api`:
  `Domain → Application → Infrastructure → API`
- Follow the same CQRS pattern: MediatR handlers, FluentValidation pipeline behavior
- Follow the same Serilog logging approach — never log tokens
- JWT Bearer config: discover public key from `https://localhost:7001/.well-known/jwks.json`
- Scope: use claim name `scope` matching Phase 1 JWT (`"scope": "openid profile"` or `identity.read`)
- The `InMemoryClientStore` in Phase 1 registers scopes `["openid", "profile"]` — update to
  also include `identity.read`
- For PostgreSQL: use `Npgsql.EntityFrameworkCore.PostgreSQL`; connection string in config
- For the POC, seed fictional identity data for `user-001`

---

## Sub-Task 2 — DPoP Cryptography Library (Shared Utilities)

**Status:** `[ ] pending`

### Intent
DPoP proof generation and JWK thumbprint calculation are needed in multiple places
(IdentityProvider.Api for validation, IdentityData.Api for validation, test helpers for
proof generation). Implement these as clean, well-tested utilities — either as a shared
library project or as parallel implementations in each API. Given the POC scope, parallel
implementations within each project are simpler and avoid a shared-project dependency.

### Expected Outcomes
- EC P-256 key pair generation utility
- Public key → JWK serialization (JSON object with `kty`, `crv`, `x`, `y`)
- JWK thumbprint calculation per RFC 7638 (SHA-256 of canonical JSON members)
- DPoP proof JWT generation (for use in test helpers and demo client)
- All utilities covered by unit tests

### Todo List
1. In `IdentityProvider.Api`, create `Infrastructure/DPoP/IDpopService.cs` (interface)
2. Create `Infrastructure/DPoP/DpopService.cs`:
   - `ValidateDpopProof(string proofJwt, string httpMethod, string httpUri)` — for token endpoint
   - `ExtractPublicJwk(string proofJwt)` → returns public JWK as an object
   - `ComputeJwkThumbprint(JsonWebKey jwk)` → returns Base64URL-encoded SHA-256 thumbprint
3. Create `Infrastructure/DPoP/DpopProofValidator.cs` — standalone validator used by both projects
4. In `IdentityData.Api`, create `Infrastructure/DPoP/IDpopProofValidator.cs` (interface)
5. Create `Infrastructure/DPoP/DpopProofValidator.cs` — validates all RFC 9449 claims
6. Create `Infrastructure/DPoP/IDpopReplayStore.cs`:
   ```
   HasBeenUsedAsync(string jti) → bool
   MarkAsUsedAsync(string jti, DateTimeOffset expiry) → Task
   ```
7. Create `Infrastructure/DPoP/InMemoryDpopReplayStore.cs` (ConcurrentDictionary-backed)
   — note in XML doc: only suitable for single-instance POC; replace with Redis for multi-instance
8. Create `Infrastructure/DPoP/DpopOptions.cs` (strongly-typed config):
   ```
   Enabled: bool
   SigningAlgorithms: string[]  (["ES256"])
   MaximumAgeSeconds: int       (default 300)
   ClockSkewSeconds: int        (default 60)
   ReplayProtectionEnabled: bool
   ```
9. Create unit tests in `IdentityProvider.UnitTests/DPoP/` covering all cryptographic operations
10. Create unit tests in `IdentityData.UnitTests/DPoP/` covering all validation cases

### Relevant Context
- Use `System.Security.Cryptography.ECDsa` (built-in .NET) for P-256 key generation
- Use `Microsoft.IdentityModel.Tokens.JsonWebKey` for JWK representation
- JWK thumbprint (RFC 7638): SHA-256 of `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` 
  with members in lexicographic order, no whitespace; result Base64URL-encoded
- DPoP proof header: `{"typ":"dpop+jwt","alg":"ES256","jwk":{...public JWK...}}`
- DPoP proof claims: `jti` (UUID), `htm` (uppercase HTTP method), `htu` (URI, no fragment/query),
  `iat` (Unix seconds), `ath` (Base64URL of SHA-256 of ASCII access token bytes) when token present
- `typ` must be `dpop+jwt` — reject proofs with `typ: JWT`
- `alg` must be asymmetric — reject `none`, `HS256`, etc.
- The JWK in the header must not be a symmetric key
- `htu` comparison: compare scheme+host+path only; ignore query string and fragment per RFC 9449

---

## Sub-Task 3 — Authorization Server: DPoP Token Endpoint Support

**Status:** `[ ] pending`

### Intent
Update `IdentityProvider.Api` so the token endpoint optionally accepts a `DPoP` header.
When a DPoP proof is present, the issued access token must be bound to the client's public key
via the `cnf.jkt` claim. The existing bearer flow must continue to work (no DPoP header = bearer).

### Expected Outcomes
- `TokenController` reads optional `DPoP` header from the request
- `ExchangeAuthorizationCodeCommand` includes optional `DpopProof` string property
- `ExchangeAuthorizationCodeCommandHandler` calls `IDpopService.ValidateDpopProof()` when proof present
- `JwtService.GenerateAccessToken()` accepts optional `cnf` payload (JWK thumbprint) 
- When DPoP proof is valid: issued JWT contains `cnf: { jkt: "<thumbprint>" }`
- `TokenResult.TokenType` is `"DPoP"` when DPoP-bound, `"Bearer"` otherwise
- `TokenResponse` returns `token_type: "DPoP"` when DPoP-bound
- Discovery document adds `dpop_signing_alg_values_supported: ["ES256"]`
- Existing bearer flow remains functional

### Todo List
1. Add `DpopProof` (nullable string) to `ExchangeAuthorizationCodeCommand`
2. Update `TokenController.Token()` to extract `DPoP` HTTP header and pass to command
3. Update `ExchangeAuthorizationCodeCommandHandler`:
   - After PKCE validation, if `DpopProof` is non-null: call `IDpopService.ValidateDpopProof()`
   - Extract public JWK from proof
   - Compute JWK thumbprint
   - Pass thumbprint to `JwtService.GenerateAccessToken()` as `CnfJkt`
4. Update `TokenRequest` record to include `string? CnfJkt`
5. Update `JwtService.GenerateAccessToken()`:
   - When `CnfJkt` is non-null: add `cnf: { jkt: "<thumbprint>" }` claim to JWT payload
   - When `CnfJkt` is non-null: set `TokenType = "DPoP"`
6. Update `TokenResult` / `TokenResponse` to propagate `token_type` correctly
7. Update `GetOpenIdConfigurationQueryHandler` to add `dpop_signing_alg_values_supported: ["ES256"]`
8. Update `OpenIdConfigurationResult` record to include the new field
9. Register `IDpopService` / `DpopService` in `ServiceCollectionExtensions`
10. Add DPoP configuration section to `appsettings.json`:
    ```json
    "Dpop": {
      "Enabled": true,
      "SigningAlgorithms": ["ES256"],
      "MaximumAgeSeconds": 300,
      "ClockSkewSeconds": 60,
      "ReplayProtectionEnabled": true
    }
    ```
11. Update `IdentityProvider.UnitTests` — add tests for DPoP token issuance
12. Update `IdentityProvider.IntegrationTests` — add DPoP token endpoint integration test
13. Build and run tests — fix errors

### Relevant Context
- `TokenController.cs`: currently `[FromForm]` parameters; DPoP proof is an HTTP header, not a form field
- Use `Request.Headers["DPoP"]` to read the proof header in the controller
- `ExchangeAuthorizationCodeCommandHandler.cs` L95-105: JWT issuance block — this is where `CnfJkt` is injected
- `JwtService.cs` L40-54: claims list — add `cnf` as a JSON object claim
- `cnf` claim value: serialize `{ "jkt": "<thumbprint>" }` as a JSON string claim using `ClaimValueTypes.Json`
- `TokenModels.cs`: `TokenResult` record with `TokenType = "Bearer"` default — update to accept override
- DPoP proof validation at token endpoint: only validates `typ`, `alg`, `jwk`, `jti`, `htm`, `htu`, `iat`;
  no `ath` at the token endpoint (no access token yet)
- `htm` at token endpoint must equal `"POST"`; `htu` must equal the token endpoint URI

---

## Sub-Task 4 — Resource Server: DPoP Authentication Handler

**Status:** `[ ] pending`

### Intent
Update `IdentityData.Api` to support DPoP-authenticated requests alongside the existing
bearer flow. Implement a custom ASP.NET Core `AuthenticationHandler` for the `DPoP` scheme
that validates the full RFC 9449 chain: access token → DPoP proof → key binding → ath.

### Expected Outcomes
- Custom `DpopAuthenticationHandler` registered as ASP.NET Core authentication scheme `"DPoP"`
- Bearer JWT validation continues to work for non-DPoP tokens
- A DPoP-bound token (containing `cnf.jkt`) is rejected when presented as `Bearer`
- A bearer token (no `cnf.jkt`) is rejected when presented as `DPoP`
- Full validation chain per RFC 9449:
  1. Parse `Authorization: DPoP <token>` header
  2. Validate JWT access token (signature, iss, aud, exp, nbf)
  3. Extract `cnf.jkt` from access token
  4. Parse `DPoP: <proof>` header
  5. Validate proof signature using public key in proof header
  6. Validate proof `typ`, `alg`, `jwk`
  7. Validate `htm` matches actual HTTP method
  8. Validate `htu` matches actual request URI (scheme+host+path only)
  9. Validate `iat` within `MaximumAgeSeconds + ClockSkewSeconds`
  10. Validate `jti` not in replay store; mark as used
  11. Validate `ath`: Base64URL(SHA256(access-token-bytes)) == proof.ath
  12. Validate `cnf.jkt` matches thumbprint of proof public key
- Replay store (`InMemoryDpopReplayStore`) used for JTI tracking
- Configuration via `DpopOptions` strongly-typed options
- Safe error responses with `WWW-Authenticate: DPoP` challenges
- Security events logged (no token values logged)
- Existing scope authorization (`identity.read`) continues to work

### Todo List
1. Add NuGet packages to `IdentityData.Api`: `Microsoft.AspNetCore.Authentication.JwtBearer`,
   `Microsoft.IdentityModel.Tokens`, `System.IdentityModel.Tokens.Jwt`
2. Create `Infrastructure/DPoP/DpopOptions.cs` (strongly-typed config)
3. Create `Infrastructure/DPoP/IDpopReplayStore.cs` interface
4. Create `Infrastructure/DPoP/InMemoryDpopReplayStore.cs` with XML doc note about single-instance limitation
5. Create `Infrastructure/DPoP/IDpopProofValidator.cs` interface
6. Create `Infrastructure/DPoP/DpopProofValidator.cs` implementing all RFC 9449 validation steps
7. Create `Infrastructure/Authentication/DpopAuthenticationHandler.cs`:
   - Inherits `AuthenticationHandler<DpopAuthenticationOptions>`
   - Implements `HandleAuthenticateAsync()`
   - Returns `AuthenticateResult.Fail()` with descriptive messages for each failure mode
   - Returns `AuthenticateResult.Success()` with `ClaimsPrincipal` from access token claims
8. Create `Infrastructure/Authentication/DpopAuthenticationOptions.cs`
9. Update `Program.cs` to register both `Bearer` and `DPoP` authentication schemes
10. Create `Common/Extensions/ServiceCollectionExtensions.cs` with DPoP service registrations
11. Update `appsettings.json` with `Dpop` configuration section
12. Update `Controllers/ProfileController.cs` and `Controllers/IdentityController.cs` to
    use `[Authorize(AuthenticationSchemes = "Bearer,DPoP")]`
13. Build and verify — fix errors

### Relevant Context
- ASP.NET Core supports multiple authentication schemes; use `AddAuthentication()` without a
  default scheme, or set default to `Bearer` and add `DPoP` as an additional scheme
- Alternatively: use policy-based selection — check `Authorization` header prefix to choose scheme
- The `DpopAuthenticationHandler` must call `JwtSecurityTokenHandler.ValidateToken()` internally
  to validate the access token before proceeding with DPoP validation
- `cnf.jkt` is stored as a JSON claim in the JWT: parse the `cnf` claim as JSON to extract `jkt`
- JWK public key in DPoP proof header: use `ECDsa.ImportParameters()` to reconstruct from x/y
- For `htu` comparison: use `Uri` class to compare scheme+host+path; ignore query/fragment
- Replay store expiry: set to `proof.iat + MaximumAgeSeconds + ClockSkewSeconds`

---

## Sub-Task 5 — Unit Tests: DPoP Validation

**Status:** `[ ] pending`

### Intent
Provide comprehensive unit test coverage for all DPoP validation logic, including every
failure mode specified in RFC 9449 and the acceptance criteria.

### Expected Outcomes
All tests listed in the acceptance criteria pass:

**DPoP Proof Tests:**
- Valid DPoP proof accepted
- Invalid signature rejected
- Invalid JWK rejected
- Unsupported algorithm rejected
- Missing `jti` rejected
- Missing `htm` rejected
- Missing `htu` rejected
- Missing `iat` rejected
- Invalid `htm` rejected
- Invalid `htu` rejected
- Expired proof rejected
- Future-dated proof rejected
- Replayed `jti` rejected

**Access Token Binding Tests:**
- Valid `cnf.jkt` accepted
- Matching DPoP public key accepted
- Mismatched DPoP public key rejected
- Missing `cnf` rejected
- Missing `jkt` rejected

**Access Token Hash Tests:**
- Correct `ath` accepted
- Incorrect `ath` rejected
- Missing `ath` when required rejected

### Todo List
1. Create `tests/IdentityData.UnitTests/DPoP/DpopProofValidatorTests.cs` — all proof validation cases
2. Create `tests/IdentityData.UnitTests/DPoP/JwkThumbprintTests.cs` — thumbprint determinism and correctness
3. Create `tests/IdentityData.UnitTests/DPoP/DpopReplayStoreTests.cs` — replay detection
4. Create `tests/IdentityData.UnitTests/DPoP/AccessTokenHashTests.cs` — ath calculation
5. Create `tests/IdentityData.UnitTests/DPoP/KeyBindingTests.cs` — cnf.jkt matching
6. Create `tests/IdentityProvider.UnitTests/DPoP/DpopTokenIssuanceTests.cs` — cnf claim in token
7. Create shared test helper `tests/TestHelpers/DpopTestHelper.cs`:
   - `GenerateEcKeyPair()` → ECDsa
   - `CreateDpopProof(ECDsa key, string htm, string htu, string? accessToken = null)` → JWT string
   - `GetPublicJwk(ECDsa key)` → JWK object
   - `ComputeThumbprint(JsonWebKey jwk)` → string
8. Run unit tests — fix failures

### Relevant Context
- `tests/IdentityProvider.UnitTests/` already has test infrastructure with xUnit, FluentAssertions, Moq
- Use the same test package versions: xUnit 2.9.3, FluentAssertions 8.4.0, Moq 4.20.72
- For `DpopTestHelper`: use `ECDsa.Create(ECCurve.NamedCurves.nistP256)` for P-256 key generation
- Test helper should produce both valid proofs and intentionally malformed proofs (for failure cases)

---

## Sub-Task 6 — Integration Tests: HTTP-Level DPoP Validation

**Status:** `[ ] pending`

### Intent
Provide end-to-end integration tests at the HTTP level, covering the complete DPoP flow
and all failure scenarios that require the full request pipeline.

### Expected Outcomes
All HTTP-level tests from the acceptance criteria pass:

**HTTP Tests:**
- Valid GET + valid DPoP proof → 200
- Valid POST + valid DPoP proof → 200
- DPoP proof for GET but used for POST → 401
- DPoP proof for `/api/profile` but used for `/api/identity` → 401
- Reused DPoP proof → 401
- DPoP-bound token presented as Bearer → 401
- Valid DPoP token with insufficient scope → 403
- Fully valid DPoP request → 200 with identity data

**End-to-End Test:**
Complete flow from key generation through token issuance to protected resource access.

**Token Replay Demonstration:**
Attacker with only the access token (no private key) cannot access the resource.

### Todo List
1. Create `tests/IdentityData.IntegrationTests/Helpers/IdentityDataFactory.cs`
   (`WebApplicationFactory<Program>`) for hosting `IdentityData.Api` in-process
2. Create `tests/IdentityData.IntegrationTests/Helpers/IdentityProviderFactory.cs`
   for hosting `IdentityProvider.Api` in-process (reuse/adapt from existing)
3. Create `tests/IdentityData.IntegrationTests/DPoP/DpopHttpValidationTests.cs`:
   - All HTTP-level failure and success cases
4. Create `tests/IdentityData.IntegrationTests/DPoP/DpopEndToEndTests.cs`:
   - Complete authorization code + PKCE + DPoP flow
   - Token replay attack demonstration test
5. Create `tests/IdentityProvider.IntegrationTests/DPoP/DpopTokenEndpointTests.cs`:
   - Token endpoint with DPoP proof → DPoP-bound token returned
   - Token endpoint without DPoP proof → Bearer token returned
   - Token endpoint with invalid DPoP proof → 400
6. Run integration tests — fix failures

### Relevant Context
- For the end-to-end test, both APIs need to run in-process simultaneously
- The end-to-end test must use the JWKS from `IdentityProvider.Api` to verify tokens
- `WebApplicationFactory` allows overriding services — use to inject test doubles where needed
- For the replay test: capture the DPoP proof JWT, make a successful request, then reuse the same proof

---

## Sub-Task 7 — Docker and Configuration

**Status:** `[ ] pending`

### Intent
Add Docker support for both APIs so the full stack can be run locally with a single command,
and ensure all configuration is properly externalized.

### Expected Outcomes
- `src/IdentityProvider.Api/Dockerfile` present and builds successfully
- `src/IdentityData.Api/Dockerfile` present and builds successfully
- `docker-compose.yml` at root orchestrates both APIs + PostgreSQL
- All DPoP options in `appsettings.json` files (not hardcoded)
- Environment variable overrides documented
- `docker-compose.yml` uses environment variables for database credentials (no secrets committed)

### Todo List
1. Create `src/IdentityProvider.Api/Dockerfile` (multi-stage: SDK build + runtime image)
2. Create `src/IdentityData.Api/Dockerfile` (multi-stage)
3. Create `docker-compose.yml` at root:
   - `identityprovider` service (port 7001)
   - `identitydata` service (port 7100)
   - `postgres` service (Supabase-compatible PostgreSQL 15+)
4. Create `.env.example` documenting required environment variables
5. Verify `docker-compose build` succeeds
6. Verify `docker-compose up` starts all services

### Relevant Context
- Both APIs target `net10.0` — use `mcr.microsoft.com/dotnet/aspnet:10.0` runtime image
- PostgreSQL connection string must be injected via environment variable
- The `IdentityData.Api` must know the `IdentityProvider.Api` JWKS URI for JWT validation —
  this changes between local dev (`https://localhost:7001`) and Docker (`http://identityprovider:80`)

---

## Sub-Task 8 — Documentation

**Status:** `[ ] pending`

### Intent
Produce accurate, educational documentation explaining DPoP concepts, the implementation
decisions, security properties, and how to run the demo.

### Expected Outcomes
- `docs/phase-3.md` — comprehensive Phase 3 documentation
- `README.md` updated to reflect Phase 3
- All DPoP concepts explained: proof structure, key binding, ath, htm, htu, replay protection
- Mermaid architecture diagram included in documentation (in `docs/phase-3.md` and README)
- Security limitations section (DPoP improves replay protection; does not replace HTTPS)
- Local setup instructions
- Bearer vs DPoP comparison section

### Todo List
1. Create `docs/phase-3.md` covering all topics in the spec
2. Update `README.md`:
   - Add Phase 3 to the overview table
   - Add Phase 3 to the Mermaid architecture diagram
   - Add Bearer vs DPoP comparison
   - Update local setup instructions
3. Review documentation for accuracy against the implementation

### Relevant Context
- Existing `docs/architecture.md` covers Phase 1; Phase 3 docs should complement it
- The Mermaid diagram provided in the spec is a good starting point for `phase-3.md`
- Security limitations to document:
  - In-memory replay store is not suitable for multi-instance deployment
  - DPoP does not protect against XSS token theft if the private key is also compromised
  - HTTPS is still required; DPoP protects against token forwarding, not network interception
  - Phase 1 RSA key is ephemeral (in-memory) — not suitable for production

---

## NuGet Packages Required

### IdentityProvider.Api (additions)
| Package | Purpose |
|---------|---------|
| No new packages needed | DPoP proof validation uses existing `Microsoft.IdentityModel.Tokens` and `System.Security.Cryptography` (built-in) |

### IdentityData.Api (new project)
| Package | Version | Purpose |
|---------|---------|---------|
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 10.0.x | JWT Bearer scheme |
| `Microsoft.IdentityModel.Tokens` | 8.9.0 | JWT/JWK operations |
| `System.IdentityModel.Tokens.Jwt` | 8.9.0 | JWT handler |
| `Npgsql.EntityFrameworkCore.PostgreSQL` | 9.x | PostgreSQL via EF Core |
| `Microsoft.EntityFrameworkCore.Design` | 9.x | EF Core tooling |
| `MediatR` | 12.5.0 | CQRS |
| `FluentValidation` | 11.11.0 | Request validation |
| `FluentValidation.AspNetCore` | 11.3.0 | ASP.NET Core integration |
| `Serilog.AspNetCore` | 9.0.0 | Structured logging |
| `Serilog.Sinks.Console` | 6.0.0 | Console sink |
| `Swashbuckle.AspNetCore` | 7.3.1 | Swagger |

### Test Projects
| Package | Version | Purpose |
|---------|---------|---------|
| `xunit` | 2.9.3 | Test framework |
| `FluentAssertions` | 8.4.0 | Assertions |
| `Moq` | 4.20.72 | Mocking |
| `Microsoft.AspNetCore.Mvc.Testing` | 10.0.x | Integration test host |
| `Microsoft.NET.Test.Sdk` | 17.14.1 | Test runner |
| `coverlet.collector` | 6.0.4 | Coverage |

---

## DPoP Cryptography Approach

### Key Pair
```
ECDsa.Create(ECCurve.NamedCurves.nistP256)
```
Built-in .NET — no extra packages.

### JWK Representation
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "<base64url-encoded X coordinate>",
  "y": "<base64url-encoded Y coordinate>"
}
```

### JWK Thumbprint (RFC 7638)
```
1. Construct canonical JSON (lexicographic key order, no whitespace):
   {"crv":"P-256","kty":"EC","x":"...","y":"..."}
2. UTF-8 encode
3. SHA-256 hash
4. Base64URL-encode
```
Use `Microsoft.IdentityModel.Tokens.JsonWebKey` with `ComputeJwkThumbprint()` if available,
or implement manually as above.

### DPoP Proof JWT Structure
```
Header:
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}

Payload:
{
  "jti": "<uuid>",
  "htm": "GET",            // uppercase HTTP method
  "htu": "https://...",   // URI without query/fragment
  "iat": 1700000000,      // Unix seconds
  "ath": "<base64url>"    // only when access token is present
}

Signature: ES256(header.payload, privateKey)
```

---

## ASP.NET Core Authentication Integration Design

```
AddAuthentication()
  .AddJwtBearer("Bearer", options => { ... })   // Phase 2 bearer flow
  .AddScheme<DpopAuthenticationOptions, DpopAuthenticationHandler>("DPoP", options => { ... })

Controllers use:
[Authorize(AuthenticationSchemes = "Bearer,DPoP")]
```

The `DpopAuthenticationHandler` reads:
- `Authorization: DPoP <access-token>`
- `DPoP: <proof-jwt>`

It validates the full chain and returns a `ClaimsPrincipal` on success.

A policy or middleware can enforce that DPoP-bound tokens (`cnf.jkt` present) are not
accepted via the `Bearer` scheme — this is part of the `Bearer` JWT validation options.

---

## CQRS Impact

DPoP validation belongs entirely in the authentication pipeline, not in any query handler.
The query handlers (`GetProfileQueryHandler`, `GetIdentityAttributesQueryHandler`) see only
an already-authenticated `ClaimsPrincipal` and must not be modified for DPoP concerns.

The intended pipeline is:
```
HTTP Request
     │
     ▼
DpopAuthenticationHandler (or JwtBearerHandler)
     │
     ▼
Authorization Middleware (scope check)
     │
     ▼
Controller Action
     │
     ▼
MediatR → ValidationBehavior → QueryHandler
     │
     ▼
EF Core → PostgreSQL
```

---

## Replay Protection Design

```csharp
public interface IDpopReplayStore
{
    Task<bool> HasBeenUsedAsync(string jti, CancellationToken ct = default);
    Task MarkAsUsedAsync(string jti, DateTimeOffset expiry, CancellationToken ct = default);
}
```

`InMemoryDpopReplayStore` uses `ConcurrentDictionary<string, DateTimeOffset>`.
On `HasBeenUsedAsync`: also prune entries whose `expiry` is in the past (lazy cleanup).
On `MarkAsUsedAsync`: store `jti → expiry`.

> **Note:** The in-memory store is only suitable for a single-instance POC.
> For multi-instance deployment, replace with a distributed store (Redis, PostgreSQL).
> The `IDpopReplayStore` abstraction is designed to be swappable without changing the validator.

---

## Phase 2 Compatibility Impact

- Existing bearer token flow: unaffected. `ExchangeAuthorizationCodeCommand` without DPoP
  header continues to issue `token_type: "Bearer"` tokens.
- New DPoP flow: opt-in. Client sends `DPoP` header → receives `token_type: "DPoP"` token.
- Resource Server: supports both `Bearer` and `DPoP` authorization schemes.
- DPoP-bound tokens (with `cnf.jkt`) are explicitly rejected by the `Bearer` handler to
  enforce correct scheme usage.
- All Phase 1 endpoints remain unchanged.
- All Phase 2 endpoints (`GET /api/profile`, `GET /api/identity`) accept both schemes.
- The `identity.read` scope is required for both flows.

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Token replay (stolen access token) | DPoP binds token to client's public key via `cnf.jkt` |
| Proof replay (stolen DPoP proof) | `jti` replay store prevents reuse |
| Proof transplanting to different endpoint | `htu` validation prevents cross-endpoint reuse |
| Proof transplanting to different method | `htm` validation prevents method mismatch |
| Clock skew | Configurable `ClockSkewSeconds` tolerance |
| Proof expiry | `MaximumAgeSeconds` limits proof window |
| Access token mispairing | `ath` claim binds proof to specific access token |
| Key mismatch | `cnf.jkt` vs proof key thumbprint comparison |
| DPoP as sole authentication | Rejected — access token always required alongside proof |
| Private key exposure | Never serialized, never logged, never transmitted |
| Stack trace leakage | `GlobalExceptionMiddleware` in both projects |
| Sensitive value logging | All log statements checked — tokens/keys never logged |
| DPoP limitations | Documented: does not replace HTTPS; does not protect against XSS key theft |
