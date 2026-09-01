# Phase 2 — Protected Identity & Trusted Data API

> **⚠️ Educational POC Disclaimer**
>
> This is an independent educational Proof of Concept. All users and identity data are entirely fictional test data. This project exists solely to demonstrate secure software engineering patterns using C# and .NET 10. It is not affiliated with any organisation and is not intended for production use.

---

## Architecture Overview

Phase 2 adds a **Resource Server** (`IdentityData.Api`) that consumes JWT access tokens issued by the Phase 1 Identity Provider and serves protected identity data from a Supabase-hosted PostgreSQL database.

```mermaid
flowchart TD
    Client[Browser / API Client]

    subgraph IdP[Identity Provider API — port 7001]
        AuthZ[/oauth/authorize]
        Token[/oauth/token]
        Jwks[/.well-known/jwks.json]
    end

    subgraph RS[IdentityData.Api — port 7100]
        JwkStore[JwkKeyStore singleton]
        JwkStartup[JwkStartupService]
        Profile[GET /api/profile]
        Identity[GET /api/identity]
        DB[(Supabase PostgreSQL)]
    end

    Client -- Authorization Code + PKCE --> AuthZ
    AuthZ -- 302 code --> Client
    Client -- POST code + verifier --> Token
    Token -- RS256 JWT --> Client

    JwkStartup -- fetch public key on startup --> Jwks
    JwkStartup -- store in memory --> JwkStore

    Client -- Bearer JWT --> Profile
    Client -- Bearer JWT --> Identity
    Profile -- validate via JwkStore --> JwkStore
    Identity -- validate via JwkStore --> JwkStore
    Profile -- EF Core query --> DB
    Identity -- EF Core query --> DB
```

---

## JWT Validation Flow

When a request arrives at `IdentityData.Api` with a `Bearer` token, ASP.NET Core's JWT Bearer middleware validates the token before the controller is invoked.

| Check | Detail |
|---|---|
| **Signature** | Verified against the RSA public key fetched from the JWK endpoint |
| **Algorithm** | RS256 only — HS256 and `none` are explicitly rejected |
| **Issuer** | Must match `IdentityProvider:Issuer` in configuration |
| **Audience** | Must match `Jwt:Audience` in configuration (`secure-identity-data-api`) |
| **Expiry** | Token must not be expired |
| **ClockSkew** | Set to `TimeSpan.Zero` — no grace period, zero tolerance on expired tokens |

The **private key never leaves the Identity Provider**. The Resource Server only ever holds the public key components (`n`, `e`) retrieved from the JWKS endpoint.

---

## JWK Retrieval

The Resource Server does not receive the public key out-of-band. Instead, it fetches it automatically at startup:

1. **`JwkStartupService`** — a hosted background service (`IHostedService`) that runs once at application start.
2. It calls `HttpClient.GetFromJsonAsync` against the configured `IdentityProvider:JwksUri` (e.g., `https://localhost:7001/.well-known/jwks.json`).
3. The retrieved RSA key parameters are stored in the **`JwkKeyStore`** singleton, which exposes an `RsaSecurityKey` to the JWT Bearer middleware.
4. **To refresh keys** (e.g., after an IdP restart that generates a new ephemeral key pair), restart the Resource Server. Phase 5 will add periodic key refresh.

> The `JwkKeyStore` is registered as a singleton and holds the key in memory. The JWT Bearer `TokenValidationParameters.IssuerSigningKey` resolves from this store at validation time.

---

## OAuth Scopes

| Scope | Description | Required by |
|---|---|---|
| `openid` | OpenID Connect scope | OAuth 2.1 flow |
| `profile` | Basic profile access | OAuth 2.1 flow |
| `identity.read` | Identity data access | `GET /api/profile`, `GET /api/identity` |

Scope enforcement uses ASP.NET Core Authorization Policies. A request that presents a valid JWT but lacks the `identity.read` scope receives **403 Forbidden** — it has been authenticated but is not authorised.

---

## Protected Endpoints

### `GET /api/profile`

Returns the authenticated user's profile data. The user is identified from the `sub` claim in the JWT — the caller cannot specify an arbitrary user ID.

**Required scope:** `identity.read`

**Request:**

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://localhost:7100/api/profile
```

**Response — 200 OK:**

```json
{
  "subject": "user-001",
  "name": "Demo User",
  "email": "demo@example.test",
  "dateOfBirth": "1990-01-01"
}
```

**Error Responses:**

| Status | Cause |
|---|---|
| `401 Unauthorized` | Missing or invalid JWT (bad signature, expired, wrong issuer/audience) |
| `403 Forbidden` | Valid JWT but `identity.read` scope not present |
| `404 Not Found` | JWT `sub` claim has no matching user record in the database |

---

### `GET /api/identity`

Returns extended identity attributes for the authenticated user.

**Required scope:** `identity.read`

**Request:**

```bash
curl -H "Authorization: Bearer <access_token>" \
  https://localhost:7100/api/identity
```

**Response — 200 OK:**

```json
{
  "subject": "user-001",
  "attributes": [
    { "name": "nationality", "value": "GB" },
    { "name": "verificationLevel", "value": "2" }
  ]
}
```

**Error Responses:**

| Status | Cause |
|---|---|
| `401 Unauthorized` | Missing or invalid JWT |
| `403 Forbidden` | Valid JWT but `identity.read` scope not present |
| `404 Not Found` | No user record found for the JWT `sub` claim |

---

## CQRS Query Flow

Each protected endpoint maps to a MediatR Query dispatched from a thin controller:

```
GET /api/profile
    │
    ▼
ProfileController.GetProfile()
    │  dispatches
    ▼
MediatR.Send(GetProfileQuery)
    │
    ├── ValidationBehavior (FluentValidation)
    ▼
GetProfileQueryHandler
    │
    ├── ICurrentUser.Subject          — sub claim from JWT (HttpContext)
    ├── IUserRepository.GetBySubjectAsync(subject)
    │       └── IdentityDataDbContext → PostgreSQL
    ├── user == null → throw NotFoundException → 404
    └── map User → ProfileDto → 200 OK
```

```
GET /api/identity
    │
    ▼
IdentityController.GetIdentity()
    │  dispatches
    ▼
MediatR.Send(GetIdentityQuery)
    │
    ├── ValidationBehavior (FluentValidation)
    ▼
GetIdentityQueryHandler
    │
    ├── ICurrentUser.Subject
    ├── IUserRepository.GetBySubjectWithAttributesAsync(subject)
    │       └── IdentityDataDbContext → PostgreSQL (includes IdentityAttributes)
    ├── user == null → throw NotFoundException → 404
    └── map User + Attributes → IdentityDto → 200 OK
```

`ICurrentUser` is resolved from `IHttpContextAccessor` — the `sub` claim is extracted from the validated JWT claims principal. The handler never reads a user ID from the request body or query string.

---

## PostgreSQL Schema

All tables live in the default `public` schema in a Supabase PostgreSQL database.

### `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key, default `gen_random_uuid()` |
| `subject` | `text` | JWT `sub` value — unique index |
| `name` | `text` | Display name |
| `email` | `text` | Email address |
| `date_of_birth` | `date` | Date of birth |
| `created_at` | `timestamptz` | Set at insert |
| `updated_at` | `timestamptz` | Updated on change |

### `identity_attributes`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key |
| `user_id` | `uuid` | FK → `users.id` |
| `attribute_name` | `text` | e.g., `nationality`, `verificationLevel` |
| `attribute_value` | `text` | Attribute value |
| `created_at` | `timestamptz` | Set at insert |

### `consents`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key |
| `user_id` | `uuid` | FK → `users.id` |
| `client_id` | `text` | OAuth client identifier |
| `scope` | `text` | Granted scope string |
| `granted_at` | `timestamptz` | When consent was given |
| `expires_at` | `timestamptz` | When consent expires (nullable) |

### `audit_logs`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | Primary key |
| `user_id` | `uuid` | FK → `users.id` (nullable — pre-auth events) |
| `event_type` | `text` | e.g., `ProfileAccessed`, `UnauthorizedRequest` |
| `resource` | `text` | e.g., `/api/profile` |
| `created_at` | `timestamptz` | Event timestamp |

---

## Authentication vs. Authorization

These are distinct steps that happen in sequence on every protected request:

**Authentication** — *Who is the caller?*

The JWT Bearer middleware validates the token: signature, issuer, audience, expiry, algorithm. If any check fails, the request is rejected with `401 Unauthorized` before it reaches the controller. On success, the claims principal is populated from the token payload.

**Authorization** — *Can the caller access this resource?*

After authentication, ASP.NET Core evaluates the `RequireScope("identity.read")` policy on the endpoint. If the validated token does not contain the required scope, the request is rejected with `403 Forbidden`. A 403 means the caller is known but not permitted — the token is valid, just under-scoped.

---

## Audit Logging

Every request to a protected endpoint writes an audit record to the `audit_logs` table, regardless of success or failure.

### Events

| Event | Trigger |
|---|---|
| `ProfileAccessed` | Successful `GET /api/profile` |
| `IdentityAccessed` | Successful `GET /api/identity` |
| `UnauthorizedRequest` | 401 — JWT missing or invalid |
| `ForbiddenRequest` | 403 — valid JWT, insufficient scope |

### What IS logged

- `EventType` — the event name
- `Resource` — the endpoint path
- `UserId` — the database user ID (when resolved; null for pre-auth events)
- `CreatedAt` — UTC timestamp

### What is NEVER logged

- Access token values
- RSA keys or key material
- Database connection strings
- Any credential or secret

---

## Local Setup

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- A Supabase project (free tier is sufficient) with a PostgreSQL connection string

### 1. Configure `appsettings.Development.json`

In `src/IdentityData.Api/appsettings.Development.json`, set the PostgreSQL connection string and Identity Provider URLs:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=<host>;Database=<db>;Username=<user>;Password=<password>;SSL Mode=Require"
  },
  "IdentityProvider": {
    "Issuer": "https://localhost:7001",
    "JwksUri": "https://localhost:7001/.well-known/jwks.json"
  },
  "Jwt": {
    "Audience": "secure-identity-data-api"
  }
}
```

### 2. Apply EF Core Migrations

```bash
# Create the initial migration (only needed once, already committed)
dotnet ef migrations add Initial --project src/IdentityData.Api

# Apply migration to the database
dotnet ef database update --project src/IdentityData.Api
```

### 3. Start Both Services

```bash
# Terminal 1 — Identity Provider (issues JWTs and serves JWKS)
dotnet run --project src/IdentityProvider.Api

# Terminal 2 — Identity Data API (validates JWTs and serves protected data)
dotnet run --project src/IdentityData.Api
```

### 4. Open Swagger

```
https://localhost:7100/swagger
```

Use the Swagger UI to obtain a token via the Identity Provider, then click **Authorize** and paste the `Bearer <token>` value to call the protected endpoints.

---

## Testing

```bash
# Phase 2 unit tests
dotnet test tests/IdentityData.UnitTests

# Phase 2 integration tests (requires no external DB — uses in-memory test doubles)
dotnet test tests/IdentityData.IntegrationTests

# All tests (Phase 1 + Phase 2)
dotnet test SecureIdentityData.slnx
```

Integration tests use `WebApplicationFactory<Program>` with an in-memory EF Core provider and a stub `JwkKeyStore` seeded with a test RSA key pair — no network calls or real database required.

---

## Docker Usage

The `IdentityData.Api` Dockerfile produces a minimal runtime image running as a non-root user.

```bash
# Build
docker build -f src/IdentityData.Api/Dockerfile -t identity-data-api .

# Run
docker run -p 8080:8080 \
  -e IdentityProvider__Issuer=https://your-idp-host \
  -e IdentityProvider__JwksUri=https://your-idp-host/.well-known/jwks.json \
  -e Jwt__Audience=secure-identity-data-api \
  -e ConnectionStrings__DefaultConnection="Host=...;Database=...;Username=...;Password=..." \
  identity-data-api
```

Environment variables use the ASP.NET Core double-underscore (`__`) convention to represent nested configuration keys.

---

## Security Considerations

| Control | Detail |
|---|---|
| **RS256 only** | `ValidAlgorithms = ["RS256"]` — HS256 and `none` are rejected at middleware level |
| **ClockSkew = Zero** | `TokenValidationParameters.ClockSkew = TimeSpan.Zero` — no grace period on expired tokens |
| **Subject from JWT only** | `ICurrentUser.Subject` reads from the validated claims principal — the caller cannot specify an arbitrary user ID in the request |
| **CORS locked** | Restricted to `https://localhost:3000` in development; configurable per environment |
| **No token logging** | Access token values are never written to logs, audit tables, or error responses |
| **Parameterized queries** | EF Core uses parameterized SQL for all database operations — no string-interpolated queries |
| **Non-root Docker user** | The container runs as a dedicated non-root `appuser` — `USER appuser` in the Dockerfile |
| **Private key isolation** | The RSA private key never leaves the Identity Provider process — the Resource Server only holds public key material |
