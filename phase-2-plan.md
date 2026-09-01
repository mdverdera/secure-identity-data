# Phase 2 — Protected Identity & Trusted Data API — Implementation Plan

## Top-Level Overview

Build `IdentityData.Api`, a standalone ASP.NET Core 10 Resource Server that:

- Validates JWT access tokens issued by `IdentityProvider.Api` (Phase 1)
- Fetches the IdentityProvider's public signing key from its JWK endpoint at startup and periodically refreshes it
- Enforces `identity.read` scope on protected endpoints
- Reads fictional user data from a Supabase PostgreSQL database via EF Core
- Exposes two protected endpoints: `GET /api/profile` and `GET /api/identity`
- Records lightweight audit events
- Ships with a Dockerfile
- Is covered by unit and integration tests

Phase 1 (`IdentityProvider.Api`) will receive **one small compatibility change**: the OAuth client's `AllowedScopes` list must be extended to include `identity.read` so the demo client can request the new scope.

---

## Phase 1 Compatibility Change

**Intent:** Extend the demo client's allowed scopes so tokens bearing `identity.read` can be issued.

**Expected Outcomes:**
- `InMemoryClientStore` allows `identity.read` scope
- Existing Phase 1 tests remain green
- `scopes_supported` in the discovery response includes `identity.read`

**Todo List:**
1. In `InMemoryClientStore.cs`, add `"identity.read"` to the `AllowedScopes` list for `secure-demo-client`
2. In `GetOpenIdConfigurationQueryHandler.cs`, add `"identity.read"` to `scopes_supported`
3. Run Phase 1 unit and integration tests to confirm nothing broke

**Relevant Context:**
- `src/IdentityProvider.Api/Infrastructure/Persistence/InMemoryClientStore.cs`
- `src/IdentityProvider.Api/Features/Discovery/Queries/GetOpenIdConfiguration/GetOpenIdConfigurationQueryHandler.cs`

**Status:** `[ ] pending`

---

## Sub-Task 1 — Solution & Project Scaffolding

**Intent:** Create the three new projects, register them in the solution file, and establish the directory skeleton so subsequent sub-tasks have a real target.

**Expected Outcomes:**
- `src/IdentityData.Api/IdentityData.Api.csproj` exists and targets `.NET 10`
- `tests/IdentityData.UnitTests/IdentityData.UnitTests.csproj` exists
- `tests/IdentityData.IntegrationTests/IdentityData.IntegrationTests.csproj` exists
- All three projects listed in `SecureIdentityData.slnx`
- `dotnet build` succeeds (empty projects)

**Todo List:**
1. Create `src/IdentityData.Api/IdentityData.Api.csproj` with the following NuGet packages:
   - `MediatR` 12.5.0
   - `FluentValidation.AspNetCore` 11.3.0
   - `Microsoft.AspNetCore.Authentication.JwtBearer` (net10)
   - `Microsoft.EntityFrameworkCore` (net10)
   - `Npgsql.EntityFrameworkCore.PostgreSQL` (latest stable for EF Core 9/10)
   - `Microsoft.IdentityModel.Protocols.OpenIdConnect` — for JWKS fetching
   - `Swashbuckle.AspNetCore` 7.x
   - `Serilog.AspNetCore` 9.x
   - `Serilog.Sinks.Console` 6.x
2. Create `tests/IdentityData.UnitTests/IdentityData.UnitTests.csproj` with xUnit, FluentAssertions, Moq
3. Create `tests/IdentityData.IntegrationTests/IdentityData.IntegrationTests.csproj` with xUnit, FluentAssertions, `Microsoft.AspNetCore.Mvc.Testing`
4. Add all three project references to `SecureIdentityData.slnx`
5. Create the top-level `Program.cs` placeholder (empty `WebApplication.CreateBuilder` with no middleware yet)
6. Create directory skeleton:
   ```
   Features/Profile/Queries/GetProfile/
   Features/Identity/Queries/GetIdentityAttributes/
   Domain/Entities/
   Domain/ValueObjects/
   Domain/Exceptions/
   Infrastructure/Authentication/
   Infrastructure/Persistence/DbContext/
   Infrastructure/Persistence/Configurations/
   Infrastructure/Persistence/Repositories/
   Infrastructure/Services/
   Common/Behaviors/
   Common/Authorization/
   Common/Extensions/
   ```
7. Verify `dotnet build SecureIdentityData.slnx` succeeds

**Status:** `[ ] pending`

---

## Sub-Task 2 — Domain Layer

**Intent:** Define the domain entities, value objects, and exceptions that model the identity data bounded context. No infrastructure or EF Core concerns here.

**Expected Outcomes:**
- `User`, `IdentityAttribute`, `Consent`, `AuditLog` entities exist as plain C# classes
- An `ApplicationException`-derived `IdentityDataException` exists for domain-level errors
- No EF Core or ASP.NET Core references in `Domain/`

**Todo List:**
1. Create `Domain/Entities/User.cs`:
   ```
   Id (Guid), Subject (string), Name (string), Email (string),
   DateOfBirth (DateOnly), CreatedAt (DateTimeOffset), UpdatedAt (DateTimeOffset)
   Navigation: ICollection<IdentityAttribute> Attributes
   ```
2. Create `Domain/Entities/IdentityAttribute.cs`:
   ```
   Id (Guid), UserId (Guid), AttributeName (string), AttributeValue (string),
   CreatedAt (DateTimeOffset)
   Navigation: User User
   ```
3. Create `Domain/Entities/Consent.cs`:
   ```
   Id (Guid), UserId (Guid), ClientId (string), Scope (string),
   GrantedAt (DateTimeOffset), ExpiresAt (DateTimeOffset?)
   Navigation: User User
   ```
4. Create `Domain/Entities/AuditLog.cs`:
   ```
   Id (Guid), UserId (Guid?), EventType (string), Resource (string),
   CreatedAt (DateTimeOffset)
   ```
5. Create `Domain/Exceptions/IdentityDataException.cs` — base domain exception
6. Create `Domain/Exceptions/UserNotFoundException.cs` — thrown when subject has no record

**Status:** `[ ] pending`

---

## Sub-Task 3 — EF Core & PostgreSQL Persistence

**Intent:** Set up EF Core with the Npgsql provider, define all entity configurations, create the `IdentityDataDbContext`, write the initial migration, and provide a repository pattern for use by CQRS handlers.

**Expected Outcomes:**
- `IdentityDataDbContext` compiles and maps all four tables
- Initial EF Core migration exists in `Infrastructure/Persistence/Migrations/`
- `IUserRepository` / `UserRepository` compile
- `dotnet ef migrations add Initial` can be run (documented, not run by CI)
- Connection string is consumed from `ConnectionStrings:DefaultConnection` via options pattern

**Todo List:**
1. Create `Infrastructure/Persistence/DbContext/IdentityDataDbContext.cs` with `DbSet<User>`, `DbSet<IdentityAttribute>`, `DbSet<Consent>`, `DbSet<AuditLog>`
2. Create EF Core Fluent API configurations in `Infrastructure/Persistence/Configurations/`:
   - `UserConfiguration.cs` — table `users`, columns snake_case, indexes on `subject` (unique) and `email`
   - `IdentityAttributeConfiguration.cs` — table `identity_attributes`, FK to users
   - `ConsentConfiguration.cs` — table `consents`, FK to users, composite index on `(user_id, client_id, scope)`
   - `AuditLogConfiguration.cs` — table `audit_logs`, optional FK to users, index on `(user_id, event_type)`
3. Create `Infrastructure/Persistence/Repositories/IUserRepository.cs`:
   ```
   Task<User?> GetBySubjectAsync(string subject, CancellationToken ct)
   Task<IReadOnlyList<IdentityAttribute>> GetAttributesBySubjectAsync(string subject, CancellationToken ct)
   ```
4. Create `Infrastructure/Persistence/Repositories/UserRepository.cs` — EF Core implementation
5. Create `Infrastructure/Persistence/Repositories/IAuditRepository.cs` and `AuditRepository.cs` — `Task AppendAsync(AuditLog entry, CancellationToken ct)`
6. Add `AddDbContext<IdentityDataDbContext>` registration in DI extensions
7. Create initial EF Core migration (run `dotnet ef migrations add Initial --project src/IdentityData.Api`)
8. Create `Infrastructure/Persistence/Seeders/DevelopmentDataSeeder.cs` — seeds one fictional user with subject `user-001` matching Phase 1 demo user

**Schema constraints:**
- All timestamps UTC
- `users.subject` — unique index
- No access tokens or private keys stored in any table

**Status:** `[ ] pending`

---

## Sub-Task 4 — JWT Bearer Authentication & JWK Integration

**Intent:** Configure ASP.NET Core JWT Bearer authentication so `IdentityData.Api` validates every incoming access token against the public RSA key fetched from `IdentityProvider.Api`'s JWK endpoint. The private key never leaves `IdentityProvider.Api`.

**Expected Outcomes:**
- JWT Bearer middleware is registered and active
- A valid RS256 JWT from `IdentityProvider.Api` results in `401 Unauthorized` being rejected (wrong sig, wrong issuer, wrong aud, expired) and `200 OK` on correct tokens
- Configuration is loaded from `IdentityProvider:Authority`, `IdentityProvider:Issuer`, `IdentityProvider:JwksUri`, `Jwt:Audience`

**Todo List:**
1. Create `Infrastructure/Authentication/JwtBearerOptions.cs` strongly-typed options class:
   ```
   IdentityProvider: { Authority, Issuer, JwksUri }
   Jwt: { Audience }
   ```
2. Create `Common/Extensions/AuthenticationExtensions.cs` — extension method `AddJwtBearerAuthentication(IServiceCollection, IConfiguration)` that:
   - Registers `AddAuthentication(JwtBearerDefaults.AuthenticationScheme)`
   - Configures `TokenValidationParameters`:
     - `ValidateIssuer = true`, `ValidIssuer` from config
     - `ValidateAudience = true`, `ValidAudience` from config
     - `ValidateLifetime = true`
     - `ValidateIssuerSigningKey = true`
     - `ValidAlgorithms = ["RS256"]` (reject HS256 and others)
     - `ClockSkew = TimeSpan.Zero`
   - Uses `ConfigurationManager` (OpenIdConnect discovery from `JwksUri`) OR manually fetches JWK via `JsonWebKeySet` to create `JsonWebKeySet` for `IssuerSigningKeys`
   - Registers an `IConfigureOptions<JwtBearerOptions>` that wires up JWK refresh
3. Add `app.UseAuthentication()` and `app.UseAuthorization()` to `Program.cs` in correct order
4. Create `appsettings.json` and `appsettings.Development.json` with correct placeholder values:
   ```json
   {
     "IdentityProvider": {
       "Authority": "https://localhost:7001",
       "Issuer": "https://localhost:7001",
       "JwksUri": "https://localhost:7001/.well-known/jwks.json"
     },
     "Jwt": {
       "Audience": "secure-identity-data-api"
     }
   }
   ```
5. Create `appsettings.example.json` with placeholder values (no real secrets)

**JWK Fetch Strategy (manual fetch — explicit, POC-appropriate):**
- On startup, make a plain `HttpClient` GET to `IdentityProvider:JwksUri`
- Parse the response into a `JsonWebKeySet`
- Extract `JsonWebKey` objects and set them as `TokenValidationParameters.IssuerSigningKeys`
- Log a startup warning (not error) if not reachable — Identity Provider may start separately
- No automatic refresh for this POC (manual restart refreshes key)

**Status:** `[ ] pending`

---

## Sub-Task 5 — Current User Context & Authorization Policies

**Intent:** Centralize access to the authenticated caller's identity via `ICurrentUser`, and define the `IdentityReadPolicy` authorization policy.

**Expected Outcomes:**
- `ICurrentUser` is injectable in CQRS handlers
- `ICurrentUser.Subject`, `ICurrentUser.Scopes`, `ICurrentUser.ClientId` are populated from the validated JWT claims
- `IdentityReadPolicy` requires `identity.read` scope
- Missing scope → `403 Forbidden`; missing token → `401 Unauthorized`

**Todo List:**
1. Create `Common/Authorization/ICurrentUser.cs`:
   ```csharp
   public interface ICurrentUser
   {
       string Subject { get; }
       IReadOnlyList<string> Scopes { get; }
       string? ClientId { get; }
       bool HasScope(string scope);
   }
   ```
2. Create `Infrastructure/Authentication/CurrentUser.cs` — implements `ICurrentUser`, reads claims from `IHttpContextAccessor`
3. Register `ICurrentUser` as `Scoped` in DI (via `IHttpContextAccessor`)
4. Create `Common/Authorization/Policies.cs` — constants for policy names: `IdentityReadPolicy`
5. Create `Common/Extensions/AuthorizationExtensions.cs` — `AddIdentityDataAuthorization(IServiceCollection)`:
   - `AddAuthorization` with `IdentityReadPolicy` policy requiring claim `scope` contains `identity.read`
6. Add `[Authorize(Policy = Policies.IdentityReadPolicy)]` to endpoint controllers
7. Unit test: `CurrentUser` correctly parses `sub`, `scope`, `client_id` from mock claims

**Status:** `[ ] pending`

---

## Sub-Task 6 — CQRS Queries & Handlers

**Intent:** Implement the two application queries that serve the protected endpoints: `GetProfileQuery` and `GetIdentityAttributesQuery`.

**Expected Outcomes:**
- `GetProfileQuery` returns a `ProfileDto` populated from `users` row matching `ICurrentUser.Subject`
- `GetIdentityAttributesQuery` returns an `IdentityAttributesDto` with subject, name, email, dateOfBirth
- Unknown subject → `UserNotFoundException` (translated to 404 in middleware)
- Queries do not directly reference `HttpContext`

**Todo List:**
1. Create `Features/Profile/Models/ProfileDto.cs`:
   ```
   Subject, Name, Email, DateOfBirth (DateOnly)
   ```
2. Create `Features/Profile/Queries/GetProfile/GetProfileQuery.cs` — record with no parameters (subject comes from `ICurrentUser`)
3. Create `Features/Profile/Queries/GetProfile/GetProfileQueryHandler.cs`:
   - Injects `IUserRepository`, `ICurrentUser`, `IAuditRepository`
   - Calls `GetBySubjectAsync(currentUser.Subject)`
   - Throws `UserNotFoundException` if null
   - Appends `AuditLog` with `EventType = "ProfileAccessed"`
   - Returns `ProfileDto`
4. Create `Features/Identity/Models/IdentityAttributesDto.cs`:
   ```
   Subject, Name, Email, DateOfBirth
   ```
5. Create `Features/Identity/Queries/GetIdentityAttributes/GetIdentityAttributesQuery.cs`
6. Create `Features/Identity/Queries/GetIdentityAttributes/GetIdentityAttributesQueryHandler.cs`:
   - Injects `IUserRepository`, `ICurrentUser`, `IAuditRepository`
   - Calls `GetBySubjectAsync(currentUser.Subject)`
   - Appends `AuditLog` with `EventType = "IdentityAccessed"`
   - Returns `IdentityAttributesDto`
7. Unit tests for both handlers using mocked repositories and `ICurrentUser`

**Status:** `[ ] pending`

---

## Sub-Task 7 — Controllers & Endpoints

**Intent:** Wire CQRS queries to thin HTTP controllers that return the correct status codes and delegate all logic to MediatR.

**Expected Outcomes:**
- `GET /api/profile` returns `200 ProfileDto` when token is valid with `identity.read`
- `GET /api/identity` returns `200 IdentityAttributesDto` when token is valid with `identity.read`
- Missing token → `401`, valid token missing scope → `403`, subject not found → `404`

**Todo List:**
1. Create `Controllers/ProfileController.cs`:
   - Route: `[Route("api/profile")]`
   - `[Authorize(Policy = Policies.IdentityReadPolicy)]`
   - `GET` → `await mediator.Send(new GetProfileQuery())`
2. Create `Controllers/IdentityController.cs`:
   - Route: `[Route("api/identity")]`
   - `[Authorize(Policy = Policies.IdentityReadPolicy)]`
   - `GET` → `await mediator.Send(new GetIdentityAttributesQuery())`
3. Create `Common/Middleware/GlobalExceptionMiddleware.cs` (mirror Phase 1 pattern):
   - `UserNotFoundException` → `404`
   - `UnauthorizedAccessException` → `401`
   - All others → `500` with generic message (no stack trace)
4. Ensure `WWW-Authenticate` challenge header is present on `401` responses (ASP.NET Core JWT Bearer does this automatically)

**Status:** `[ ] pending`

---

## Sub-Task 8 — Audit Logging

**Intent:** Record structured audit events for access and unauthorized/forbidden events without logging any token values.

**Expected Outcomes:**
- Each successful `GET /api/profile` creates an `audit_logs` row with `EventType = "ProfileAccessed"`
- Each successful `GET /api/identity` creates an `audit_logs` row with `EventType = "IdentityAccessed"`
- Audit log never contains: access tokens, authorization codes, private keys, connection strings

**Todo List:**
1. Create `Domain/Services/AuditEventTypes.cs` — constants: `ProfileAccessed`, `IdentityAccessed`, `UnauthorizedRequest`, `ForbiddenRequest`
2. Audit log writes are already planned in Sub-Task 6 handlers via `IAuditRepository.AppendAsync`
3. Register `IAuditRepository` / `AuditRepository` in DI
4. Add MediatR pipeline behavior `AuditBehavior` or keep audit writes inside handlers — keep it simple, write directly in handlers

**Status:** `[ ] pending`

---

## Sub-Task 9 — Swagger / OpenAPI Configuration

**Intent:** Document both protected endpoints in Swagger UI with JWT bearer security definition, required scopes, and POC disclaimer.

**Expected Outcomes:**
- Swagger UI shows `Authorize` button with Bearer token input
- `GET /api/profile` and `GET /api/identity` show required scope annotations
- `dotnet run` serves Swagger at `/swagger`

**Todo List:**
1. Configure Swashbuckle with:
   - `SecurityDefinition` for `Bearer` (HTTP scheme, Bearer format, JWT)
   - `SecurityRequirement` applying Bearer to all endpoints
2. Add XML doc comments to controllers with `<remarks>Requires scope: identity.read</remarks>`
3. Add `OperationFilter` to surface scope requirements per endpoint
4. Add POC disclaimer to Swagger info description (same style as Phase 1)

**Status:** `[ ] pending`

---

## Sub-Task 10 — Unit Tests

**Intent:** Cover JWT validation edge cases, `CurrentUser` extraction, and CQRS handler logic without requiring a database or running Identity Provider.

**Expected Outcomes:**
- All tests in `IdentityData.UnitTests` pass
- No real database connection required for unit tests

**Test Classes to Create:**

1. `Authentication/JwtValidationTests.cs`
   - Valid token → authenticated
   - Wrong issuer → `401`
   - Wrong audience → `401`
   - Expired token → `401`
   - Invalid signature (wrong key) → `401`
   - Missing `scope` claim → not authorized for `identity.read`
   - `alg: HS256` token → rejected

2. `Authorization/CurrentUserTests.cs`
   - `Subject` extracted from `sub` claim
   - `Scopes` parsed from space-delimited `scope` claim
   - `HasScope("identity.read")` returns true/false correctly
   - Unauthenticated context → throws or returns empty

3. `Features/GetProfileQueryHandlerTests.cs`
   - User found → returns `ProfileDto`
   - User not found → throws `UserNotFoundException`
   - Audit log appended on success

4. `Features/GetIdentityAttributesQueryHandlerTests.cs`
   - User found → returns `IdentityAttributesDto`
   - Audit appended

**Todo List:**
1. Create test project structure
2. Implement all four test classes above
3. Run `dotnet test tests/IdentityData.UnitTests`

**Status:** `[ ] pending`

---

## Sub-Task 11 — Integration Tests

**Intent:** Test the full HTTP pipeline from token to response, including actual JWT validation middleware, scope enforcement, and (optionally) in-memory database for data retrieval.

**Expected Outcomes:**
- `GET /api/profile` without token → `401`
- `GET /api/profile` with forged/invalid token → `401`
- `GET /api/profile` with expired token → `401`
- `GET /api/profile` with valid token but no `identity.read` scope → `403`
- `GET /api/profile` with valid token + `identity.read` → `200` with ProfileDto
- `GET /api/identity` with valid token + `identity.read` → `200`
- Key integration test: Issue token from `IdentityProvider.Api` WebApplicationFactory → send to `IdentityData.Api` WebApplicationFactory → validate full chain

**Todo List:**
1. Create `IdentityDataFactory.cs` (mirrors `IdentityProviderFactory` from Phase 1):
   - Overrides `ConfigureWebHost` to swap EF Core for `UseInMemoryDatabase` (EF Core InMemory provider — chosen for speed/simplicity)
   - Seeds test user `user-001`
2. Create `Helpers/TokenHelper.cs` that can produce signed test JWTs (reuse Phase 1's `IdentityProviderFactory` pattern, or generate tokens directly with the same RSA test key)
3. Create `ProfileEndpointTests.cs` with all scenarios above
4. Create `IdentityEndpointTests.cs`
5. Create `FullFlowIntegrationTest.cs`:
   - Starts `IdentityProviderFactory` (Phase 1 in-process)
   - Executes PKCE + auth code + token exchange to get a real JWT
   - Sends that JWT to `IdentityDataFactory`
   - Asserts `200` and correct profile data

**Note on test database:** EF Core `UseInMemoryDatabase` (InMemory provider) avoids requiring a real Supabase connection for automated tests. Chosen for speed and simplicity.

**Status:** `[ ] pending`

---

## Sub-Task 12 — Dockerfile

**Intent:** Create a production-ready Dockerfile for `IdentityData.Api` that builds the image, runs the API, and accepts configuration via environment variables.

**Expected Outcomes:**
- `docker build` succeeds
- Container starts and responds on port 8080
- No secrets baked into the image
- Environment variable names match the ASP.NET Core configuration key convention (`IdentityProvider__Authority`, `Jwt__Audience`, `ConnectionStrings__DefaultConnection`)

**Todo List:**
1. Create `src/IdentityData.Api/Dockerfile`:
   - Multi-stage: `sdk:10` build stage → `aspnet:10` runtime stage
   - Build: `dotnet publish -c Release -o /app`
   - Runtime: `EXPOSE 8080`, `ENTRYPOINT ["dotnet", "IdentityData.Api.dll"]`
   - `ENV ASPNETCORE_URLS=http://+:8080`
   - Local development port: HTTPS `7100`, HTTP `5100` (configured in `launchSettings.json`)
   - CORS: Allow-list locked to `https://localhost:3000` in Development environment (pre-configured for Phase 4 Next.js client)
2. Create `.dockerignore` at solution root (or `src/IdentityData.Api/`) to exclude `bin/`, `obj/`, `*.user`
3. Document `docker build` and `docker run` commands with environment variable examples in `docs/phase-2.md`

**Status:** `[ ] pending`

---

## Sub-Task 13 — Documentation

**Intent:** Update the root README and create `docs/phase-2.md` to document the Phase 2 architecture, endpoints, local setup, and testing.

**Expected Outcomes:**
- `README.md` Phase 2 roadmap entry updated from `🔜` to `✅`
- `docs/phase-2.md` exists with Mermaid architecture diagram, endpoint documentation, setup instructions, Docker usage, and security notes

**Todo List:**
1. Update `README.md`:
   - Mark Phase 2 as `✅ Complete`
   - Add Phase 2 to the overview section
   - Add new endpoints to the API table
2. Create `docs/phase-2.md` with:
   - Mermaid architecture diagram (IdentityProvider → JWT → IdentityData.Api → Supabase → Response)
   - JWT validation flow
   - JWK retrieval explanation
   - OAuth scopes table
   - Protected endpoint documentation
   - CQRS query flow diagrams
   - PostgreSQL schema (table definitions)
   - Authentication vs. authorization explanation
   - Audit logging events
   - Local setup (prerequisites, migrate, seed, run)
   - Integration test instructions
   - Docker build and run examples
   - Security considerations

**Status:** `[ ] pending`

---

## Required NuGet Packages Summary

### `IdentityData.Api`
| Package | Purpose |
|---|---|
| `MediatR` 12.5.0 | CQRS dispatch |
| `FluentValidation.AspNetCore` 11.3.0 | Input validation |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | JWT Bearer middleware |
| `Microsoft.IdentityModel.Protocols.OpenIdConnect` | JWK/OIDC config fetch |
| `Microsoft.EntityFrameworkCore` | ORM |
| `Npgsql.EntityFrameworkCore.PostgreSQL` | PostgreSQL provider |
| `Microsoft.EntityFrameworkCore.Tools` | Migrations CLI |
| `Swashbuckle.AspNetCore` 7.x | Swagger UI |
| `Serilog.AspNetCore` 9.x | Structured logging |
| `Serilog.Sinks.Console` 6.x | Console sink |

### `IdentityData.UnitTests`
| Package | Purpose |
|---|---|
| `xunit` 2.9.x | Test framework |
| `xunit.runner.visualstudio` 3.x | VS runner |
| `FluentAssertions` 8.4.0 | Assertions |
| `Moq` 4.20.x | Mocking |
| `Microsoft.NET.Test.Sdk` | Test SDK |
| `coverlet.collector` | Coverage |

### `IdentityData.IntegrationTests`
| Package | Purpose |
|---|---|
| `xunit` 2.9.x | Test framework |
| `FluentAssertions` 8.4.0 | Assertions |
| `Microsoft.AspNetCore.Mvc.Testing` | WebApplicationFactory |
| `Microsoft.EntityFrameworkCore.InMemory` | Test DB |
| `Microsoft.NET.Test.Sdk` | Test SDK |
| Project ref: `IdentityProvider.Api` | Full-flow test token issuance |

---

## Security Considerations

| Concern | Mitigation |
|---|---|
| Token forgery | RS256 signature validated against JWK-fetched public key only |
| Weak algorithm | `ValidAlgorithms = ["RS256"]` — HS256 and `none` rejected |
| Wrong issuer | `ValidateIssuer = true` with exact issuer match |
| Wrong audience | `ValidateAudience = true` with exact audience match |
| Expired token | `ValidateLifetime = true`, `ClockSkew = Zero` |
| Scope escalation | Policy requires `identity.read` in `scope` claim |
| Token logging | No token values logged anywhere — enforced by code review |
| SQL injection | EF Core parameterized queries only |
| Stack trace leakage | `GlobalExceptionMiddleware` returns generic 500 |
| CORS | Strict allow-list (configured via `AllowedOrigins` in appsettings) |
| Private key exposure | `IdentityData.Api` never receives the private key — JWK endpoint provides public key only |
| Database credentials | Connection string via environment variable / secrets — never committed |

---

## Execution Order

```
Phase 1 Compatibility Change
    ↓
Sub-Task 1: Scaffolding
    ↓
Sub-Task 2: Domain Layer
    ↓
Sub-Task 3: EF Core & Persistence
    ↓
Sub-Task 4: JWT Auth & JWK Integration
    ↓
Sub-Task 5: CurrentUser & Authorization Policies
    ↓
Sub-Task 6: CQRS Queries
    ↓
Sub-Task 7: Controllers & Error Handling
    ↓
Sub-Task 8: Audit Logging
    ↓
Sub-Task 9: Swagger
    ↓
Sub-Task 10: Unit Tests
    ↓
Sub-Task 11: Integration Tests
    ↓
Sub-Task 12: Dockerfile
    ↓
Sub-Task 13: Documentation
```
