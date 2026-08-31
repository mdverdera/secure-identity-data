using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace IdentityProvider.IntegrationTests.Helpers;

/// <summary>
/// Shared WebApplicationFactory for all integration tests.
/// Hosts the real IdentityProvider.Api pipeline in-process using
/// Microsoft.AspNetCore.Mvc.Testing — no network required.
/// </summary>
public sealed class IdentityProviderFactory : WebApplicationFactory<Program>
{
    // No overrides needed for Phase 1 — we use the real in-memory stores
    // and real RSA key provider. Each factory instance gets its own key.
}

/// <summary>
/// Provides PKCE helpers for integration tests.
/// </summary>
public static class PkceHelper
{
    public static string GenerateCodeVerifier()
    {
        // 32 bytes → 43 base64url chars — satisfies RFC 7636 minimum of 43 chars
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string GenerateCodeChallenge(string verifier)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(verifier);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
