using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.IntegrationTests.Helpers;

/// <summary>
/// Mints JWT access tokens and DPoP proof JWTs for use in IdentityData.Api integration tests.
///
/// All tokens are signed with real cryptographic keys so the produced JWTs pass the full
/// validation pipeline inside the application under test.
/// </summary>
public static class TestTokenFactory
{
    // ── Access tokens ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a plain Bearer JWT access token — no cnf binding.
    /// </summary>
    public static string CreateBearerToken(
        SecurityKey signingKey,
        string userId            = "user-001",
        string scope             = "openid profile identity.read",
        string issuer            = TestConstants.Issuer,
        string audience          = TestConstants.Audience,
        int    lifetimeSeconds   = 900)
    {
        var now    = DateTime.UtcNow;
        var claims = BuildBaseClaims(userId, scope);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject            = new ClaimsIdentity(claims),
            Issuer             = issuer,
            Audience           = audience,
            IssuedAt           = now,
            NotBefore          = now,
            Expires            = now.AddSeconds(lifetimeSeconds),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
        };

        var handler = new JwtSecurityTokenHandler();
        var token   = handler.CreateToken(descriptor);
        return handler.WriteToken(token);
    }

    /// <summary>
    /// Creates a DPoP-bound JWT access token — includes a <c>cnf.jkt</c> claim
    /// binding the token to the supplied EC P-256 key.
    /// </summary>
    public static string CreateDpopBoundToken(
        SecurityKey signingKey,
        ECDsa       dpopKey,
        string userId          = "user-001",
        string scope           = "openid profile identity.read",
        string issuer          = TestConstants.Issuer,
        string audience        = TestConstants.Audience,
        int    lifetimeSeconds = 900)
    {
        var thumbprint = ComputeEcThumbprint(dpopKey);
        var cnfValue   = JsonSerializer.Serialize(new { jkt = thumbprint });

        var now    = DateTime.UtcNow;
        var claims = BuildBaseClaims(userId, scope);
        claims.Add(new Claim("cnf", cnfValue, JsonClaimValueTypes.Json));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject            = new ClaimsIdentity(claims),
            Issuer             = issuer,
            Audience           = audience,
            IssuedAt           = now,
            NotBefore          = now,
            Expires            = now.AddSeconds(lifetimeSeconds),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
        };

        var handler = new JwtSecurityTokenHandler();
        var token   = handler.CreateToken(descriptor);
        return handler.WriteToken(token);
    }

    // ── DPoP proofs ──────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a DPoP proof JWT signed with the supplied EC P-256 key.
    /// Includes an <c>ath</c> claim (SHA-256 of the access token) when
    /// <paramref name="accessToken"/> is provided.
    /// </summary>
    public static string CreateDpopProof(
        ECDsa  key,
        string htm,
        string htu,
        string? accessToken      = null,
        int     iatOffsetSeconds = 0,
        string? overrideJti      = null)
    {
        var parameters   = key.ExportParameters(includePrivateParameters: false);
        var x            = Base64UrlEncode(parameters.Q.X!);
        var y            = Base64UrlEncode(parameters.Q.Y!);

        // ── Header ──────────────────────────────────────────────────────────
        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = "ES256",
            ["jwk"] = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"]   = x,
                ["y"]   = y,
            },
        };

        // ── Payload ─────────────────────────────────────────────────────────
        var payload = new Dictionary<string, object>
        {
            ["jti"] = overrideJti ?? Guid.NewGuid().ToString(),
            ["htm"] = htm,
            ["htu"] = htu,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + iatOffsetSeconds,
        };

        if (accessToken is not null)
        {
            var tokenBytes = Encoding.ASCII.GetBytes(accessToken);
            var hashBytes  = SHA256.HashData(tokenBytes);
            payload["ath"] = Base64UrlEncode(hashBytes);
        }

        // ── Encode + Sign ────────────────────────────────────────────────────
        var headerB64   = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadB64  = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        var signingInput = $"{headerB64}.{payloadB64}";

        var inputBytes = Encoding.ASCII.GetBytes(signingInput);
        var sig = key.SignData(
            inputBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return $"{signingInput}.{Base64UrlEncode(sig)}";
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static List<Claim> BuildBaseClaims(string userId, string scope) =>
    [
        new Claim(JwtRegisteredClaimNames.Sub, userId),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("scope", scope),
    ];

    /// <summary>Computes the RFC 7638 JWK thumbprint for an EC P-256 key.</summary>
    public static string ComputeEcThumbprint(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var x = Base64UrlEncode(parameters.Q.X!);
        var y = Base64UrlEncode(parameters.Q.Y!);

        // Canonical JSON: members in lexicographic order, no whitespace.
        var canonical = JsonSerializer.Serialize(new SortedDictionary<string, string>
        {
            ["crv"] = "P-256",
            ["kty"] = "EC",
            ["x"]   = x,
            ["y"]   = y,
        });

        var utf8 = Encoding.UTF8.GetBytes(canonical);
        var hash = SHA256.HashData(utf8);
        return Base64UrlEncode(hash);
    }

    internal static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
