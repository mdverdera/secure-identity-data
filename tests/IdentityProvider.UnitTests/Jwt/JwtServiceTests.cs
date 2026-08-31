using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using IdentityProvider.Api.Infrastructure.Authentication;
using IdentityProvider.Api.Infrastructure.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.UnitTests.Jwt;

public sealed class JwtServiceTests : IDisposable
{
    private readonly RsaSigningKeyProvider _keyProvider = new();
    private readonly JwtService _sut;

    public JwtServiceTests()
    {
        _sut = new JwtService(_keyProvider, accessTokenLifetimeSeconds: 900);
    }

    private static TokenRequest BuildRequest(
        string userId = "user-001",
        string scope = "openid profile",
        string issuer = "https://localhost:7001",
        string audience = "secure-identity-data-api") =>
        new(userId, scope, issuer, audience);

    // ── Token issuance ────────────────────────────────────────────────────────

    [Fact]
    public void GenerateAccessToken_ReturnsNonEmptyAccessToken()
    {
        var result = _sut.GenerateAccessToken(BuildRequest());

        result.AccessToken.Should().NotBeNullOrWhiteSpace();
        result.TokenType.Should().Be("Bearer");
        result.ExpiresInSeconds.Should().Be(900);
    }

    [Fact]
    public void GenerateAccessToken_ProducesValidJwtStructure()
    {
        var result = _sut.GenerateAccessToken(BuildRequest());

        // A valid JWT has exactly 3 base64url segments separated by '.'
        var parts = result.AccessToken.Split('.');
        parts.Should().HaveCount(3);
    }

    // ── Claims ────────────────────────────────────────────────────────────────

    [Fact]
    public void GenerateAccessToken_ContainsCorrectIssuer()
    {
        var result = _sut.GenerateAccessToken(BuildRequest(issuer: "https://localhost:7001"));

        var jwt = ParseJwt(result.AccessToken);
        jwt.Issuer.Should().Be("https://localhost:7001");
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectSubject()
    {
        var result = _sut.GenerateAccessToken(BuildRequest(userId: "user-001"));

        var jwt = ParseJwt(result.AccessToken);
        jwt.Subject.Should().Be("user-001");
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectAudience()
    {
        var result = _sut.GenerateAccessToken(BuildRequest(audience: "secure-identity-data-api"));

        var jwt = ParseJwt(result.AccessToken);
        jwt.Audiences.Should().Contain("secure-identity-data-api");
    }

    [Fact]
    public void GenerateAccessToken_ContainsScopeClaimWithRequestedScopes()
    {
        var result = _sut.GenerateAccessToken(BuildRequest(scope: "openid profile"));

        var jwt = ParseJwt(result.AccessToken);
        var scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
        scope.Should().Be("openid profile");
    }

    [Fact]
    public void GenerateAccessToken_ContainsUniqueJti()
    {
        var result1 = _sut.GenerateAccessToken(BuildRequest());
        var result2 = _sut.GenerateAccessToken(BuildRequest());

        var jti1 = ParseJwt(result1.AccessToken).Id;
        var jti2 = ParseJwt(result2.AccessToken).Id;

        jti1.Should().NotBeNullOrEmpty();
        jti2.Should().NotBeNullOrEmpty();
        jti1.Should().NotBe(jti2);
    }

    [Fact]
    public void GenerateAccessToken_ExpiryIsWithinExpectedLifetime()
    {
        var before = DateTime.UtcNow;
        var result = _sut.GenerateAccessToken(BuildRequest());
        var after = DateTime.UtcNow;

        var jwt = ParseJwt(result.AccessToken);
        jwt.ValidTo.Should().BeAfter(before.AddSeconds(899));
        jwt.ValidTo.Should().BeBefore(after.AddSeconds(901));
    }

    [Fact]
    public void GenerateAccessToken_ContainsKidInHeader()
    {
        var result = _sut.GenerateAccessToken(BuildRequest());

        var jwt = ParseJwt(result.AccessToken);
        jwt.Header.Kid.Should().Be(_keyProvider.KeyId);
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    [Fact]
    public void GenerateAccessToken_SignatureIsValidWithPublicKey()
    {
        var result = _sut.GenerateAccessToken(BuildRequest());

        var publicKey = _keyProvider.GetPublicKey();
        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:7001",
            ValidateAudience = true,
            ValidAudience = "secure-identity-data-api",
            ValidateLifetime = true,
            IssuerSigningKey = publicKey,
            ClockSkew = TimeSpan.Zero,
        };

        var handler = new JwtSecurityTokenHandler();
        var act = () => handler.ValidateToken(result.AccessToken, validationParams, out _);

        act.Should().NotThrow("the token should be valid and verifiable with the public key");
    }

    [Fact]
    public void GenerateAccessToken_SignatureFailsWithDifferentKey()
    {
        var result = _sut.GenerateAccessToken(BuildRequest());

        // Use a different RSA key for verification — should fail
        using var differentKeyProvider = new RsaSigningKeyProvider();
        var differentPublicKey = differentKeyProvider.GetPublicKey();

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKey = differentPublicKey,
        };

        var handler = new JwtSecurityTokenHandler();
        var act = () => handler.ValidateToken(result.AccessToken, validationParams, out _);

        act.Should().Throw<SecurityTokenSignatureKeyNotFoundException>(
            "a different RSA key cannot verify the signature");
    }

    // ── Key management ────────────────────────────────────────────────────────

    [Fact]
    public void GetPublicKey_DoesNotExposePrivateParameters()
    {
        var publicKey = _keyProvider.GetPublicKey();
        var rsa = publicKey.Rsa;

        rsa.Should().NotBeNull();

        // ExportParameters(true) should throw when private parameters are not available
        var act = () => rsa!.ExportParameters(includePrivateParameters: true);
        act.Should().Throw<Exception>("the public-only key cannot export private parameters");
    }

    [Fact]
    public void SigningKey_KidMatchesPublicKeyKid()
    {
        var signingKey = _keyProvider.GetSigningKey();
        var publicKey = _keyProvider.GetPublicKey();

        signingKey.KeyId.Should().Be(publicKey.KeyId);
        signingKey.KeyId.Should().Be(_keyProvider.KeyId);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static JwtSecurityToken ParseJwt(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ReadJwtToken(token);
    }

    public void Dispose() => _keyProvider.Dispose();
}
