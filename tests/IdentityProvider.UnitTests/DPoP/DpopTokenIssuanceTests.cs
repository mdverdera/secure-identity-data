using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using FluentAssertions;
using IdentityProvider.Api.Infrastructure.Authentication;
using IdentityProvider.Api.Infrastructure.Jwt;

namespace IdentityProvider.UnitTests.DPoP;

/// <summary>
/// Unit tests for <see cref="JwtService"/> DPoP issuance behaviour.
/// Verifies that a token issued with <see cref="TokenRequest.CnfJkt"/> carries the
/// correct <c>cnf</c> claim and <c>TokenType = "DPoP"</c>, and that a token issued
/// without <see cref="TokenRequest.CnfJkt"/> is a plain Bearer token with no cnf claim.
/// </summary>
public sealed class DpopTokenIssuanceTests : IDisposable
{
    private readonly RsaSigningKeyProvider _keyProvider = new();
    private readonly JwtService _sut;

    // A realistic thumbprint value — 43-character Base64URL string.
    private const string SampleJkt = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    private const string TestIssuer   = "https://localhost:7001";
    private const string TestAudience = "secure-identity-data-api";

    public DpopTokenIssuanceTests()
    {
        _sut = new JwtService(_keyProvider);
    }

    // ── DPoP-bound token ───────────────────────────────────────────────────────

    /// <summary>
    /// When CnfJkt is provided, the issued JWT must contain a <c>cnf</c> claim whose
    /// value is valid JSON with a <c>jkt</c> field equal to the supplied thumbprint.
    /// </summary>
    [Fact]
    public void GenerateAccessToken_WithCnfJkt_ContainsCnfClaimWithCorrectJkt()
    {
        var request = new TokenRequest(
            UserId:   "user-001",
            Scope:    "openid profile",
            Issuer:   TestIssuer,
            Audience: TestAudience,
            CnfJkt:   SampleJkt);

        var result = _sut.GenerateAccessToken(request);

        var jwtHandler = new JwtSecurityTokenHandler();
        var parsed     = jwtHandler.ReadJwtToken(result.AccessToken);

        var cnfClaim = parsed.Claims.FirstOrDefault(c => c.Type == "cnf");
        cnfClaim.Should().NotBeNull("a DPoP-bound token must carry a cnf claim");

        var cnfJson = JsonDocument.Parse(cnfClaim!.Value);
        cnfJson.RootElement.TryGetProperty("jkt", out var jktElement).Should().BeTrue(
            "cnf must contain a jkt property");
        jktElement.GetString().Should().Be(SampleJkt);
    }

    /// <summary>
    /// When CnfJkt is provided, <c>TokenResult.TokenType</c> must be "DPoP".
    /// </summary>
    [Fact]
    public void GenerateAccessToken_WithCnfJkt_TokenTypeIsDPoP()
    {
        var request = new TokenRequest(
            UserId:   "user-001",
            Scope:    "openid profile",
            Issuer:   TestIssuer,
            Audience: TestAudience,
            CnfJkt:   SampleJkt);

        var result = _sut.GenerateAccessToken(request);

        result.TokenType.Should().Be("DPoP");
    }

    // ── Bearer token ───────────────────────────────────────────────────────────

    /// <summary>
    /// When CnfJkt is null, the issued JWT must NOT contain a <c>cnf</c> claim.
    /// </summary>
    [Fact]
    public void GenerateAccessToken_WithoutCnfJkt_ContainsNoCnfClaim()
    {
        var request = new TokenRequest(
            UserId:   "user-001",
            Scope:    "openid profile",
            Issuer:   TestIssuer,
            Audience: TestAudience,
            CnfJkt:   null);

        var result = _sut.GenerateAccessToken(request);

        var jwtHandler = new JwtSecurityTokenHandler();
        var parsed     = jwtHandler.ReadJwtToken(result.AccessToken);

        parsed.Claims.Should().NotContain(c => c.Type == "cnf",
            "a Bearer token must not contain a cnf claim");
    }

    /// <summary>
    /// When CnfJkt is null, <c>TokenResult.TokenType</c> must be "Bearer".
    /// </summary>
    [Fact]
    public void GenerateAccessToken_WithoutCnfJkt_TokenTypeIsBearer()
    {
        var request = new TokenRequest(
            UserId:   "user-001",
            Scope:    "openid profile",
            Issuer:   TestIssuer,
            Audience: TestAudience,
            CnfJkt:   null);

        var result = _sut.GenerateAccessToken(request);

        result.TokenType.Should().Be("Bearer");
    }

    // ── cnf claim format ───────────────────────────────────────────────────────

    /// <summary>
    /// The <c>cnf</c> claim value must be valid JSON in the form <c>{"jkt":"&lt;thumbprint&gt;"}</c>.
    /// </summary>
    [Fact]
    public void GenerateAccessToken_WithCnfJkt_CnfClaimIsValidJson()
    {
        var request = new TokenRequest(
            UserId:   "user-001",
            Scope:    "openid profile",
            Issuer:   TestIssuer,
            Audience: TestAudience,
            CnfJkt:   SampleJkt);

        var result = _sut.GenerateAccessToken(request);

        var jwtHandler = new JwtSecurityTokenHandler();
        var parsed     = jwtHandler.ReadJwtToken(result.AccessToken);

        var cnfClaim = parsed.Claims.FirstOrDefault(c => c.Type == "cnf");
        cnfClaim.Should().NotBeNull();

        // Must parse cleanly as a JSON object.
        var act = () => JsonDocument.Parse(cnfClaim!.Value);
        act.Should().NotThrow("cnf must be valid JSON");

        var doc = JsonDocument.Parse(cnfClaim!.Value);
        doc.RootElement.ValueKind.Should().Be(JsonValueKind.Object,
            "cnf must be a JSON object");

        // The serialised form must match the canonical {"jkt":"<value>"} shape.
        var serialised = cnfClaim.Value;
        serialised.Should().Contain("\"jkt\"");
        serialised.Should().Contain(SampleJkt);
    }

    public void Dispose() => _keyProvider.Dispose();
}
