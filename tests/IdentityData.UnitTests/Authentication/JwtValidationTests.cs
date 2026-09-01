using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace IdentityData.UnitTests.Authentication;

public sealed class JwtValidationTests
{
    private const string ValidIssuer = "https://localhost:7001";
    private const string ValidAudience = "secure-identity-data-api";

    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _verificationKey;
    private readonly TokenValidationParameters _validationParameters;

    public JwtValidationTests()
    {
        // Generate a fresh RSA key pair for tests
        var rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(rsa);

        // Export public key only for verification
        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(rsa.ExportParameters(false));
        _verificationKey = new RsaSecurityKey(publicRsa);

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = ValidIssuer,
            ValidateAudience = true,
            ValidAudience = ValidAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _verificationKey,
            ValidAlgorithms = ["RS256"]
        };
    }

    private string CreateToken(
        string? subject = "user-001",
        string? issuer = ValidIssuer,
        string? audience = ValidAudience,
        string? scope = "openid profile identity.read",
        int lifetimeSeconds = 900,
        SigningCredentials? signingCredentials = null)
    {
        var now = DateTime.UtcNow;
        var credentials = signingCredentials ?? new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>();
        if (subject != null) claims.Add(new Claim("sub", subject));
        if (scope != null) claims.Add(new Claim("scope", scope));

        // For negative lifetimes, shift notBefore back so expires is still after notBefore
        var notBefore = lifetimeSeconds < 0
            ? now.AddSeconds(lifetimeSeconds - 1)
            : now;

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: notBefore,
            expires: now.AddSeconds(lifetimeSeconds),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public void ValidToken_ShouldPassValidation()
    {
        var token = CreateToken();
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        act.Should().NotThrow();
    }

    [Fact]
    public void ExpiredToken_ShouldFailValidation()
    {
        var token = CreateToken(lifetimeSeconds: -1);
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        act.Should().Throw<SecurityTokenExpiredException>();
    }

    [Fact]
    public void WrongIssuer_ShouldFailValidation()
    {
        var token = CreateToken(issuer: "https://evil.example.com");
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        act.Should().Throw<SecurityTokenInvalidIssuerException>();
    }

    [Fact]
    public void WrongAudience_ShouldFailValidation()
    {
        var token = CreateToken(audience: "wrong-audience");
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        act.Should().Throw<SecurityTokenInvalidAudienceException>();
    }

    [Fact]
    public void InvalidSignature_ShouldFailValidation()
    {
        // Create token signed with a DIFFERENT key
        var differentRsa = RSA.Create(2048);
        var differentKey = new RsaSecurityKey(differentRsa);
        var differentCredentials = new SigningCredentials(differentKey, SecurityAlgorithms.RsaSha256);

        var token = CreateToken(signingCredentials: differentCredentials);
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        act.Should().Throw<SecurityTokenSignatureKeyNotFoundException>();
    }

    [Fact]
    public void Hs256Token_ShouldFailValidation()
    {
        // Create an HS256 token — should be rejected because ValidAlgorithms = ["RS256"]
        var hmacKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("super-secret-key-that-is-at-least-32-chars-long"));
        var hmacCredentials = new SigningCredentials(hmacKey, SecurityAlgorithms.HmacSha256);

        var token = CreateToken(signingCredentials: hmacCredentials);
        var handler = new JwtSecurityTokenHandler();

        var act = () => handler.ValidateToken(token, _validationParameters, out _);
        // The library rejects a token signed with the wrong algorithm family by failing
        // signature key lookup — both SecurityTokenInvalidAlgorithmException and
        // SecurityTokenSignatureKeyNotFoundException are acceptable rejections.
        act.Should().Throw<SecurityTokenException>();
    }
}
