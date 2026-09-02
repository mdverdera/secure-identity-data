using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using IdentityProvider.Api.Infrastructure.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Api.Infrastructure.Jwt;

/// <summary>
/// Issues RS256 signed JWT access tokens.
///
/// Security notes:
/// - Access tokens are short-lived (configurable, default 15 minutes).
/// - A unique jti (JWT ID) is included to support future replay prevention.
/// - The kid header ties the token to a specific JWK for verification.
/// - No sensitive personal data is placed in the token payload.
/// - Token values are NEVER logged.
/// </summary>
public sealed class JwtService : IJwtService
{
    private readonly ISigningKeyProvider _signingKeyProvider;
    private readonly int _accessTokenLifetimeSeconds;

    public JwtService(ISigningKeyProvider signingKeyProvider, int accessTokenLifetimeSeconds = 900)
    {
        _signingKeyProvider = signingKeyProvider;
        _accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
    }

    /// <inheritdoc />
    public TokenResult GenerateAccessToken(TokenRequest request)
    {
        var signingKey = _signingKeyProvider.GetSigningKey();
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

        var now = DateTime.UtcNow;
        var expiry = now.AddSeconds(_accessTokenLifetimeSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, request.UserId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new("scope", request.Scope),
        };

        if (request.CnfJkt is not null)
            claims.Add(new Claim("cnf", $"{{\"jkt\":\"{request.CnfJkt}\"}}", Microsoft.IdentityModel.JsonWebTokens.JsonClaimValueTypes.Json));

        var token = new JwtSecurityToken(
            issuer: request.Issuer,
            audience: request.Audience,
            claims: claims,
            notBefore: now,
            expires: expiry,
            signingCredentials: credentials);

        // Ensure kid is present in the JWT header for JWK resolution
        token.Header[JwtHeaderParameterNames.Kid] = _signingKeyProvider.KeyId;

        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(token);

        // NOTE: Do not log tokenString — access tokens are sensitive credentials.
        var tokenType = request.CnfJkt is not null ? "DPoP" : "Bearer";
        return new TokenResult(tokenString, _accessTokenLifetimeSeconds, tokenType);
    }
}
