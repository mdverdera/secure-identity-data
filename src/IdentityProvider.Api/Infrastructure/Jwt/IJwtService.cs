namespace IdentityProvider.Api.Infrastructure.Jwt;

/// <summary>
/// Creates signed JWT access tokens for authenticated users.
/// </summary>
public interface IJwtService
{
    /// <summary>
    /// Generates a signed RS256 JWT access token.
    /// The token includes standard claims: iss, sub, aud, scope, iat, exp, jti.
    /// </summary>
    TokenResult GenerateAccessToken(TokenRequest request);
}
