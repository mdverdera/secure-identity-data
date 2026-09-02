namespace IdentityProvider.Api.Infrastructure.Jwt;

/// <summary>
/// Encapsulates the claims/properties needed to generate an access token.
/// </summary>
public sealed record TokenRequest(
    string UserId,
    string Scope,
    string Issuer,
    string Audience,
    string? CnfJkt = null   // DPoP JWK thumbprint — when present, issues DPoP-bound token
);

/// <summary>
/// Result of a successful token generation.
/// </summary>
public sealed record TokenResult(
    string AccessToken,
    int ExpiresInSeconds,
    string TokenType = "Bearer"
);
