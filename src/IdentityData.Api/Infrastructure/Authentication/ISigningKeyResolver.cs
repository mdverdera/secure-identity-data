using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Infrastructure.Authentication;

/// <summary>
/// Abstracts the resolution of JWT signing keys for token validation.
/// The production implementation fetches keys from the JWKS URI.
/// Test implementations return a fixed in-process key.
/// </summary>
public interface ISigningKeyResolver
{
    /// <summary>
    /// Returns the signing keys to use when validating a JWT token.
    /// </summary>
    IEnumerable<SecurityKey> ResolveSigningKeys(
        string token,
        SecurityToken? securityToken,
        string kid,
        TokenValidationParameters validationParameters);
}
