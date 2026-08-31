using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Api.Infrastructure.Authentication;

/// <summary>
/// Provides the RSA signing key used for JWT issuance and JWK publication.
/// Abstracts key management so the implementation can be swapped for a
/// production key-management solution (e.g. AWS KMS / Secrets Manager)
/// without changing any consuming code.
/// </summary>
public interface ISigningKeyProvider
{
    /// <summary>The key identifier included in JWT headers and JWK set.</summary>
    string KeyId { get; }

    /// <summary>
    /// Returns the RSA security key for signing operations.
    /// The private key material must never be logged or exposed via HTTP.
    /// </summary>
    RsaSecurityKey GetSigningKey();

    /// <summary>
    /// Returns the RSA security key containing only public parameters,
    /// safe to expose via the JWKS endpoint.
    /// </summary>
    RsaSecurityKey GetPublicKey();
}
