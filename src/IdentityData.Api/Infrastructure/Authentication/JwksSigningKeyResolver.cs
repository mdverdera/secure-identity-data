using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Infrastructure.Authentication;

/// <summary>
/// Production implementation of <see cref="ISigningKeyResolver"/>.
/// Fetches the signing key set from the configured JWKS URI on each call.
/// This is called infrequently (once per authentication event) so the HTTP cost is acceptable
/// for this educational POC. A production system would cache and refresh on a schedule.
/// </summary>
public sealed class JwksSigningKeyResolver : ISigningKeyResolver
{
    private readonly string _jwksUri;

    public JwksSigningKeyResolver(string jwksUri)
    {
        _jwksUri = jwksUri;
    }

    /// <inheritdoc />
    public IEnumerable<SecurityKey> ResolveSigningKeys(
        string token,
        SecurityToken? securityToken,
        string kid,
        TokenValidationParameters validationParameters)
    {
        try
        {
            using var http     = new System.Net.Http.HttpClient();
            var       jwksJson = http.GetStringAsync(_jwksUri).GetAwaiter().GetResult();
            var       jwks     = new JsonWebKeySet(jwksJson);
            return jwks.GetSigningKeys();
        }
        catch
        {
            return Enumerable.Empty<SecurityKey>();
        }
    }
}
