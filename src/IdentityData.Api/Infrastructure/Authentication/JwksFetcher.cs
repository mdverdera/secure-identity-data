using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Infrastructure.Authentication;

public static class JwksFetcher
{
    public static async Task<IEnumerable<SecurityKey>> FetchAsync(
        string jwksUri,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10);

            var json = await httpClient.GetStringAsync(jwksUri, cancellationToken);
            var keySet = new JsonWebKeySet(json);
            var keys = keySet.GetSigningKeys();

            logger.LogInformation("Successfully fetched {Count} signing key(s) from {Uri}", keys.Count, jwksUri);
            return keys;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "Could not fetch JWK from {Uri}: {Message}. JWT validation will fail until keys are available.",
                jwksUri,
                ex.Message);
            return [];
        }
    }
}
