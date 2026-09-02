using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// In-memory implementation seeded with the single demo client.
/// Phase 1 only — not suitable for production use.
///
/// The demo client uses the public-client model (no client_secret).
/// PKCE with S256 provides the required proof-of-possession for public clients,
/// per OAuth 2.1 recommendations. A client_secret would be unnecessary complexity
/// for demonstrating the Authorization Code + PKCE flow.
/// </summary>
public sealed class InMemoryClientStore : IClientStore
{
    private static readonly IReadOnlyDictionary<string, OAuthClient> Clients =
        new Dictionary<string, OAuthClient>(StringComparer.Ordinal)
        {
            ["secure-demo-client"] = new OAuthClient
            {
                ClientId = "secure-demo-client",
                ClientName = "Secure Identity Demo Client",
                RedirectUris = ["https://localhost:3000/callback"],
                AllowedScopes = ["openid", "profile", "identity.read"],
            },
        };

    public Task<OAuthClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default) =>
        Task.FromResult(Clients.TryGetValue(clientId, out var client) ? client : null);
}
