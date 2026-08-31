using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// Read-only store for registered OAuth clients.
/// </summary>
public interface IClientStore
{
    /// <summary>Returns the client with the given id, or null if not found.</summary>
    Task<OAuthClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default);
}
