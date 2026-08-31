using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// Manages authorization codes for the OAuth Authorization Code flow.
/// Codes are single-use and short-lived.
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>Persists a newly issued authorization code.</summary>
    Task StoreAsync(AuthorizationCode code, CancellationToken ct = default);

    /// <summary>
    /// Retrieves an authorization code by value.
    /// Returns null if the code does not exist or has already been removed.
    /// </summary>
    Task<AuthorizationCode?> FindAsync(string code, CancellationToken ct = default);

    /// <summary>
    /// Removes a code from the store (called after successful exchange or when expired).
    /// </summary>
    Task RemoveAsync(string code, CancellationToken ct = default);
}
