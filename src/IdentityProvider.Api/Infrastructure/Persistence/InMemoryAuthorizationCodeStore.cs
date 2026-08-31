using System.Collections.Concurrent;
using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// Thread-safe in-memory authorization code store backed by a ConcurrentDictionary.
/// Phase 1 only — not suitable for production or multi-instance deployments.
/// </summary>
public sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCode> _store = new(StringComparer.Ordinal);

    public Task StoreAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        _store[code.Code] = code;
        return Task.CompletedTask;
    }

    public Task<AuthorizationCode?> FindAsync(string code, CancellationToken ct = default)
    {
        _store.TryGetValue(code, out var authCode);
        return Task.FromResult(authCode);
    }

    public Task RemoveAsync(string code, CancellationToken ct = default)
    {
        _store.TryRemove(code, out _);
        return Task.CompletedTask;
    }
}
