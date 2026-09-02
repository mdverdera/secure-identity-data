using System.Collections.Concurrent;

namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// In-memory DPoP JTI replay store backed by <see cref="ConcurrentDictionary{TKey,TValue}"/>.
///
/// <para>
/// ⚠️ <b>WARNING</b>: This implementation is only suitable for single-instance deployments.
/// For multi-instance (horizontally scaled) deployments, replace with a distributed
/// store such as Redis or a database-backed implementation.
/// The <see cref="IDpopReplayStore"/> abstraction is designed to be swappable without
/// changing the DPoP validation logic.
/// </para>
/// </summary>
public sealed class InMemoryDpopReplayStore : IDpopReplayStore
{
    // Maps jti → expiry. Entries are lazily pruned on each HasBeenUsedAsync call.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> HasBeenUsedAsync(string jti, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;

        // Lazy cleanup: remove entries that have already expired to bound memory growth.
        foreach (var key in _used.Keys)
        {
            if (_used.TryGetValue(key, out var exp) && exp <= now)
                _used.TryRemove(key, out _);
        }

        // A jti is "used" only if it exists AND its expiry is still in the future.
        var used = _used.TryGetValue(jti, out var expiry) && expiry > now;
        return Task.FromResult(used);
    }

    /// <inheritdoc />
    public Task MarkAsUsedAsync(string jti, DateTimeOffset expiry, CancellationToken ct = default)
    {
        // TryAdd is a no-op if the key already exists — the first writer wins, which is correct.
        _used.TryAdd(jti, expiry);
        return Task.CompletedTask;
    }
}
