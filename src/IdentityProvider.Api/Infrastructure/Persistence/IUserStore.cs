using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// Read-only store for demo users.
/// </summary>
public interface IUserStore
{
    /// <summary>Returns the demo user (Phase 1 has a single user).</summary>
    Task<User?> GetDemoUserAsync(CancellationToken ct = default);
}
