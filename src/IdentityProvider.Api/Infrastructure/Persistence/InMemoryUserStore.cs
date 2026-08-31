using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.Api.Infrastructure.Persistence;

/// <summary>
/// In-memory demo user store.
/// Contains a single fictional test user — not real personal information.
/// </summary>
public sealed class InMemoryUserStore : IUserStore
{
    private static readonly User DemoUser = new()
    {
        UserId = "user-001",
        Name = "Demo User",
        Email = "demo@example.test",
    };

    public Task<User?> GetDemoUserAsync(CancellationToken ct = default) =>
        Task.FromResult<User?>(DemoUser);
}
