namespace IdentityData.Api.Domain.Entities;

public sealed class Consent
{
    public Guid Id { get; init; }
    public Guid UserId { get; init; }
    public string ClientId { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;
    public DateTimeOffset GrantedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }

    // Navigation
    public User User { get; init; } = null!;
}
