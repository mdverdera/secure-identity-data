namespace IdentityData.Api.Domain.Entities;

public sealed class IdentityAttribute
{
    public Guid Id { get; init; }
    public Guid UserId { get; init; }
    public string AttributeName { get; init; } = string.Empty;
    public string AttributeValue { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }

    // Navigation
    public User User { get; init; } = null!;
}
