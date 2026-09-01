namespace IdentityData.Api.Domain.Entities;

public sealed class User
{
    public Guid Id { get; init; }
    public string Subject { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
    public DateOnly DateOfBirth { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }

    // Navigation
    public ICollection<IdentityAttribute> Attributes { get; init; } = [];
    public ICollection<Consent> Consents { get; init; } = [];
    public ICollection<AuditLog> AuditLogs { get; init; } = [];
}
