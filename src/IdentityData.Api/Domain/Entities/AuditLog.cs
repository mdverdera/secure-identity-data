namespace IdentityData.Api.Domain.Entities;

/// <summary>
/// Records an auditable access event for identity data.
/// </summary>
public sealed class AuditLog
{
    public required Guid Id { get; init; }
    public required string UserId { get; init; }
    public required string Action { get; init; }
    public required string Resource { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required string ClientId { get; init; }
}
