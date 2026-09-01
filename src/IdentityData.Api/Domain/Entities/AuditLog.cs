namespace IdentityData.Api.Domain.Entities;

public sealed class AuditLog
{
    public Guid Id { get; init; }
    public Guid? UserId { get; init; }
    public string EventType { get; init; } = string.Empty;
    public string Resource { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
}
