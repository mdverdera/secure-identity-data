namespace IdentityProvider.Api.Domain.Entities;

/// <summary>
/// Represents a fictional demo user for the POC identity provider.
/// All data is test data — not real personal information.
/// </summary>
public sealed class User
{
    public string UserId { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Email { get; init; } = string.Empty;
}
