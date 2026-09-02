namespace IdentityData.Api.Domain.Entities;

/// <summary>
/// Represents a stored identity record for a user.
/// All data in this system is fictional and for educational purposes only.
/// This does NOT connect to or represent any real government identity system.
/// </summary>
public sealed class IdentityRecord
{
    public required string UserId { get; init; }
    public required string FullName { get; init; }
    public required string Email { get; init; }

    /// <summary>
    /// Fictional national identifier — NOT a real government ID format.
    /// Used for educational demonstration of sensitive data handling only.
    /// </summary>
    public required string NationalId { get; init; }

    public required DateOnly DateOfBirth { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
}
