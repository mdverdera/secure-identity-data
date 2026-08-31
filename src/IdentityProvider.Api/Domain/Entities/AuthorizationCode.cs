namespace IdentityProvider.Api.Domain.Entities;

/// <summary>
/// Represents a single-use, short-lived authorization code issued after a
/// successful authorization request. The code is bound to the client,
/// redirect URI, and PKCE code_challenge — it cannot be used by any other party.
/// </summary>
public sealed class AuthorizationCode
{
    /// <summary>Cryptographically secure random code value (256-bit entropy).</summary>
    public string Code { get; init; } = string.Empty;

    public string ClientId { get; init; } = string.Empty;
    public string RedirectUri { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public string Scope { get; init; } = string.Empty;

    /// <summary>The S256 PKCE challenge stored at authorization time.</summary>
    public string CodeChallenge { get; init; } = string.Empty;
    public string CodeChallengeMethod { get; init; } = string.Empty;

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Whether the code has already been exchanged for a token.
    /// Once true the code must be permanently rejected.
    /// </summary>
    public bool Used { get; private set; }

    /// <summary>Returns true when the code has passed its expiry time.</summary>
    public bool IsExpired(DateTimeOffset? now = null) =>
        (now ?? DateTimeOffset.UtcNow) >= ExpiresAt;

    /// <summary>
    /// Marks the code as used. Calling this a second time is a no-op;
    /// callers should check <see cref="Used"/> before trusting the state.
    /// </summary>
    public void MarkUsed() => Used = true;
}
