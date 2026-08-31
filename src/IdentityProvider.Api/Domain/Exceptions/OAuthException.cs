namespace IdentityProvider.Api.Domain.Exceptions;

/// <summary>
/// Represents an OAuth protocol error that should be returned to the caller
/// using the standard OAuth error response format.
/// </summary>
public sealed class OAuthException : Exception
{
    /// <summary>OAuth error code (e.g. "invalid_client", "invalid_grant").</summary>
    public string Error { get; }

    /// <summary>Human-readable description safe to return to clients.</summary>
    public string? ErrorDescription { get; }

    public OAuthException(string error, string? errorDescription = null)
        : base(errorDescription ?? error)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    // ── Standard OAuth 2.x error codes ──────────────────────────────────────

    public static OAuthException InvalidRequest(string description) =>
        new("invalid_request", description);

    public static OAuthException InvalidClient(string description) =>
        new("invalid_client", description);

    public static OAuthException InvalidGrant(string description) =>
        new("invalid_grant", description);

    public static OAuthException InvalidScope(string description) =>
        new("invalid_scope", description);

    public static OAuthException UnsupportedResponseType(string description) =>
        new("unsupported_response_type", description);

    public static OAuthException UnsupportedGrantType(string description) =>
        new("unsupported_grant_type", description);
}
