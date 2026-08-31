namespace IdentityProvider.Api.Domain.Entities;

/// <summary>
/// Represents a registered OAuth client.
/// Phase 1 uses a public-client model (no client_secret) because PKCE provides
/// the required proof-of-possession for public clients per OAuth 2.1 recommendations.
/// A confidential client would require a client_secret, which is unnecessary here
/// and would add complexity without security benefit for the PKCE demonstration.
/// </summary>
public sealed class OAuthClient
{
    public string ClientId { get; init; } = string.Empty;
    public string ClientName { get; init; } = string.Empty;
    public IReadOnlyList<string> RedirectUris { get; init; } = [];
    public IReadOnlyList<string> AllowedScopes { get; init; } = [];

    /// <summary>
    /// Returns true if the redirect URI is an exact match against the registered URIs.
    /// Exact-match only — no wildcards, no path prefix matching.
    /// </summary>
    public bool IsRedirectUriAllowed(string redirectUri) =>
        RedirectUris.Any(r => string.Equals(r, redirectUri, StringComparison.Ordinal));

    /// <summary>
    /// Returns true if all requested scopes are within the client's AllowedScopes.
    /// </summary>
    public bool AreScopesAllowed(IEnumerable<string> requestedScopes) =>
        requestedScopes.All(s => AllowedScopes.Contains(s, StringComparer.Ordinal));
}
