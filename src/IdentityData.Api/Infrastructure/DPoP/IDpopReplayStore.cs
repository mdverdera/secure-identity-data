namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// Stores and checks DPoP proof JTI values to prevent replay attacks (RFC 9449 §11.1).
/// </summary>
public interface IDpopReplayStore
{
    /// <summary>
    /// Returns <c>true</c> if the given <paramref name="jti"/> has already been used
    /// and has not yet expired.
    /// </summary>
    Task<bool> HasBeenUsedAsync(string jti, CancellationToken ct = default);

    /// <summary>
    /// Records the <paramref name="jti"/> as used until <paramref name="expiry"/>.
    /// After <paramref name="expiry"/> the entry may be discarded.
    /// </summary>
    Task MarkAsUsedAsync(string jti, DateTimeOffset expiry, CancellationToken ct = default);
}
