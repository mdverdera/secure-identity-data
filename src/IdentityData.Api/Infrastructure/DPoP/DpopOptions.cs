namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// Strongly-typed configuration for DPoP proof validation at the resource server.
/// Bind from the "Dpop" section in appsettings.json.
/// </summary>
public sealed class DpopOptions
{
    /// <summary>The configuration section name.</summary>
    public const string SectionName = "Dpop";

    /// <summary>Whether DPoP enforcement is active. Defaults to <c>true</c>.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Asymmetric signing algorithms accepted in the DPoP proof <c>alg</c> header.
    /// Defaults to ES256 only.
    /// </summary>
    public string[] SigningAlgorithms { get; init; } = ["ES256"];

    /// <summary>
    /// Maximum age (in seconds) of a DPoP proof, measured from <c>iat</c>.
    /// Defaults to 300 seconds (5 minutes).
    /// </summary>
    public int MaximumAgeSeconds { get; init; } = 300;

    /// <summary>
    /// Permitted clock skew (in seconds) for <c>iat</c> validation.
    /// Defaults to 60 seconds.
    /// </summary>
    public int ClockSkewSeconds { get; init; } = 60;

    /// <summary>
    /// Whether replay protection (JTI uniqueness enforcement) is active.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool ReplayProtectionEnabled { get; init; } = true;
}
