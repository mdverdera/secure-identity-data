using Microsoft.AspNetCore.Authentication;

namespace IdentityData.Api.Infrastructure.Authentication;

/// <summary>
/// Options for the DPoP authentication scheme.
/// DPoP-specific configuration is provided via <see cref="IdentityData.Api.Infrastructure.DPoP.DpopOptions"/>.
/// </summary>
public sealed class DpopAuthenticationOptions : AuthenticationSchemeOptions
{
    // No additional options needed — DPoP config comes from DpopOptions.
}
