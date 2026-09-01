namespace IdentityData.Api;

/// <summary>
/// Marker class used as the TEntryPoint for <see cref="Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory{TEntryPoint}"/>.
/// Avoids a global-namespace <c>Program</c> collision when the test project also references IdentityProvider.Api.
/// </summary>
public sealed class IdentityDataApiMarker { }
