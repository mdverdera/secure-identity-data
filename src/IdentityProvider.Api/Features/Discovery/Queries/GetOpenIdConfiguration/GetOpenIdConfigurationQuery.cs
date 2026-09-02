using MediatR;

namespace IdentityProvider.Api.Features.Discovery.Queries.GetOpenIdConfiguration;

/// <summary>
/// Query: return the OpenID-style discovery metadata document.
///
/// IMPORTANT: This is a simplified discovery endpoint for the POC.
/// It only advertises capabilities that are actually implemented.
/// This does NOT constitute full OpenID Connect compliance.
/// </summary>
public sealed record GetOpenIdConfigurationQuery : IRequest<OpenIdConfigurationResult>;

public sealed record OpenIdConfigurationResult(
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string JwksUri,
    IReadOnlyList<string> ResponseTypesSupported,
    IReadOnlyList<string> SubjectTypesSupported,
    IReadOnlyList<string> IdTokenSigningAlgValuesSupported,
    IReadOnlyList<string> ScopesSupported,
    IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    IReadOnlyList<string> CodeChallengeMethodsSupported,
    [property: System.Text.Json.Serialization.JsonPropertyName("dpop_signing_alg_values_supported")]
    IReadOnlyList<string> DpopSigningAlgValuesSupported
);
