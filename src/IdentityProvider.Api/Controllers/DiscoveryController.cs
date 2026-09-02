using IdentityProvider.Api.Features.Discovery.Queries.GetJwks;
using IdentityProvider.Api.Features.Discovery.Queries.GetOpenIdConfiguration;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace IdentityProvider.Api.Controllers;

/// <summary>
/// Serves OpenID-style discovery metadata and JWKS.
///
/// ⚠️  DEMO IDENTITY PROVIDER — Not for production use.
/// This is a simplified discovery endpoint for the POC.
/// It does NOT claim full OpenID Connect compliance.
/// </summary>
[ApiController]
public sealed class DiscoveryController : ControllerBase
{
    private readonly IMediator _mediator;

    public DiscoveryController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// OpenID-style discovery metadata endpoint.
    /// Returns only capabilities that are actually implemented.
    /// This is a simplified endpoint for the POC and does not claim full OIDC compliance.
    /// </summary>
    [HttpGet("/.well-known/openid-configuration")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(OpenIdConfigurationResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetOpenIdConfiguration(CancellationToken cancellationToken)
    {
        var result = await _mediator.Send(new GetOpenIdConfigurationQuery(), cancellationToken);
        return Ok(new OpenIdConfigurationResponse(result));
    }

    /// <summary>
    /// JSON Web Key Set endpoint.
    /// Returns the public RSA signing key. The private key is never exposed.
    /// </summary>
    [HttpGet("/.well-known/jwks.json")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(JwksResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetJwks(CancellationToken cancellationToken)
    {
        var result = await _mediator.Send(new GetJwksQuery(), cancellationToken);
        return Ok(new JwksResponse(result.Keys.Select(k => new JwkResponse(k)).ToList()));
    }

    // ── Response DTOs (snake_case per spec) ─────────────────────────────────

    private sealed record OpenIdConfigurationResponse
    {
        [JsonPropertyName("issuer")] public string Issuer { get; init; }
        [JsonPropertyName("authorization_endpoint")] public string AuthorizationEndpoint { get; init; }
        [JsonPropertyName("token_endpoint")] public string TokenEndpoint { get; init; }
        [JsonPropertyName("jwks_uri")] public string JwksUri { get; init; }
        [JsonPropertyName("response_types_supported")] public IReadOnlyList<string> ResponseTypesSupported { get; init; }
        [JsonPropertyName("subject_types_supported")] public IReadOnlyList<string> SubjectTypesSupported { get; init; }
        [JsonPropertyName("id_token_signing_alg_values_supported")] public IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }
        [JsonPropertyName("scopes_supported")] public IReadOnlyList<string> ScopesSupported { get; init; }
        [JsonPropertyName("token_endpoint_auth_methods_supported")] public IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; }
        [JsonPropertyName("code_challenge_methods_supported")] public IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; }
        [JsonPropertyName("dpop_signing_alg_values_supported")] public IReadOnlyList<string> DpopSigningAlgValuesSupported { get; init; }

        public OpenIdConfigurationResponse(OpenIdConfigurationResult r)
        {
            Issuer = r.Issuer;
            AuthorizationEndpoint = r.AuthorizationEndpoint;
            TokenEndpoint = r.TokenEndpoint;
            JwksUri = r.JwksUri;
            ResponseTypesSupported = r.ResponseTypesSupported;
            SubjectTypesSupported = r.SubjectTypesSupported;
            IdTokenSigningAlgValuesSupported = r.IdTokenSigningAlgValuesSupported;
            ScopesSupported = r.ScopesSupported;
            TokenEndpointAuthMethodsSupported = r.TokenEndpointAuthMethodsSupported;
            CodeChallengeMethodsSupported = r.CodeChallengeMethodsSupported;
            DpopSigningAlgValuesSupported = r.DpopSigningAlgValuesSupported;
        }
    }

    private sealed record JwksResponse(
        [property: JsonPropertyName("keys")] IReadOnlyList<JwkResponse> Keys);

    private sealed record JwkResponse
    {
        [JsonPropertyName("kty")] public string Kty { get; init; }
        [JsonPropertyName("use")] public string Use { get; init; }
        [JsonPropertyName("alg")] public string Alg { get; init; }
        [JsonPropertyName("kid")] public string Kid { get; init; }
        [JsonPropertyName("n")] public string N { get; init; }
        [JsonPropertyName("e")] public string E { get; init; }

        public JwkResponse(JsonWebKeyDto dto)
        {
            Kty = dto.Kty;
            Use = dto.Use;
            Alg = dto.Alg;
            Kid = dto.Kid;
            N = dto.N;
            E = dto.E;
        }
    }
}
