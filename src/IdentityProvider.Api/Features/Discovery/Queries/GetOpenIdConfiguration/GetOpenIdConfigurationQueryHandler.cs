using MediatR;
using Microsoft.Extensions.Configuration;

namespace IdentityProvider.Api.Features.Discovery.Queries.GetOpenIdConfiguration;

/// <summary>
/// Builds the discovery document from configuration.
/// Only implemented capabilities are advertised.
/// </summary>
public sealed class GetOpenIdConfigurationQueryHandler
    : IRequestHandler<GetOpenIdConfigurationQuery, OpenIdConfigurationResult>
{
    private readonly IConfiguration _configuration;

    public GetOpenIdConfigurationQueryHandler(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public Task<OpenIdConfigurationResult> Handle(
        GetOpenIdConfigurationQuery request,
        CancellationToken cancellationToken)
    {
        var issuer = _configuration["IdentityProvider:Issuer"] ?? "https://localhost:7001";

        var result = new OpenIdConfigurationResult(
            Issuer: issuer,
            AuthorizationEndpoint: $"{issuer}/oauth/authorize",
            TokenEndpoint: $"{issuer}/oauth/token",
            JwksUri: $"{issuer}/.well-known/jwks.json",
            ResponseTypesSupported: ["code"],
            SubjectTypesSupported: ["public"],
            IdTokenSigningAlgValuesSupported: ["RS256"],
            ScopesSupported: ["openid", "profile"],
            TokenEndpointAuthMethodsSupported: ["none"],  // public client
            CodeChallengeMethodsSupported: ["S256"],
            DpopSigningAlgValuesSupported: ["ES256"]
        );

        return Task.FromResult(result);
    }
}
