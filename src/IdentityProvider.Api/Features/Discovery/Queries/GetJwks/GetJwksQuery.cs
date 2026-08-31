using MediatR;

namespace IdentityProvider.Api.Features.Discovery.Queries.GetJwks;

/// <summary>
/// Query: return the JSON Web Key Set containing the public RSA signing key.
/// Only public parameters are included — never the private key.
/// </summary>
public sealed record GetJwksQuery : IRequest<JwksResult>;

/// <summary>
/// Represents the JWKS response document.
/// </summary>
public sealed record JwksResult(IReadOnlyList<JsonWebKeyDto> Keys);

/// <summary>
/// A single public JSON Web Key (RSA, public parameters only).
/// </summary>
public sealed record JsonWebKeyDto(
    string Kty,
    string Use,
    string Alg,
    string Kid,
    string N,
    string E
);
