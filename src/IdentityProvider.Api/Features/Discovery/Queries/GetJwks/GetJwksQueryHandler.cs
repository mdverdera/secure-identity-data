using System.Security.Cryptography;
using IdentityProvider.Api.Infrastructure.Authentication;
using MediatR;

namespace IdentityProvider.Api.Features.Discovery.Queries.GetJwks;

/// <summary>
/// Handles the JWKS query by exporting only the public RSA key parameters.
/// Private key components (d, p, q, dp, dq, qi) are NEVER included.
/// </summary>
public sealed class GetJwksQueryHandler : IRequestHandler<GetJwksQuery, JwksResult>
{
    private readonly ISigningKeyProvider _signingKeyProvider;

    public GetJwksQueryHandler(ISigningKeyProvider signingKeyProvider)
    {
        _signingKeyProvider = signingKeyProvider;
    }

    public Task<JwksResult> Handle(GetJwksQuery request, CancellationToken cancellationToken)
    {
        var publicKey = _signingKeyProvider.GetPublicKey();
        var rsaKey = publicKey.Rsa ?? throw new InvalidOperationException("Public RSA key is unavailable.");

        var parameters = rsaKey.ExportParameters(includePrivateParameters: false);

        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            throw new InvalidOperationException("RSA public key parameters are missing.");
        }

        var jwk = new JsonWebKeyDto(
            Kty: "RSA",
            Use: "sig",
            Alg: "RS256",
            Kid: _signingKeyProvider.KeyId,
            N: Base64UrlEncode(parameters.Modulus),
            E: Base64UrlEncode(parameters.Exponent)
        );

        return Task.FromResult(new JwksResult([jwk]));
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
