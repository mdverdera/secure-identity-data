namespace IdentityProvider.Api.Infrastructure.DPoP;

/// <summary>
/// The extracted EC public key from a validated DPoP proof header JWK.
/// </summary>
/// <param name="Kty">Key type, always "EC" for DPoP proofs using ES256.</param>
/// <param name="Crv">Curve name, e.g. "P-256".</param>
/// <param name="X">Base64URL-encoded X coordinate.</param>
/// <param name="Y">Base64URL-encoded Y coordinate.</param>
public sealed record DpopPublicKey(string Kty, string Crv, string X, string Y);
