using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Api.Infrastructure.DPoP;

/// <summary>
/// Validates a DPoP proof JWT presented at the token endpoint (RFC 9449 §4.2).
/// At the token endpoint no access token exists yet, so <c>ath</c> is not validated.
/// </summary>
public interface IDpopProofValidator
{
    /// <summary>
    /// Validates a DPoP proof JWT for use at the token endpoint.
    /// </summary>
    /// <param name="proofJwt">The raw DPoP proof JWT string.</param>
    /// <param name="expectedHtm">Expected HTTP method (e.g. "POST").</param>
    /// <param name="expectedHtu">Expected HTTP URI (scheme + host + path only).</param>
    /// <returns>The extracted public JWK (kty, crv, x, y) on success.</returns>
    /// <exception cref="DpopValidationException">Thrown for any validation failure.</exception>
    DpopPublicKey ValidateProof(string proofJwt, string expectedHtm, string expectedHtu);
}

/// <summary>
/// Default implementation of <see cref="IDpopProofValidator"/> for the token endpoint.
/// Validates structure, algorithm, signature, required claims, htm, htu, and iat.
/// Does NOT validate <c>ath</c> (no access token at the token endpoint).
/// </summary>
public sealed class DpopProofValidator : IDpopProofValidator
{
    private readonly DpopOptions _options;

    /// <param name="options">DPoP timing and algorithm configuration.</param>
    public DpopProofValidator(DpopOptions options)
    {
        _options = options;
    }

    /// <inheritdoc />
    public DpopPublicKey ValidateProof(string proofJwt, string expectedHtm, string expectedHtu)
    {
        // Step 1 — Parse header to read typ, alg and jwk before full token validation.
        JsonWebToken jwt;
        try
        {
            var handler = new JsonWebTokenHandler();
            jwt = handler.ReadJsonWebToken(proofJwt);
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"JWT could not be parsed: {ex.Message}");
        }

        // Step 1 — Verify typ == "dpop+jwt" (case-insensitive).
        var typ = jwt.Typ;
        if (!string.Equals(typ, DpopProofClaims.DpopTyp, StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidProof($"Expected typ '{DpopProofClaims.DpopTyp}', got '{typ}'.");

        // Step 2 — Verify alg is in the allowed list.
        var alg = jwt.Alg;
        if (!_options.SigningAlgorithms.Contains(alg, StringComparer.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidAlgorithm(alg);

        // Step 3 — Extract jwk from header; must be present, must be EC, must NOT have a private key.
        if (!jwt.TryGetHeaderValue<JsonElement>("jwk", out var jwkElement))
            throw DpopValidationException.MissingClaim("jwk");

        var jwkJson = jwkElement.GetRawText();
        JsonWebKey headerJwk;
        try
        {
            headerJwk = JsonWebKey.Create(jwkJson);
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"Header 'jwk' could not be parsed: {ex.Message}");
        }

        if (!string.Equals(headerJwk.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidProof("Header 'jwk' must be an EC key (kty=EC).");

        if (!string.IsNullOrEmpty(headerJwk.D))
            throw DpopValidationException.InvalidProof("Header 'jwk' must not contain a private key parameter 'd'.");

        if (string.IsNullOrEmpty(headerJwk.X) || string.IsNullOrEmpty(headerJwk.Y))
            throw DpopValidationException.InvalidProof("Header 'jwk' is missing EC coordinates.");

        // Step 4 — Reconstruct ECDsa public key from JWK x/y.
        ECDsa ecdsa;
        try
        {
            var xBytes = Base64UrlDecode(headerJwk.X);
            var yBytes = Base64UrlDecode(headerJwk.Y);
            ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q     = new ECPoint { X = xBytes, Y = yBytes },
            });
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"Could not reconstruct EC public key: {ex.Message}");
        }

        // Step 5 — Validate signature.
        var securityKey = new ECDsaSecurityKey(ecdsa);
        var tvp = new TokenValidationParameters
        {
            ValidateIssuer           = false,
            ValidateAudience         = false,
            ValidateLifetime         = false, // iat validated manually below
            ValidTypes               = [DpopProofClaims.DpopTyp],
            IssuerSigningKey         = securityKey,
            RequireSignedTokens      = true,
        };

        TokenValidationResult result;
        try
        {
            var handler = new JsonWebTokenHandler();
            result = handler.ValidateTokenAsync(proofJwt, tvp).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"Token validation error: {ex.Message}");
        }

        if (!result.IsValid)
            throw DpopValidationException.InvalidSignature();

        // Step 6 — Verify required payload claims.
        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
            throw DpopValidationException.MissingClaim("jti");

        if (!jwt.TryGetPayloadValue<string>("htm", out var htm) || string.IsNullOrWhiteSpace(htm))
            throw DpopValidationException.MissingClaim("htm");

        if (!jwt.TryGetPayloadValue<string>("htu", out var htu) || string.IsNullOrWhiteSpace(htu))
            throw DpopValidationException.MissingClaim("htu");

        if (!jwt.TryGetPayloadValue<long>("iat", out var iat))
        {
            // Some serialisers store iat as int; try int fallback
            if (!jwt.TryGetPayloadValue<int>("iat", out var iatInt))
                throw DpopValidationException.MissingClaim("iat");
            iat = iatInt;
        }

        // Step 7 — Verify htm (case-insensitive).
        if (!string.Equals(htm.Trim(), expectedHtm.Trim(), StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidHtm();

        // Step 8 — Verify htu: compare scheme + authority + path only.
        Uri htuUri;
        Uri expectedHtuUri;
        try
        {
            htuUri        = new Uri(htu,         UriKind.Absolute);
            expectedHtuUri = new Uri(expectedHtu, UriKind.Absolute);
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"'htu' is not a valid absolute URI: {ex.Message}");
        }

        // Compare scheme + authority + path (no query, no fragment).
        var htuNorm        = $"{htuUri.Scheme}://{htuUri.Authority}{htuUri.AbsolutePath}".TrimEnd('/');
        var expectedHtuNorm = $"{expectedHtuUri.Scheme}://{expectedHtuUri.Authority}{expectedHtuUri.AbsolutePath}".TrimEnd('/');
        if (!string.Equals(htuNorm, expectedHtuNorm, StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidHtu();

        // Step 9 — Verify iat is within [now - MaxAge - Skew, now + Skew].
        var now       = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var notBefore = now - _options.MaximumAgeSeconds - _options.ClockSkewSeconds;
        var notAfter  = now + _options.ClockSkewSeconds;
        if (iat < notBefore || iat > notAfter)
            throw DpopValidationException.ExpiredProof();

        // Step 10 — Return public key.
        return new DpopPublicKey(
            Kty: headerJwk.Kty,
            Crv: headerJwk.Crv ?? "P-256",
            X:   headerJwk.X,
            Y:   headerJwk.Y);
    }

    private static byte[] Base64UrlDecode(string value)
    {
        // Restore Base64 padding
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = (base64.Length % 4) switch
        {
            2 => base64 + "==",
            3 => base64 + "=",
            _ => base64,
        };
        return Convert.FromBase64String(base64);
    }
}
