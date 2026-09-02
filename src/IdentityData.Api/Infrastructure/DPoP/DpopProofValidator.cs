using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// Validates the complete RFC 9449 DPoP proof chain for a resource-server request.
/// Extends token-endpoint validation with <c>ath</c>, <c>cnf.jkt</c>, and replay checks.
/// </summary>
public interface IDpopProofValidator
{
    /// <summary>
    /// Validates the complete RFC 9449 DPoP chain for a resource request.
    /// </summary>
    /// <param name="proofJwt">The DPoP proof JWT from the DPoP header.</param>
    /// <param name="accessToken">The raw access token string from the Authorization header.</param>
    /// <param name="expectedHtm">Expected HTTP method.</param>
    /// <param name="expectedHtu">Expected HTTP target URI (scheme + host + path).</param>
    /// <param name="cnfJkt">The <c>cnf.jkt</c> value from the access token.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="DpopValidationException">Thrown for any validation failure.</exception>
    Task ValidateAsync(
        string proofJwt,
        string accessToken,
        string expectedHtm,
        string expectedHtu,
        string cnfJkt,
        CancellationToken ct = default);
}

/// <summary>
/// Default implementation of <see cref="IDpopProofValidator"/> for the resource server.
/// Performs structural, signature, claim, ath, replay, and key-binding checks.
/// </summary>
public sealed class DpopProofValidator : IDpopProofValidator
{
    private readonly DpopOptions _options;
    private readonly IDpopReplayStore _replayStore;
    private readonly IJwkThumbprintService _thumbprintService;

    /// <param name="options">DPoP timing and algorithm configuration.</param>
    /// <param name="replayStore">JTI replay store.</param>
    /// <param name="thumbprintService">JWK thumbprint calculator.</param>
    public DpopProofValidator(
        DpopOptions options,
        IDpopReplayStore replayStore,
        IJwkThumbprintService thumbprintService)
    {
        _options           = options;
        _replayStore       = replayStore;
        _thumbprintService = thumbprintService;
    }

    /// <inheritdoc />
    public async Task ValidateAsync(
        string proofJwt,
        string accessToken,
        string expectedHtm,
        string expectedHtu,
        string cnfJkt,
        CancellationToken ct = default)
    {
        // === Step 1: Structural validation (same as token-endpoint validator) ===

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

        // Verify typ == "dpop+jwt".
        var typ = jwt.Typ;
        if (!string.Equals(typ, DpopProofClaims.DpopTyp, StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidProof($"Expected typ '{DpopProofClaims.DpopTyp}', got '{typ}'.");

        // Verify alg is in the allowed list.
        var alg = jwt.Alg;
        if (!_options.SigningAlgorithms.Contains(alg, StringComparer.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidAlgorithm(alg);

        // Extract and validate jwk header.
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

        // Reconstruct ECDsa public key.
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

        // Validate signature.
        var securityKey = new ECDsaSecurityKey(ecdsa);
        var tvp = new TokenValidationParameters
        {
            ValidateIssuer      = false,
            ValidateAudience    = false,
            ValidateLifetime    = false,
            ValidTypes          = [DpopProofClaims.DpopTyp],
            IssuerSigningKey    = securityKey,
            RequireSignedTokens = true,
        };

        TokenValidationResult sigResult;
        try
        {
            var handler = new JsonWebTokenHandler();
            sigResult = await handler.ValidateTokenAsync(proofJwt, tvp).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw DpopValidationException.InvalidProof($"Token validation error: {ex.Message}");
        }

        if (!sigResult.IsValid)
            throw DpopValidationException.InvalidSignature();

        // Verify required payload claims.
        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrWhiteSpace(jti))
            throw DpopValidationException.MissingClaim("jti");

        if (!jwt.TryGetPayloadValue<string>("htm", out var htm) || string.IsNullOrWhiteSpace(htm))
            throw DpopValidationException.MissingClaim("htm");

        if (!jwt.TryGetPayloadValue<string>("htu", out var htu) || string.IsNullOrWhiteSpace(htu))
            throw DpopValidationException.MissingClaim("htu");

        if (!jwt.TryGetPayloadValue<long>("iat", out var iat))
        {
            if (!jwt.TryGetPayloadValue<int>("iat", out var iatInt))
                throw DpopValidationException.MissingClaim("iat");
            iat = iatInt;
        }

        // Verify htm.
        if (!string.Equals(htm.Trim(), expectedHtm.Trim(), StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidHtm();

        // Verify htu (scheme + authority + path only).
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

        var htuNorm        = $"{htuUri.Scheme}://{htuUri.Authority}{htuUri.AbsolutePath}".TrimEnd('/');
        var expectedHtuNorm = $"{expectedHtuUri.Scheme}://{expectedHtuUri.Authority}{expectedHtuUri.AbsolutePath}".TrimEnd('/');
        if (!string.Equals(htuNorm, expectedHtuNorm, StringComparison.OrdinalIgnoreCase))
            throw DpopValidationException.InvalidHtu();

        // Verify iat is within window.
        var now       = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var notBefore = now - _options.MaximumAgeSeconds - _options.ClockSkewSeconds;
        var notAfter  = now + _options.ClockSkewSeconds;
        if (iat < notBefore || iat > notAfter)
            throw DpopValidationException.ExpiredProof();

        // === Step 2: Validate ath (access token hash) ===
        if (!jwt.TryGetPayloadValue<string>("ath", out var ath) || string.IsNullOrWhiteSpace(ath))
            throw DpopValidationException.MissingAth();

        var tokenBytes = Encoding.ASCII.GetBytes(accessToken);
        var hashBytes  = SHA256.HashData(tokenBytes);
        var expected   = JwkThumbprintService.Base64UrlEncode(hashBytes);

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(ath),
                Encoding.ASCII.GetBytes(expected)))
        {
            throw DpopValidationException.InvalidAth();
        }

        // === Step 3: Replay check ===
        if (await _replayStore.HasBeenUsedAsync(jti, ct).ConfigureAwait(false))
            throw DpopValidationException.ReplayedProof();

        // === Step 4: Compute proof public key thumbprint ===
        var crv        = headerJwk.Crv ?? "P-256";
        var thumbprint = _thumbprintService.ComputeThumbprint(crv, headerJwk.X, headerJwk.Y);

        // === Step 5: Compare with cnf.jkt ===
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(thumbprint),
                Encoding.ASCII.GetBytes(cnfJkt)))
        {
            throw DpopValidationException.KeyMismatch();
        }

        // === Step 6: Mark JTI as used ===
        var expiryOffset = DateTimeOffset.FromUnixTimeSeconds(iat)
            .AddSeconds(_options.MaximumAgeSeconds + _options.ClockSkewSeconds);

        await _replayStore.MarkAsUsedAsync(jti, expiryOffset, ct).ConfigureAwait(false);
    }

    private static byte[] Base64UrlDecode(string value)
    {
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
