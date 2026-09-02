using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityProvider.UnitTests.DPoP;

/// <summary>
/// Generates valid EC P-256 DPoP proof JWTs for use in IdentityProvider unit tests.
/// Targets the token-endpoint validator (<c>DpopProofValidator.ValidateProof</c>) which
/// does NOT require an <c>ath</c> claim.
/// All signing is done with real P-256 keys so the produced tokens pass cryptographic
/// verification. Every configurable property maps directly to an override needed by a
/// specific negative test scenario.
/// </summary>
internal sealed class DpopTestProofBuilder
{
    private readonly ECDsa _ecdsa;
    private readonly ECParameters _publicParams;

    // ── Configurable header / payload overrides ──────────────────────────────

    /// <summary>JWT <c>typ</c> header. Default: "dpop+jwt".</summary>
    public string Typ { get; set; } = "dpop+jwt";

    /// <summary>JWT <c>alg</c> header. Default: "ES256".</summary>
    public string Alg { get; set; } = "ES256";

    /// <summary>When true, includes the private 'd' coordinate in the header JWK.</summary>
    public bool IncludePrivateKey { get; set; } = false;

    /// <summary>When false, the <c>jwk</c> header is omitted.</summary>
    public bool IncludeJwk { get; set; } = true;

    /// <summary>Override the <c>jti</c> claim value. Null = auto-generate.</summary>
    public string? OverrideJti { get; set; }

    /// <summary>When false, the <c>jti</c> claim is omitted entirely.</summary>
    public bool IncludeJti { get; set; } = true;

    /// <summary>Override the <c>htm</c> claim. Null = use the Build() argument.</summary>
    public string? OverrideHtm { get; set; }

    /// <summary>When false, the <c>htm</c> claim is omitted.</summary>
    public bool IncludeHtm { get; set; } = true;

    /// <summary>Override the <c>htu</c> claim. Null = use the Build() argument.</summary>
    public string? OverrideHtu { get; set; }

    /// <summary>When false, the <c>htu</c> claim is omitted.</summary>
    public bool IncludeHtu { get; set; } = true;

    /// <summary>Override the <c>iat</c> Unix timestamp. Null = now.</summary>
    public long? OverrideIat { get; set; }

    /// <summary>When false, the <c>iat</c> claim is omitted.</summary>
    public bool IncludeIat { get; set; } = true;

    /// <summary>Creates a builder using a freshly generated P-256 key pair.</summary>
    public DpopTestProofBuilder()
    {
        _ecdsa        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publicParams = _ecdsa.ExportParameters(includePrivateParameters: false);
    }

    /// <summary>Creates a builder reusing an existing P-256 ECDsa instance.</summary>
    public DpopTestProofBuilder(ECDsa ecdsa)
    {
        _ecdsa        = ecdsa;
        _publicParams = ecdsa.ExportParameters(includePrivateParameters: false);
    }

    // ── Public helpers ────────────────────────────────────────────────────────

    /// <summary>Returns the Base64URL-encoded X, Y and curve name for the public key.</summary>
    public (string X, string Y, string Crv) GetPublicJwk() => (
        Base64UrlEncode(_publicParams.Q.X!),
        Base64UrlEncode(_publicParams.Q.Y!),
        "P-256"
    );

    /// <summary>Builds and signs a DPoP proof JWT.</summary>
    /// <param name="htm">HTTP method for the <c>htm</c> claim.</param>
    /// <param name="htu">HTTP target URI for the <c>htu</c> claim.</param>
    public string Build(
        string htm = "POST",
        string htu = "https://localhost:7001/oauth/token")
    {
        var now = OverrideIat ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // ── Header ──────────────────────────────────────────────────────────
        var header = new Dictionary<string, object>
        {
            ["typ"] = Typ,
            ["alg"] = Alg,
        };

        if (IncludeJwk)
            header["jwk"] = BuildJwkObject();

        // ── Payload ─────────────────────────────────────────────────────────
        var payload = new Dictionary<string, object>();

        if (IncludeJti)
            payload["jti"] = OverrideJti ?? Guid.NewGuid().ToString();

        if (IncludeHtm)
            payload["htm"] = OverrideHtm ?? htm;

        if (IncludeHtu)
            payload["htu"] = OverrideHtu ?? htu;

        if (IncludeIat)
            payload["iat"] = now;

        // ── Encode header + payload ──────────────────────────────────────────
        var headerB64  = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        var signingInput = $"{headerB64}.{payloadB64}";

        // ── Sign ─────────────────────────────────────────────────────────────
        var sigB64 = ComputeSignature(signingInput);

        return $"{signingInput}.{sigB64}";
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private object BuildJwkObject()
    {
        var jwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"]   = Base64UrlEncode(_publicParams.Q.X!),
            ["y"]   = Base64UrlEncode(_publicParams.Q.Y!),
        };

        if (IncludePrivateKey)
        {
            var priv = _ecdsa.ExportParameters(includePrivateParameters: true);
            jwk["d"] = Base64UrlEncode(priv.D!);
        }

        return jwk;
    }

    private string ComputeSignature(string signingInput)
    {
        if (Alg == "ES256")
        {
            var inputBytes = Encoding.ASCII.GetBytes(signingInput);
            var sig = _ecdsa.SignData(
                inputBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return Base64UrlEncode(sig);
        }

        if (Alg == "RS256")
        {
            // For negative test: produce a random/invalid signature so the proof is rejected.
            var dummy = new byte[256];
            RandomNumberGenerator.Fill(dummy);
            return Base64UrlEncode(dummy);
        }

        // Unknown alg: return a dummy signature.
        return Base64UrlEncode(new byte[64]);
    }

    internal static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
