using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityData.UnitTests.DPoP;

/// <summary>
/// Generates valid EC P-256 DPoP proof JWTs for use in unit tests.
/// All signing is done with real P-256 keys so the produced tokens pass
/// cryptographic verification by <c>DpopProofValidator</c>.
/// </summary>
internal sealed class DpopProofBuilder
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

    /// <summary>Override the <c>ath</c> value explicitly.</summary>
    public string? OverrideAth { get; set; }

    /// <summary>
    /// When true and <see cref="Build"/> is called with a non-null accessToken,
    /// the computed <c>ath</c> is included in the payload.
    /// </summary>
    public bool IncludeAth { get; set; } = false;

    /// <summary>Creates a builder using a freshly generated P-256 key pair.</summary>
    public DpopProofBuilder()
    {
        _ecdsa        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publicParams = _ecdsa.ExportParameters(includePrivateParameters: false);
    }

    /// <summary>Creates a builder reusing an existing P-256 ECDsa instance.</summary>
    public DpopProofBuilder(ECDsa ecdsa)
    {
        _ecdsa        = ecdsa;
        _publicParams = ecdsa.ExportParameters(includePrivateParameters: false);
    }

    // ── Public helpers ────────────────────────────────────────────────────────

    /// <summary>Returns the Base64URL-encoded X, Y and the curve name for the public key.</summary>
    public (string X, string Y, string Crv) GetPublicJwk() => (
        Base64UrlEncode(_publicParams.Q.X!),
        Base64UrlEncode(_publicParams.Q.Y!),
        "P-256"
    );

    /// <summary>Computes the access-token hash expected in the <c>ath</c> claim.</summary>
    public static string ComputeAth(string accessToken)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncode(bytes);
    }

    /// <summary>Builds and signs a DPoP proof JWT.</summary>
    /// <param name="htm">HTTP method for the <c>htm</c> claim.</param>
    /// <param name="htu">HTTP target URI for the <c>htu</c> claim.</param>
    /// <param name="accessToken">When supplied (and <see cref="IncludeAth"/> is true), the <c>ath</c> claim is added.</param>
    public string Build(
        string htm = "POST",
        string htu = "https://localhost:7002/connect/token",
        string? accessToken = null)
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

        if (OverrideAth is not null)
            payload["ath"] = OverrideAth;
        else if (IncludeAth && accessToken is not null)
            payload["ath"] = ComputeAth(accessToken);

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
            // Sign with IEEE P1363 format (r || s), which is what JsonWebTokenHandler expects for ES256.
            var inputBytes = Encoding.ASCII.GetBytes(signingInput);
            var sig = _ecdsa.SignData(inputBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return Base64UrlEncode(sig);
        }

        if (Alg == "RS256")
        {
            // For negative test: produce a random/invalid signature so the proof will be rejected.
            var dummy = new byte[256];
            RandomNumberGenerator.Fill(dummy);
            return Base64UrlEncode(dummy);
        }

        // Unknown alg: return empty signature.
        return Base64UrlEncode(new byte[64]);
    }

    internal static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
