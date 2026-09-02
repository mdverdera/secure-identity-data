namespace IdentityProvider.Api.Infrastructure.DPoP;

/// <summary>Claim names defined by RFC 9449 for DPoP proof JWTs.</summary>
public static class DpopProofClaims
{
    /// <summary>HTTP method (uppercase), e.g. "POST".</summary>
    public const string Htm = "htm";

    /// <summary>HTTP target URI (scheme + authority + path, no query or fragment).</summary>
    public const string Htu = "htu";

    /// <summary>
    /// Access token hash: Base64URL(SHA-256(ASCII(access_token))).
    /// Present on resource-server requests; absent at the token endpoint.
    /// </summary>
    public const string Ath = "ath";

    /// <summary>Required <c>typ</c> header value for DPoP proof JWTs.</summary>
    public const string DpopTyp = "dpop+jwt";
}
