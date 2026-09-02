namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// Thrown when a DPoP proof JWT fails validation.
/// The exception message contains a human-readable reason code but NEVER includes
/// the raw proof JWT, access token, or any private key material.
/// </summary>
public sealed class DpopValidationException : Exception
{
    /// <summary>
    /// A short machine-readable error code suitable for an OAuth error response.
    /// </summary>
    public string ErrorCode { get; }

    private DpopValidationException(string errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>Proof is structurally invalid (e.g. not parseable as a JWT).</summary>
    public static DpopValidationException InvalidProof(string reason) =>
        new("invalid_dpop_proof", $"Invalid DPoP proof: {reason}");

    /// <summary>JWT signature verification failed.</summary>
    public static DpopValidationException InvalidSignature() =>
        new("invalid_dpop_proof", "DPoP proof signature is invalid.");

    /// <summary>The <c>alg</c> header value is not in the allowed algorithms list.</summary>
    public static DpopValidationException InvalidAlgorithm(string alg) =>
        new("invalid_dpop_proof", $"DPoP proof algorithm '{alg}' is not permitted.");

    /// <summary>A required claim is absent from the proof payload or header.</summary>
    public static DpopValidationException MissingClaim(string claimName) =>
        new("invalid_dpop_proof", $"Required DPoP proof claim '{claimName}' is missing.");

    /// <summary>The <c>htm</c> claim does not match the expected HTTP method.</summary>
    public static DpopValidationException InvalidHtm() =>
        new("invalid_dpop_proof", "DPoP proof 'htm' does not match the request method.");

    /// <summary>The <c>htu</c> claim does not match the expected request URI.</summary>
    public static DpopValidationException InvalidHtu() =>
        new("invalid_dpop_proof", "DPoP proof 'htu' does not match the request URI.");

    /// <summary>The <c>iat</c> claim is outside the acceptable window.</summary>
    public static DpopValidationException ExpiredProof() =>
        new("invalid_dpop_proof", "DPoP proof 'iat' is outside the acceptable time window.");

    /// <summary>The <c>ath</c> claim is missing when an access token is expected.</summary>
    public static DpopValidationException MissingAth() =>
        new("invalid_dpop_proof", "DPoP proof 'ath' claim is missing.");

    /// <summary>The <c>ath</c> claim does not match the hash of the access token.</summary>
    public static DpopValidationException InvalidAth() =>
        new("invalid_dpop_proof", "DPoP proof 'ath' does not match the access token hash.");

    /// <summary>A previously seen JTI has been replayed.</summary>
    public static DpopValidationException ReplayedProof() =>
        new("invalid_dpop_proof", "DPoP proof 'jti' has already been used (replay detected).");

    /// <summary>The proof public key does not match the binding in the access token.</summary>
    public static DpopValidationException KeyMismatch() =>
        new("invalid_dpop_proof", "DPoP proof public key does not match the access token binding.");
}
