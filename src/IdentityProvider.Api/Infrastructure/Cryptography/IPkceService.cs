namespace IdentityProvider.Api.Infrastructure.Cryptography;

/// <summary>
/// Provides PKCE (Proof Key for Code Exchange) operations following RFC 7636.
/// Only the S256 code challenge method is supported; the "plain" method is
/// explicitly rejected as it provides no meaningful security benefit.
/// </summary>
public interface IPkceService
{
    /// <summary>
    /// Computes the S256 code challenge for a given code verifier.
    /// Challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    /// </summary>
    string GenerateCodeChallenge(string codeVerifier);

    /// <summary>
    /// Validates a code verifier against a stored S256 code challenge.
    /// Returns true if the verifier produces the same challenge; false otherwise.
    /// </summary>
    bool ValidateCodeVerifier(string codeVerifier, string storedCodeChallenge);
}
