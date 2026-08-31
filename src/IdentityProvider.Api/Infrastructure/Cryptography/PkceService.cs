using System.Security.Cryptography;
using System.Text;

namespace IdentityProvider.Api.Infrastructure.Cryptography;

/// <summary>
/// RFC 7636 S256 PKCE implementation.
/// code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
/// </summary>
public sealed class PkceService : IPkceService
{
    /// <inheritdoc />
    public string GenerateCodeChallenge(string codeVerifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier);

        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    /// <inheritdoc />
    public bool ValidateCodeVerifier(string codeVerifier, string storedCodeChallenge)
    {
        if (string.IsNullOrWhiteSpace(codeVerifier) ||
            string.IsNullOrWhiteSpace(storedCodeChallenge))
        {
            return false;
        }

        var computed = GenerateCodeChallenge(codeVerifier);

        // Constant-time comparison to prevent timing attacks
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computed),
            Encoding.ASCII.GetBytes(storedCodeChallenge));
    }

    // RFC 4648 §5 base64url encoding (no padding)
    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
