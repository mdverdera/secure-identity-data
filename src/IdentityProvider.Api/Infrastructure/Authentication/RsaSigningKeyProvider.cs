using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace IdentityProvider.Api.Infrastructure.Authentication;

/// <summary>
/// Generates and holds an in-memory RSA key pair for Phase 1 local development.
///
/// IMPORTANT — Production deployment notes:
/// In production this class must be replaced with an implementation that:
///   1. Loads the RSA private key from AWS KMS / Secrets Manager (or equivalent).
///   2. Never writes raw private key bytes to disk, logs, or environment variables.
///   3. Rotates keys on a defined schedule and maintains multiple valid public keys
///      in the JWKS endpoint to allow zero-downtime rotation.
///
/// The in-memory key generated here is ephemeral — it is re-generated on every
/// application restart and is ONLY suitable for local development and testing.
/// </summary>
public sealed class RsaSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly RSA _rsa;
    private bool _disposed;

    public string KeyId { get; }

    public RsaSigningKeyProvider()
    {
        // 2048-bit RSA — minimum recommended for RS256 in modern applications.
        _rsa = RSA.Create(keySizeInBits: 2048);
        // Deterministic kid derived from the public key thumbprint.
        KeyId = ComputeKeyId(_rsa);
    }

    /// <inheritdoc />
    public RsaSecurityKey GetSigningKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new RsaSecurityKey(_rsa) { KeyId = KeyId };
    }

    /// <inheritdoc />
    public RsaSecurityKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Export only the public parameters — never include private components.
        var publicParams = _rsa.ExportParameters(includePrivateParameters: false);
        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(publicParams);
        return new RsaSecurityKey(publicRsa) { KeyId = KeyId };
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _rsa.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    /// Computes a stable key ID from the SHA-256 thumbprint of the public key modulus.
    /// This approach means the kid changes when the key changes (correct behaviour).
    /// </summary>
    private static string ComputeKeyId(RSA rsa)
    {
        var publicParams = rsa.ExportParameters(includePrivateParameters: false);
        var modulus = publicParams.Modulus ?? [];
        var hash = System.Security.Cryptography.SHA256.HashData(modulus);
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_')[..16]; // Use first 16 chars for a compact kid
    }
}
