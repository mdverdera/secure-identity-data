using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityData.Api.Infrastructure.DPoP;

/// <summary>
/// Computes JWK thumbprints as defined in RFC 7638.
/// </summary>
public interface IJwkThumbprintService
{
    /// <summary>
    /// Computes the JWK thumbprint (RFC 7638) for an EC P-256 public key.
    /// The canonical JSON form is <c>{"crv":"P-256","kty":"EC","x":"…","y":"…"}</c>
    /// (members in lexicographic order, no whitespace).
    /// Returns Base64URL(SHA-256(UTF-8(canonical_json))).
    /// The same public key always produces the same thumbprint.
    /// </summary>
    /// <param name="crv">Curve name, e.g. "P-256".</param>
    /// <param name="x">Base64URL-encoded X coordinate.</param>
    /// <param name="y">Base64URL-encoded Y coordinate.</param>
    string ComputeThumbprint(string crv, string x, string y);
}

/// <summary>
/// Default implementation of <see cref="IJwkThumbprintService"/>.
/// Produces a SHA-256 thumbprint over the RFC 7638 canonical JSON representation
/// of an EC public key.
/// </summary>
public sealed class JwkThumbprintService : IJwkThumbprintService
{
    /// <inheritdoc />
    public string ComputeThumbprint(string crv, string x, string y)
    {
        // RFC 7638 §3: members in lexicographic order, no whitespace.
        // For EC P-256: {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
        var canonical = JsonSerializer.Serialize(new SortedDictionary<string, string>
        {
            ["crv"] = crv,
            ["kty"] = "EC",
            ["x"]   = x,
            ["y"]   = y,
        });

        var utf8 = Encoding.UTF8.GetBytes(canonical);
        var hash = SHA256.HashData(utf8);
        return Base64UrlEncode(hash);
    }

    internal static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
