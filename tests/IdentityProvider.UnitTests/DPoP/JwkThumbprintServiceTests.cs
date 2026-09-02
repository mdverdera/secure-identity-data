using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using IdentityProvider.Api.Infrastructure.DPoP;

namespace IdentityProvider.UnitTests.DPoP;

/// <summary>
/// Unit tests for <see cref="JwkThumbprintService"/> (RFC 7638 compliance).
/// </summary>
public sealed class JwkThumbprintServiceTests
{
    private readonly JwkThumbprintService _sut = new();

    // A fixed P-256 key pair generated once for deterministic testing.
    // x and y are the Base64URL-encoded coordinates of an arbitrary P-256 public key.
    private const string TestCrv = "P-256";
    private const string TestX   = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    private const string TestY   = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    [Fact]
    public void SameKey_AlwaysProducesSameThumbprint()
    {
        var first  = _sut.ComputeThumbprint(TestCrv, TestX, TestY);
        var second = _sut.ComputeThumbprint(TestCrv, TestX, TestY);

        first.Should().Be(second);
    }

    [Fact]
    public void DifferentKeys_ProduceDifferentThumbprints()
    {
        // Generate two real P-256 key pairs and extract their JWK coordinates.
        var (crv1, x1, y1) = GenerateP256JwkCoords();
        var (crv2, x2, y2) = GenerateP256JwkCoords();

        var t1 = _sut.ComputeThumbprint(crv1, x1, y1);
        var t2 = _sut.ComputeThumbprint(crv2, x2, y2);

        // The chance of collision is negligible; if this fails, the RNG is broken.
        t1.Should().NotBe(t2);
    }

    [Fact]
    public void CanonicalJson_UsesLexicographicMemberOrder()
    {
        // RFC 7638 §3: for EC the required members in order are crv, kty, x, y.
        // We verify by recomputing manually and comparing.
        var canonical = JsonSerializer.Serialize(new SortedDictionary<string, string>
        {
            ["crv"] = TestCrv,
            ["kty"] = "EC",
            ["x"]   = TestX,
            ["y"]   = TestY,
        });

        // The serialised string must start with {"crv": (lowest member lexicographically).
        canonical.Should().StartWith("{\"crv\":");

        // Verify kty comes before x, and x comes before y.
        var ktyIndex = canonical.IndexOf("\"kty\"", StringComparison.Ordinal);
        var xIndex   = canonical.IndexOf("\"x\"",   StringComparison.Ordinal);
        var yIndex   = canonical.IndexOf("\"y\"",   StringComparison.Ordinal);

        ktyIndex.Should().BeLessThan(xIndex);
        xIndex.Should().BeLessThan(yIndex);

        // The thumbprint must equal Base64URL(SHA256(UTF8(canonical))).
        var expected = Base64UrlEncode(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(canonical)));

        _sut.ComputeThumbprint(TestCrv, TestX, TestY).Should().Be(expected);
    }

    [Fact]
    public void Result_IsValidBase64Url_WithNoPadding()
    {
        var thumbprint = _sut.ComputeThumbprint(TestCrv, TestX, TestY);

        thumbprint.Should().NotContain("=");
        thumbprint.Should().NotContain("+");
        thumbprint.Should().NotContain("/");
    }

    [Fact]
    public void KnownVector_IsStable_AcrossInstances()
    {
        // Verify that two independent service instances produce the same thumbprint for
        // the same fixed key, confirming the implementation is deterministic and canonical.
        var sut2 = new JwkThumbprintService();

        var t1 = _sut.ComputeThumbprint(TestCrv, TestX, TestY);
        var t2 = sut2.ComputeThumbprint(TestCrv, TestX, TestY);

        t1.Should().Be(t2);
        t1.Should().NotBeNullOrWhiteSpace();
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private static (string crv, string x, string y) GenerateP256JwkCoords()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters  = ecdsa.ExportParameters(includePrivateParameters: false);
        return (
            "P-256",
            Base64UrlEncode(parameters.Q.X!),
            Base64UrlEncode(parameters.Q.Y!)
        );
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
