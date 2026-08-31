using FluentAssertions;
using IdentityProvider.Api.Infrastructure.Cryptography;

namespace IdentityProvider.UnitTests.Cryptography;

public sealed class PkceServiceTests
{
    private readonly PkceService _sut = new();

    // ── GenerateCodeChallenge ──────────────────────────────────────────────────

    [Fact]
    public void GenerateCodeChallenge_WithValidVerifier_ReturnsSha256Base64UrlHash()
    {
        // The RFC 7636 Appendix B test vector:
        // verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        var challenge = _sut.GenerateCodeChallenge(verifier);

        challenge.Should().Be(expectedChallenge);
    }

    [Fact]
    public void GenerateCodeChallenge_ProducesBase64UrlEncoding_NoPlus_NoSlash_NoPadding()
    {
        var challenge = _sut.GenerateCodeChallenge("any-valid-verifier-string-at-least-43chars-xxxx");

        challenge.Should().NotContain("+");
        challenge.Should().NotContain("/");
        challenge.Should().NotContain("=");
    }

    [Fact]
    public void GenerateCodeChallenge_SameVerifier_ProducesSameChallenge()
    {
        const string verifier = "test-verifier-that-is-long-enough-to-meet-rfc-7636-requirements";

        var challenge1 = _sut.GenerateCodeChallenge(verifier);
        var challenge2 = _sut.GenerateCodeChallenge(verifier);

        challenge1.Should().Be(challenge2);
    }

    [Fact]
    public void GenerateCodeChallenge_DifferentVerifiers_ProduceDifferentChallenges()
    {
        var challenge1 = _sut.GenerateCodeChallenge("verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var challenge2 = _sut.GenerateCodeChallenge("verifier-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        challenge1.Should().NotBe(challenge2);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void GenerateCodeChallenge_EmptyOrWhitespace_Throws(string verifier)
    {
        var act = () => _sut.GenerateCodeChallenge(verifier);

        act.Should().Throw<ArgumentException>();
    }

    // ── ValidateCodeVerifier ───────────────────────────────────────────────────

    [Fact]
    public void ValidateCodeVerifier_CorrectVerifier_ReturnsTrue()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = _sut.GenerateCodeChallenge(verifier);

        var result = _sut.ValidateCodeVerifier(verifier, challenge);

        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateCodeVerifier_WrongVerifier_ReturnsFalse()
    {
        const string correctVerifier = "correct-verifier-that-is-long-enough-rfc7636-xx";
        const string wrongVerifier   = "wrong-verifier-that-is-long-enough-rfc7636-xxxx";
        var challenge = _sut.GenerateCodeChallenge(correctVerifier);

        var result = _sut.ValidateCodeVerifier(wrongVerifier, challenge);

        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("", "some-challenge")]
    [InlineData(" ", "some-challenge")]
    [InlineData("some-verifier-long-enough-yes-at-least-43-chars", "")]
    [InlineData("some-verifier-long-enough-yes-at-least-43-chars", " ")]
    public void ValidateCodeVerifier_EmptyOrWhitespace_ReturnsFalse(string verifier, string challenge)
    {
        var result = _sut.ValidateCodeVerifier(verifier, challenge);

        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateCodeVerifier_TamperedChallenge_ReturnsFalse()
    {
        const string verifier = "some-verifier-long-enough-yes-at-least-43-chars";
        var challenge = _sut.GenerateCodeChallenge(verifier);
        var tamperedChallenge = challenge[..^1] + "X"; // flip last char

        var result = _sut.ValidateCodeVerifier(verifier, tamperedChallenge);

        result.Should().BeFalse();
    }
}
