using FluentAssertions;
using IdentityData.Api.Infrastructure.DPoP;

namespace IdentityData.UnitTests.DPoP;

/// <summary>
/// Tests that <see cref="DpopProofValidator"/> correctly enforces key binding via
/// <c>cnf.jkt</c>: the thumbprint of the public key embedded in the proof header must
/// match the <c>cnf.jkt</c> claim extracted from the access token.
/// </summary>
public sealed class KeyBindingTests
{
    private const string ValidHtm        = "GET";
    private const string ValidHtu        = "https://localhost:7002/identity/attributes";
    private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.token";

    private readonly DpopOptions            _options           = new();
    private readonly InMemoryDpopReplayStore _replayStore       = new();
    private readonly JwkThumbprintService   _thumbprintService = new();
    private readonly DpopProofValidator     _sut;

    public KeyBindingTests()
    {
        _sut = new DpopProofValidator(_options, _replayStore, _thumbprintService);
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Proof signed with the same key recorded in cnf.jkt should pass key-binding.
    /// </summary>
    [Fact]
    public async Task ValidCnfJkt_MatchingKey_ValidationPasses()
    {
        var builder = new DpopProofBuilder();
        builder.IncludeAth = true;

        var (x, y, crv) = builder.GetPublicJwk();
        var cnfJkt = _thumbprintService.ComputeThumbprint(crv, x, y);

        var proof = builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(proof, ValidAccessToken, ValidHtm, ValidHtu, cnfJkt);

        await act.Should().NotThrowAsync();
    }

    /// <summary>
    /// Explicit test: when the proof's embedded public key matches cnf.jkt exactly, the
    /// key-binding check must succeed.
    /// </summary>
    [Fact]
    public async Task MatchingDpopPublicKey_ValidationPasses()
    {
        var builder = new DpopProofBuilder();
        builder.IncludeAth = true;

        var (x, y, crv) = builder.GetPublicJwk();
        var cnfJkt = _thumbprintService.ComputeThumbprint(crv, x, y);

        var proof = builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(proof, ValidAccessToken, ValidHtm, ValidHtu, cnfJkt);

        await act.Should().NotThrowAsync("the proof key matches the token binding");
    }

    // ── Negative tests ─────────────────────────────────────────────────────────

    /// <summary>
    /// When the proof is signed with a different key than the one bound in cnf.jkt, the
    /// validator must throw with a key-mismatch error.
    /// </summary>
    [Fact]
    public async Task MismatchedDpopPublicKey_ThrowsKeyMismatch()
    {
        // builder1 produces the proof; builder2 produces the cnf.jkt.
        var builder1 = new DpopProofBuilder();
        var builder2 = new DpopProofBuilder();

        builder1.IncludeAth = true;

        // cnf.jkt is computed from builder2's key — intentionally different.
        var (x2, y2, crv2) = builder2.GetPublicJwk();
        var cnfJkt = _thumbprintService.ComputeThumbprint(crv2, x2, y2);

        var proof = builder1.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(proof, ValidAccessToken, ValidHtm, ValidHtu, cnfJkt);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.ErrorCode == "invalid_dpop_proof",
                "a key mismatch is always an invalid_dpop_proof error");
    }

    /// <summary>
    /// When cnf.jkt is an empty string (simulates a missing / null cnf claim in the token),
    /// the validator must reject the proof.
    /// </summary>
    [Fact]
    public async Task MissingCnfJkt_EmptyString_Rejected()
    {
        var builder = new DpopProofBuilder();
        builder.IncludeAth = true;

        var proof = builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        // Pass an empty cnfJkt — simulates a caller that found no cnf.jkt in the token.
        var act = () => _sut.ValidateAsync(proof, ValidAccessToken, ValidHtm, ValidHtu, cnfJkt: "");

        await act.Should().ThrowAsync<DpopValidationException>();
    }

    /// <summary>
    /// When the cnf.jkt value supplied does not match any valid thumbprint format
    /// (simulates a token whose cnf claim exists but has no <c>jkt</c> field), the
    /// validator must reject the proof.
    /// </summary>
    [Fact]
    public async Task CnfWithoutJkt_InvalidThumbprint_Rejected()
    {
        var builder = new DpopProofBuilder();
        builder.IncludeAth = true;

        var proof = builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        // Pass a clearly wrong/absent jkt value — bytes that can never match any real thumbprint.
        var act = () => _sut.ValidateAsync(proof, ValidAccessToken, ValidHtm, ValidHtu,
            cnfJkt: DpopProofBuilder.Base64UrlEncode(new byte[32]));

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.ErrorCode == "invalid_dpop_proof");
    }
}
