using FluentAssertions;
using IdentityData.Api.Infrastructure.DPoP;

namespace IdentityData.UnitTests.DPoP;

/// <summary>
/// Tests that <see cref="DpopProofValidator"/> correctly validates the <c>ath</c>
/// (access token hash) claim: SHA-256(ASCII(accessToken)), Base64URL-encoded.
/// </summary>
public sealed class AccessTokenHashTests
{
    private const string ValidHtm        = "GET";
    private const string ValidHtu        = "https://localhost:7002/identity/attributes";
    private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.token";

    private readonly DpopOptions            _options;
    private readonly InMemoryDpopReplayStore _replayStore;
    private readonly JwkThumbprintService   _thumbprintService;
    private readonly DpopProofValidator     _sut;
    private readonly DpopProofBuilder       _builder;

    public AccessTokenHashTests()
    {
        _options           = new DpopOptions();
        _replayStore       = new InMemoryDpopReplayStore();
        _thumbprintService = new JwkThumbprintService();
        _sut               = new DpopProofValidator(_options, _replayStore, _thumbprintService);
        _builder           = new DpopProofBuilder();
    }

    private string ValidCnfJkt()
    {
        var (x, y, crv) = _builder.GetPublicJwk();
        return _thumbprintService.ComputeThumbprint(crv, x, y);
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    /// <summary>
    /// When <c>ath</c> equals SHA256(ASCII(accessToken)) encoded as Base64URL, the proof must
    /// be accepted.
    /// </summary>
    [Fact]
    public async Task CorrectAth_ValidationPasses()
    {
        // IncludeAth = true causes the builder to compute SHA256(ASCII(accessToken)) internally.
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(
            proof, ValidAccessToken, ValidHtm, ValidHtu, ValidCnfJkt());

        await act.Should().NotThrowAsync();
    }

    // ── Negative tests ─────────────────────────────────────────────────────────

    /// <summary>
    /// When <c>ath</c> is the hash of a different access token (or a tampered value), the
    /// validator must throw with an <c>ath</c>-related error.
    /// </summary>
    [Fact]
    public async Task IncorrectAth_WrongHash_ThrowsInvalidAth()
    {
        // Override with the hash of a completely different token.
        _builder.OverrideAth = DpopProofBuilder.ComputeAth("some-other-token-that-is-not-the-real-one");
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(
            proof, ValidAccessToken, ValidHtm, ValidHtu, ValidCnfJkt());

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("ath"),
                "ath mismatch must be reported via the ath claim in the error message");
    }

    /// <summary>
    /// When the proof carries no <c>ath</c> claim but an access token is provided, the
    /// validator must throw (access token binding is mandatory for resource-server requests).
    /// </summary>
    [Fact]
    public async Task MissingAthWhenRequired_ThrowsMissingAth()
    {
        // Default: IncludeAth = false, no OverrideAth → no ath claim in proof.
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(
            proof, ValidAccessToken, ValidHtm, ValidHtu, ValidCnfJkt());

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("ath"),
                "the missing ath claim must be the reported reason for rejection");
    }
}
