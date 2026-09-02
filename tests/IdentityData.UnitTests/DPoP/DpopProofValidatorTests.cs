using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using IdentityData.Api.Infrastructure.DPoP;

namespace IdentityData.UnitTests.DPoP;

/// <summary>
/// Unit tests for <see cref="DpopProofValidator"/> — the full RFC 9449 resource-server validator.
/// </summary>
public sealed class DpopProofValidatorTests
{
    private const string ValidHtm        = "GET";
    private const string ValidHtu        = "https://localhost:7002/identity/attributes";
    private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.token";

    private readonly DpopOptions            _options;
    private readonly InMemoryDpopReplayStore _replayStore;
    private readonly JwkThumbprintService   _thumbprintService;
    private readonly DpopProofValidator     _sut;
    private readonly DpopProofBuilder       _builder;

    public DpopProofValidatorTests()
    {
        _options           = new DpopOptions();
        _replayStore       = new InMemoryDpopReplayStore();
        _thumbprintService = new JwkThumbprintService();
        _sut               = new DpopProofValidator(_options, _replayStore, _thumbprintService);
        _builder           = new DpopProofBuilder();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private string ValidCnfJkt()
    {
        var (x, y, crv) = _builder.GetPublicJwk();
        return _thumbprintService.ComputeThumbprint(crv, x, y);
    }

    private async Task ValidateAsync(string proof, string? accessToken = null, string? cnfJkt = null)
        => await _sut.ValidateAsync(
            proofJwt:     proof,
            accessToken:  accessToken ?? ValidAccessToken,
            expectedHtm:  ValidHtm,
            expectedHtu:  ValidHtu,
            cnfJkt:       cnfJkt ?? ValidCnfJkt());

    // ── Happy path ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidProof_Accepted()
    {
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().NotThrowAsync();
    }

    // ── Algorithm / type checks ────────────────────────────────────────────────

    [Fact]
    public async Task WrongAlgorithm_RS256_Rejected()
    {
        _builder.Alg     = "RS256";
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.ErrorCode == "invalid_dpop_proof");
    }

    [Fact]
    public async Task TypNotDpopJwt_Rejected()
    {
        _builder.Typ     = "JWT";
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("typ"));
    }

    // ── Required claim checks ──────────────────────────────────────────────────

    [Fact]
    public async Task MissingJti_Rejected()
    {
        _builder.IncludeJti = false;
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("jti"));
    }

    [Fact]
    public async Task MissingHtm_Rejected()
    {
        _builder.IncludeHtm = false;
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("htm"));
    }

    [Fact]
    public async Task MissingHtu_Rejected()
    {
        _builder.IncludeHtu = false;
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("htu"));
    }

    [Fact]
    public async Task MissingIat_Rejected()
    {
        _builder.IncludeIat = false;
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("iat"));
    }

    // ── iat / expiry checks ───────────────────────────────────────────────────

    [Fact]
    public async Task ExpiredIat_TooOld_Rejected()
    {
        // iat > MaximumAgeSeconds + ClockSkewSeconds ago
        _builder.OverrideIat = DateTimeOffset.UtcNow
            .AddSeconds(-(_options.MaximumAgeSeconds + _options.ClockSkewSeconds + 10))
            .ToUnixTimeSeconds();
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("iat"));
    }

    [Fact]
    public async Task FutureIat_BeyondSkew_Rejected()
    {
        // iat > ClockSkewSeconds in the future
        _builder.OverrideIat = DateTimeOffset.UtcNow
            .AddSeconds(_options.ClockSkewSeconds + 10)
            .ToUnixTimeSeconds();
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("iat"));
    }

    // ── htm / htu checks ──────────────────────────────────────────────────────

    [Fact]
    public async Task HtmMismatch_Rejected()
    {
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: "DELETE", htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("htm"));
    }

    [Fact]
    public async Task HtuMismatch_Rejected()
    {
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: "https://evil.example.com/steal", accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("htu"));
    }

    // ── Signature check ──────────────────────────────────────────────────────

    [Fact]
    public async Task InvalidSignature_Rejected()
    {
        _builder.IncludeAth = true;
        var validProof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        // Tamper with the signature (last segment).
        var parts      = validProof.Split('.');
        parts[2]       = DpopProofBuilder.Base64UrlEncode(new byte[64]); // zeros, not a valid sig
        var tampered   = string.Join('.', parts);

        var act = () => ValidateAsync(tampered, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>();
    }

    // ── Private key in JWK ────────────────────────────────────────────────────

    [Fact]
    public async Task PrivateKeyInJwk_Rejected()
    {
        _builder.IncludePrivateKey = true;
        _builder.IncludeAth        = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("private"));
    }

    // ── ath checks ────────────────────────────────────────────────────────────

    [Fact]
    public async Task CorrectAth_Accepted()
    {
        _builder.IncludeAth = true;
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task IncorrectAth_Rejected()
    {
        _builder.OverrideAth = DpopProofBuilder.Base64UrlEncode(new byte[32]); // wrong hash
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("ath"));
    }

    [Fact]
    public async Task MissingAth_Rejected()
    {
        // IncludeAth = false (default) and no OverrideAth → ath claim absent.
        var proof = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => ValidateAsync(proof, ValidAccessToken);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("ath"));
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    [Fact]
    public async Task ReplayedJti_Rejected()
    {
        var sharedJti    = Guid.NewGuid().ToString();
        _builder.IncludeAth = true;

        // First use of the same jti.
        _builder.OverrideJti = sharedJti;
        var proof1 = _builder.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);
        await _sut.ValidateAsync(proof1, ValidAccessToken, ValidHtm, ValidHtu, ValidCnfJkt());

        // Second use must be rejected.
        // Build a new proof token with the same jti but a distinct signature.
        var builder2 = new DpopProofBuilder();
        // We need cnfJkt to match builder2's key; use builder2's key for this proof
        var (x2, y2, crv2) = builder2.GetPublicJwk();
        var cnfJkt2 = _thumbprintService.ComputeThumbprint(crv2, x2, y2);

        builder2.OverrideJti = sharedJti;
        builder2.IncludeAth  = true;
        var proof2 = builder2.Build(htm: ValidHtm, htu: ValidHtu, accessToken: ValidAccessToken);

        var act = () => _sut.ValidateAsync(proof2, ValidAccessToken, ValidHtm, ValidHtu, cnfJkt2);

        await act.Should().ThrowAsync<DpopValidationException>()
            .Where(e => e.Message.Contains("replay"));
    }
}
