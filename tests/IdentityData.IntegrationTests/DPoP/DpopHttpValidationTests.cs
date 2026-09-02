using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using IdentityData.IntegrationTests.Helpers;

namespace IdentityData.IntegrationTests.DPoP;

/// <summary>
/// HTTP-level integration tests for DPoP validation in IdentityData.Api.
///
/// Each test stands alone — the factory is shared via IClassFixture but each test
/// uses a fresh EC key pair so JTI replay state does not leak between tests.
///
/// Test matrix:
/// ✓ Valid GET /api/profile with DPoP-bound token + valid proof → 200
/// ✓ Valid GET /api/identity with DPoP-bound token + valid proof → 200
/// ✓ DPoP proof htm=GET used on POST request → 401
/// ✓ DPoP proof for /api/profile used on /api/identity → 401
/// ✓ Reused DPoP proof (same jti twice) → second request 401
/// ✓ DPoP-bound token presented as Bearer → 401
/// ✓ DPoP token with scope missing identity.read → 403
/// ✓ Plain Bearer token (no cnf.jkt) on Bearer scheme → 200
/// ✓ Plain Bearer token presented with DPoP header → 401 (cnf missing → DPoP rejects)
/// ✓ Fully valid DPoP request with correct ath → 200
/// </summary>
public sealed class DpopHttpValidationTests : IClassFixture<IdentityDataFactory>
{
    private readonly IdentityDataFactory _factory;
    private readonly HttpClient _client;

    public DpopHttpValidationTests(IdentityDataFactory factory)
    {
        _factory = factory;
        _client  = factory.CreateClient();
        _factory.EnsureDbSeeded();
    }

    // ── Valid DPoP requests ────────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_WithValidDpopToken_Returns200()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetIdentity_WithValidDpopToken_Returns200()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/identity",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/identity",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetProfile_WithValidDpopAndCorrectAth_Returns200()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        // ath is always included by CreateDpopProof when accessToken is supplied
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "correct ath and valid cnf.jkt binding should succeed");
    }

    // ── htm mismatch ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_ProofHasWrongHtm_Returns401()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        // Proof says htm=POST but the actual request is GET
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "POST", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "htm mismatch must be rejected");
    }

    // ── htu mismatch ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetIdentity_ProofIssuedForProfile_Returns401()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        // Proof is for /api/profile but request goes to /api/identity
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/identity",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "htu mismatch must be rejected");
    }

    // ── Replay attack ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_ReusedDpopProof_SecondRequestReturns401()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);
        var jti   = Guid.NewGuid().ToString();
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken, overrideJti: jti);

        // First request — must succeed
        var first = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);
        first.StatusCode.Should().Be(HttpStatusCode.OK, "first use of proof must succeed");

        // Second request — same proof JTI must be rejected
        var second = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);
        second.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "replayed JTI must be rejected by the replay store");
    }

    // ── Token downgrade attack ─────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_DpopBoundTokenPresentedAsBearer_Returns401()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey);

        // Present DPoP-bound token under Bearer scheme — must be rejected
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        request.Headers.Add("Authorization", $"Bearer {accessToken}");

        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "DPoP-bound token must not be accepted under Bearer scheme");
    }

    // ── Scope enforcement ──────────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_DpopTokenMissingIdentityReadScope_Returns403()
    {
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey, dpopKey,
            scope: "openid profile"); // identity.read intentionally absent
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "missing identity.read scope must produce 403");
    }

    // ── Bearer scheme (no cnf) ─────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_PlainBearerToken_Returns200()
    {
        var accessToken = TestTokenFactory.CreateBearerToken(_factory.IssuerSigningKey);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        request.Headers.Add("Authorization", $"Bearer {accessToken}");

        var response = await _client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "a valid plain Bearer token (no cnf.jkt) should be accepted on the Bearer scheme");
    }

    [Fact]
    public async Task GetProfile_PlainBearerTokenWithDpopHeader_Returns401()
    {
        // A plain Bearer token has no cnf.jkt — when presented under the DPoP scheme
        // the DPoP handler must reject it because cnf.jkt is required for DPoP.
        using var dpopKey    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       accessToken = TestTokenFactory.CreateBearerToken(_factory.IssuerSigningKey);
        var proof = TestTokenFactory.CreateDpopProof(
            dpopKey, htm: "GET", htu: "http://localhost/api/profile",
            accessToken: accessToken);

        var response = await SendWithDpopAsync(HttpMethod.Get, "/api/profile",
            accessToken, proof, scheme: "DPoP");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "a token without cnf.jkt must be rejected by the DPoP handler");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Task<HttpResponseMessage> SendWithDpopAsync(
        HttpMethod method,
        string     requestUri,
        string     accessToken,
        string     dpopProof,
        string     scheme = "DPoP")
    {
        var request = new HttpRequestMessage(method, requestUri);
        request.Headers.Add("Authorization", $"{scheme} {accessToken}");
        request.Headers.Add("DPoP", dpopProof);
        return _client.SendAsync(request);
    }
}
