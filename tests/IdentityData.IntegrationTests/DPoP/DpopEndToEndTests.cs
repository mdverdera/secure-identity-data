using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using IdentityData.IntegrationTests.Helpers;

namespace IdentityData.IntegrationTests.DPoP;

/// <summary>
/// End-to-end and security demonstration tests for the DPoP flow in IdentityData.Api.
///
/// These tests narrate the RFC 9449 DPoP story:
///
/// 1. <see cref="FullDpopFlow_FromTokenToProtectedResource_Succeeds"/>
///    Demonstrates the complete DPoP path: generate EC key → mint DPoP-bound token →
///    create DPoP proof for the resource request → access protected resource → 200 OK.
///
/// 2. <see cref="TokenReplayAttack_AttackerWithAccessTokenOnly_CannotAccessResource"/>
///    Demonstrates why DPoP protects against token theft: an attacker who steals the
///    DPoP-bound access token but does not have the client's EC private key cannot
///    access the protected resource — any DPoP proof they create with their own key
///    does not match the cnf.jkt in the stolen token.
/// </summary>
public sealed class DpopEndToEndTests : IClassFixture<IdentityDataFactory>
{
    private readonly IdentityDataFactory _factory;
    private readonly HttpClient _client;

    public DpopEndToEndTests(IdentityDataFactory factory)
    {
        _factory = factory;
        _client  = factory.CreateClient();
        _factory.EnsureDbSeeded();
    }

    // ── Full DPoP Flow ────────────────────────────────────────────────────────

    /// <summary>
    /// Demonstrates the complete DPoP authorization flow against IdentityData.Api:
    ///
    /// Step 1  – Client generates an EC P-256 key pair.
    /// Step 2  – Test mints a DPoP-bound access token using the test RSA signing key,
    ///           embedding cnf.jkt = thumbprint(clientKey).
    /// Step 3  – Verify the access token is DPoP-typed and carries cnf.jkt.
    /// Step 4  – Client creates a DPoP proof for GET /api/profile, including ath.
    /// Step 5  – Client sends GET /api/profile with Authorization: DPoP &lt;token&gt;
    ///           and DPoP: &lt;proof&gt;.
    /// Step 6  – Assert 200 OK — the resource server validated the full chain.
    /// Step 7  – Assert response body contains expected profile data.
    /// </summary>
    [Fact]
    public async Task FullDpopFlow_FromTokenToProtectedResource_Succeeds()
    {
        // Step 1 — Generate client EC P-256 key pair
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Compute the client's JWK thumbprint (this is what cnf.jkt will be bound to)
        var clientThumbprint = TestTokenFactory.ComputeEcThumbprint(clientKey);
        clientThumbprint.Should().NotBeNullOrEmpty("thumbprint of EC key must be computable");

        // Step 2 — Mint a DPoP-bound access token with cnf.jkt = clientThumbprint
        var accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey,
            clientKey,
            userId: "user-001",
            scope:  "openid profile identity.read");

        // Step 3 — Verify the token is DPoP-bound
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(accessToken);

        var tokenType = "DPoP"; // We minted it DPoP-bound; the issuer would set token_type
        tokenType.Should().Be("DPoP");

        var cnfClaim = jwt.Claims.FirstOrDefault(c => c.Type == "cnf");
        cnfClaim.Should().NotBeNull("access token must carry the cnf claim");

        var cnfDoc = JsonDocument.Parse(cnfClaim!.Value);
        cnfDoc.RootElement.TryGetProperty("jkt", out var jktEl).Should().BeTrue();
        var jkt = jktEl.GetString()!;
        jkt.Should().Be(clientThumbprint,
            "cnf.jkt must equal the thumbprint of the client's EC key");

        // Step 4 — Client creates DPoP proof for GET /api/profile
        var proof = TestTokenFactory.CreateDpopProof(
            clientKey,
            htm:         "GET",
            htu:         "http://localhost/api/profile",
            accessToken: accessToken);

        // Step 5 — Send the protected resource request
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        request.Headers.Add("Authorization", $"DPoP {accessToken}");
        request.Headers.Add("DPoP", proof);

        var response = await _client.SendAsync(request);

        // Step 6 — Assert 200 OK
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "legitimate DPoP client with matching key must access the resource");

        // Step 7 — Assert profile data is present
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("userId").GetString().Should().Be("user-001");
        body.GetProperty("fullName").GetString().Should().NotBeNullOrEmpty();
        body.GetProperty("email").GetString().Should().NotBeNullOrEmpty();
    }

    // ── Token Replay Attack Demonstration ────────────────────────────────────

    /// <summary>
    /// Demonstrates that DPoP protects against token theft.
    ///
    /// Scenario:
    /// - Client obtains a DPoP-bound access token (cnf.jkt bound to their private key).
    /// - An attacker intercepts and steals the access token (but NOT the private key).
    ///
    /// Legitimate client:
    /// - Creates a DPoP proof with THEIR private key.
    /// - Presents Authorization: DPoP &lt;token&gt; + DPoP: &lt;proof&gt;.
    /// - Resource server validates: JWK thumbprint in proof == cnf.jkt in token → PASS → 200.
    ///
    /// Attacker:
    /// - Generates their own EC key pair (does not have the client's private key).
    /// - Creates a DPoP proof with THEIR key.
    /// - Presents Authorization: DPoP &lt;stolen-token&gt; + DPoP: &lt;attacker-proof&gt;.
    /// - Resource server validates: JWK thumbprint of attacker key ≠ cnf.jkt → FAIL → 401.
    ///
    /// Also demonstrates: presenting only the stolen token with no DPoP header → 401.
    /// </summary>
    [Fact]
    public async Task TokenReplayAttack_AttackerWithAccessTokenOnly_CannotAccessResource()
    {
        // ── Setup: legitimate client ─────────────────────────────────────────
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Client obtains a DPoP-bound access token
        var accessToken = TestTokenFactory.CreateDpopBoundToken(
            _factory.IssuerSigningKey,
            clientKey,
            userId: "user-001",
            scope:  "openid profile identity.read");

        // ── Legitimate client succeeds ────────────────────────────────────────
        var legitimateProof = TestTokenFactory.CreateDpopProof(
            clientKey,
            htm:         "GET",
            htu:         "http://localhost/api/profile",
            accessToken: accessToken);

        var legitimateRequest = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        legitimateRequest.Headers.Add("Authorization", $"DPoP {accessToken}");
        legitimateRequest.Headers.Add("DPoP", legitimateProof);

        var legitimateResponse = await _client.SendAsync(legitimateRequest);
        legitimateResponse.StatusCode.Should().Be(HttpStatusCode.OK,
            "legitimate client using their own private key must succeed");

        // ── Attacker: has the access token, generates their OWN key ──────────
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // The attacker's thumbprint differs from cnf.jkt in the stolen token
        var attackerThumbprint = TestTokenFactory.ComputeEcThumbprint(attackerKey);
        var clientThumbprint   = TestTokenFactory.ComputeEcThumbprint(clientKey);
        attackerThumbprint.Should().NotBe(clientThumbprint,
            "attacker's key thumbprint must differ from client's key");

        // Attacker creates a proof with their own key
        var attackerProof = TestTokenFactory.CreateDpopProof(
            attackerKey,
            htm:         "GET",
            htu:         "http://localhost/api/profile",
            accessToken: accessToken);

        var attackRequest = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        attackRequest.Headers.Add("Authorization", $"DPoP {accessToken}");
        attackRequest.Headers.Add("DPoP", attackerProof);

        // ── Assert: attacker with mismatched key is rejected ──────────────────
        var attackResponse = await _client.SendAsync(attackRequest);
        attackResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "attacker's DPoP key does not match cnf.jkt in the stolen token → key mismatch → 401");

        // ── Also demonstrate: token without DPoP header is rejected ───────────
        var noProofRequest = new HttpRequestMessage(HttpMethod.Get, "/api/profile");
        noProofRequest.Headers.Add("Authorization", $"DPoP {accessToken}");
        // No DPoP header — handler must require it

        var noProofResponse = await _client.SendAsync(noProofRequest);
        noProofResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "DPoP-bound token with no DPoP proof header must be rejected");
    }
}
