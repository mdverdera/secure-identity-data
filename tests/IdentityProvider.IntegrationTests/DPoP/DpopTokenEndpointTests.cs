using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using FluentAssertions;
using IdentityProvider.IntegrationTests.Helpers;

namespace IdentityProvider.IntegrationTests.DPoP;

/// <summary>
/// Integration tests for DPoP proof handling at the IdentityProvider.Api token endpoint.
///
/// Tests cover:
/// - Token issued with valid DPoP proof → token_type = "DPoP" and cnf.jkt present
/// - Token issued without DPoP proof → token_type = "Bearer" (existing flow unchanged)
/// - DPoP proof with wrong htm → 400 Bad Request
/// - DPoP proof with unsupported alg → 400 Bad Request
/// - Expired DPoP proof → 400 Bad Request
/// - Discovery document shows dpop_signing_alg_values_supported
/// </summary>
public sealed class DpopTokenEndpointTests : IClassFixture<IdentityProviderFactory>
{
    private readonly HttpClient _client;

    public DpopTokenEndpointTests(IdentityProviderFactory factory)
    {
        _client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Token_WithValidDpopProof_ReturnsDpopTokenType()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = DpopProofHelper.CreateProof(dpopKey, htm: "POST",
            htu: "https://localhost:7001/oauth/token");

        var response = await PostTokenWithDpopAsync(code, verifier, proof);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("token_type").GetString().Should()
            .Be("DPoP", "a DPoP proof was supplied so the token must be DPoP-bound");
        json.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Token_WithValidDpopProof_AccessTokenContainsCnfJkt()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = DpopProofHelper.CreateProof(dpopKey, htm: "POST",
            htu: "https://localhost:7001/oauth/token");

        var response = await PostTokenWithDpopAsync(code, verifier, proof);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json        = await response.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = json.GetProperty("access_token").GetString()!;

        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(accessToken);

        var cnfClaim = jwt.Claims.FirstOrDefault(c => c.Type == "cnf");
        cnfClaim.Should().NotBeNull("DPoP-bound token must have a cnf claim");

        var cnf = JsonDocument.Parse(cnfClaim!.Value);
        cnf.RootElement.TryGetProperty("jkt", out var jktEl).Should().BeTrue("cnf must have jkt");
        jktEl.GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Token_WithoutDpopProof_ReturnsBearerTokenType()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        var response = await PostTokenAsync(code, verifier);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    // ── Discovery ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_ContainsDpopSigningAlgValuesSupported()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.TryGetProperty("dpop_signing_alg_values_supported", out var dpopAlgs)
            .Should().BeTrue("discovery must advertise DPoP alg support");

        dpopAlgs.EnumerateArray()
            .Select(e => e.GetString())
            .Should().Contain("ES256");
    }

    // ── Failure modes ────────────────────────────────────────────────────────

    [Fact]
    public async Task Token_WithDpopProofWrongHtm_ReturnsBadRequest()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Build proof with htm=GET instead of POST
        var proof = DpopProofHelper.CreateProof(dpopKey, htm: "GET",
            htu: "https://localhost:7001/oauth/token");

        var response = await PostTokenWithDpopAsync(code, verifier, proof);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task Token_WithDpopProofWrongAlg_ReturnsBadRequest()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Build proof with alg=RS256 — not in allowed list
        var proof = DpopProofHelper.CreateProof(dpopKey, htm: "POST",
            htu: "https://localhost:7001/oauth/token", alg: "RS256");

        var response = await PostTokenWithDpopAsync(code, verifier, proof);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task Token_WithExpiredDpopProof_ReturnsBadRequest()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        using var dpopKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Build proof with iat 10 minutes in the past — exceeds MaximumAgeSeconds (300 s) + skew
        var expired = DateTimeOffset.UtcNow.AddMinutes(-11).ToUnixTimeSeconds();
        var proof = DpopProofHelper.CreateProof(dpopKey, htm: "POST",
            htu: "https://localhost:7001/oauth/token", overrideIat: expired);

        var response = await PostTokenWithDpopAsync(code, verifier, proof);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<(string code, string verifier)> GetAuthorizationCodeAsync()
    {
        var verifier  = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);
        var url = $"/oauth/authorize" +
                  $"?client_id=secure-demo-client" +
                  $"&redirect_uri={Uri.EscapeDataString("https://localhost:3000/callback")}" +
                  $"&response_type=code" +
                  $"&scope={Uri.EscapeDataString("openid profile")}" +
                  $"&state=dpop-test-state" +
                  $"&code_challenge={Uri.EscapeDataString(challenge)}" +
                  $"&code_challenge_method=S256";

        var redirect = await _client.GetAsync(url);
        redirect.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var query = HttpUtility.ParseQueryString(redirect.Headers.Location!.Query);
        return (query["code"]!, verifier);
    }

    private Task<HttpResponseMessage> PostTokenAsync(string code, string verifier)
    {
        return _client.PostAsync("/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "authorization_code",
                ["code"]          = code,
                ["redirect_uri"]  = "https://localhost:3000/callback",
                ["client_id"]     = "secure-demo-client",
                ["code_verifier"] = verifier,
            }));
    }

    private Task<HttpResponseMessage> PostTokenWithDpopAsync(
        string code, string verifier, string dpopProof)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "authorization_code",
                ["code"]          = code,
                ["redirect_uri"]  = "https://localhost:3000/callback",
                ["client_id"]     = "secure-demo-client",
                ["code_verifier"] = verifier,
            }),
        };
        request.Headers.Add("DPoP", dpopProof);
        return _client.SendAsync(request);
    }
}

/// <summary>
/// Minimal DPoP proof builder for IdentityProvider integration tests.
/// Produces a real ES256-signed "dpop+jwt" for the happy path, and
/// configurable overrides for negative tests.
/// </summary>
internal static class DpopProofHelper
{
    public static string CreateProof(
        ECDsa   key,
        string  htm,
        string  htu,
        string  alg         = "ES256",
        long?   overrideIat = null)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);
        var x = Base64UrlEncode(parameters.Q.X!);
        var y = Base64UrlEncode(parameters.Q.Y!);

        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = alg,
            ["jwk"] = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"]   = x,
                ["y"]   = y,
            },
        };

        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString(),
            ["htm"] = htm,
            ["htu"] = htu,
            ["iat"] = overrideIat ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        var headerB64  = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        var signingInput = $"{headerB64}.{payloadB64}";

        if (alg == "ES256")
        {
            var sig = key.SignData(
                Encoding.ASCII.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return $"{signingInput}.{Base64UrlEncode(sig)}";
        }

        // For unsupported alg tests: random/invalid signature so the proof is structurally
        // valid (parseable) but will fail signature/alg validation.
        var dummy = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(dummy);
        return $"{signingInput}.{Base64UrlEncode(dummy)}";
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
