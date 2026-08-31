using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using FluentAssertions;
using IdentityProvider.IntegrationTests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using IdentityProvider.Api.Infrastructure.Authentication;

namespace IdentityProvider.IntegrationTests;

/// <summary>
/// End-to-end integration tests for the complete OAuth Authorization Code + PKCE flow.
/// These tests host the real application pipeline in-process using WebApplicationFactory.
/// </summary>
public sealed class OAuthFlowIntegrationTests : IClassFixture<IdentityProviderFactory>
{
    private readonly HttpClient _client;
    private readonly IdentityProviderFactory _factory;

    public OAuthFlowIntegrationTests(IdentityProviderFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false, // We need to inspect the redirect manually
        });
    }

    // ── Discovery endpoints ───────────────────────────────────────────────────

    [Fact]
    public async Task GetOpenIdConfiguration_ReturnsDiscoveryDocument()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Contain("json");

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();

        json.GetProperty("issuer").GetString().Should().NotBeNullOrEmpty();
        json.GetProperty("authorization_endpoint").GetString().Should().Contain("/oauth/authorize");
        json.GetProperty("token_endpoint").GetString().Should().Contain("/oauth/token");
        json.GetProperty("jwks_uri").GetString().Should().Contain("/.well-known/jwks.json");
        json.GetProperty("code_challenge_methods_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Contain("S256");
        json.GetProperty("response_types_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Contain("code");
    }

    [Fact]
    public async Task GetJwks_ReturnsPublicKeyOnly()
    {
        var response = await _client.GetAsync("/.well-known/jwks.json");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var keys = json.GetProperty("keys").EnumerateArray().ToList();

        keys.Should().HaveCount(1);
        var key = keys[0];

        key.GetProperty("kty").GetString().Should().Be("RSA");
        key.GetProperty("use").GetString().Should().Be("sig");
        key.GetProperty("alg").GetString().Should().Be("RS256");
        key.GetProperty("kid").GetString().Should().NotBeNullOrEmpty();
        key.GetProperty("n").GetString().Should().NotBeNullOrEmpty();
        key.GetProperty("e").GetString().Should().NotBeNullOrEmpty();

        // Private parameters must NOT be present
        key.TryGetProperty("d", out _).Should().BeFalse("private exponent must never be exposed");
        key.TryGetProperty("p", out _).Should().BeFalse("private parameter p must never be exposed");
        key.TryGetProperty("q", out _).Should().BeFalse("private parameter q must never be exposed");
    }

    // ── Authorization endpoint ────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_ValidRequest_ReturnsRedirectWithCode()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge);
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        var location = response.Headers.Location;
        location.Should().NotBeNull();
        location!.ToString().Should().StartWith("https://localhost:3000/callback");

        var query = HttpUtility.ParseQueryString(location.Query);
        query["code"].Should().NotBeNullOrEmpty();
        query["state"].Should().Be("integration-test-state");
    }

    [Fact]
    public async Task Authorize_InvalidClientId_ReturnsBadRequest()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge, clientId: "invalid-client");
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_client");
    }

    [Fact]
    public async Task Authorize_MismatchedRedirectUri_ReturnsBadRequest()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge, redirectUri: "https://evil.example.com/callback");
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task Authorize_UnsupportedResponseType_ReturnsBadRequest()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge, responseType: "token");
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("unsupported_response_type");
    }

    [Fact]
    public async Task Authorize_MissingCodeChallenge_ReturnsBadRequest()
    {
        var url = BuildAuthorizeUrl(codeChallenge: "");
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task Authorize_UnsupportedCodeChallengeMethod_ReturnsBadRequest()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge, codeChallengeMethod: "plain");
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    // ── Token endpoint ────────────────────────────────────────────────────────

    [Fact]
    public async Task Token_ValidAuthorizationCode_ReturnsJwtAccessToken()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        var response = await PostTokenAsync(code, verifier);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        json.GetProperty("token_type").GetString().Should().Be("Bearer");
        json.GetProperty("expires_in").GetInt32().Should().BeGreaterThan(0);
        json.GetProperty("scope").GetString().Should().Be("openid profile");
    }

    [Fact]
    public async Task Token_ValidToken_ClaimsAreCorrect()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();
        var tokenResponse = await PostTokenAsync(code, verifier);
        var json = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = json.GetProperty("access_token").GetString()!;

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(accessToken);

        jwt.Issuer.Should().NotBeNullOrEmpty();
        jwt.Subject.Should().Be("user-001");
        jwt.Audiences.Should().Contain("secure-identity-data-api");
        jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value.Should().Be("openid profile");
        jwt.Id.Should().NotBeNullOrEmpty("jti claim is required");
        jwt.ValidTo.Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task Token_ValidToken_SignatureVerifiableWithJwks()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();
        var tokenResponse = await PostTokenAsync(code, verifier);
        var json = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        var accessToken = json.GetProperty("access_token").GetString()!;

        // Fetch public key from JWKS
        var keyProvider = _factory.Services.GetRequiredService<ISigningKeyProvider>();
        var publicKey = keyProvider.GetPublicKey();

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = publicKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };

        var handler = new JwtSecurityTokenHandler();
        var act = () => handler.ValidateToken(accessToken, validationParams, out _);

        act.Should().NotThrow("the token signature must be verifiable with the public key from JWKS");
    }

    [Fact]
    public async Task Token_ReplayAttack_SecondUseOfSameCodeFails()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        // First use — should succeed
        var first = await PostTokenAsync(code, verifier);
        first.StatusCode.Should().Be(HttpStatusCode.OK);

        // Second use of same code — must fail
        var second = await PostTokenAsync(code, verifier);
        second.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await second.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Token_WrongCodeVerifier_ReturnsBadRequest()
    {
        var (code, _) = await GetAuthorizationCodeAsync();

        var wrongVerifier = PkceHelper.GenerateCodeVerifier(); // Different verifier
        var response = await PostTokenAsync(code, wrongVerifier);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Token_InvalidAuthorizationCode_ReturnsBadRequest()
    {
        var response = await PostTokenAsync("nonexistent-code", PkceHelper.GenerateCodeVerifier());

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Token_WrongClientId_ReturnsBadRequest()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        var response = await PostTokenAsync(code, verifier, clientId: "wrong-client");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Token_WrongRedirectUri_ReturnsBadRequest()
    {
        var (code, verifier) = await GetAuthorizationCodeAsync();

        var response = await PostTokenAsync(code, verifier,
            redirectUri: "https://evil.example.com/callback");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Token_UnsupportedGrantType_ReturnsBadRequest()
    {
        var response = await _client.PostAsync("/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "secure-demo-client",
            }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("unsupported_grant_type");
    }

    [Fact]
    public async Task Token_MissingCodeVerifier_ReturnsBadRequest()
    {
        var (code, _) = await GetAuthorizationCodeAsync();

        var response = await _client.PostAsync("/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = "https://localhost:3000/callback",
                ["client_id"] = "secure-demo-client",
                // code_verifier intentionally omitted
            }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("error").GetString().Should().Be("invalid_request");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private string BuildAuthorizeUrl(
        string codeChallenge = "",
        string clientId = "secure-demo-client",
        string redirectUri = "https://localhost:3000/callback",
        string responseType = "code",
        string scope = "openid profile",
        string state = "integration-test-state",
        string codeChallengeMethod = "S256")
    {
        return $"/oauth/authorize" +
               $"?client_id={Uri.EscapeDataString(clientId)}" +
               $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
               $"&response_type={Uri.EscapeDataString(responseType)}" +
               $"&scope={Uri.EscapeDataString(scope)}" +
               $"&state={Uri.EscapeDataString(state)}" +
               $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
               $"&code_challenge_method={Uri.EscapeDataString(codeChallengeMethod)}";
    }

    private async Task<(string code, string verifier)> GetAuthorizationCodeAsync()
    {
        var verifier = PkceHelper.GenerateCodeVerifier();
        var challenge = PkceHelper.GenerateCodeChallenge(verifier);

        var url = BuildAuthorizeUrl(challenge);
        var response = await _client.GetAsync(url);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect,
            "authorization request should redirect to callback");

        var location = response.Headers.Location!;
        var query = HttpUtility.ParseQueryString(location.Query);
        var code = query["code"]!;

        code.Should().NotBeNullOrEmpty();
        return (code, verifier);
    }

    private Task<HttpResponseMessage> PostTokenAsync(
        string code,
        string codeVerifier,
        string clientId = "secure-demo-client",
        string redirectUri = "https://localhost:3000/callback")
    {
        return _client.PostAsync("/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = clientId,
                ["code_verifier"] = codeVerifier,
            }));
    }
}
