extern alias IdpAssembly;

using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace IdentityData.IntegrationTests;

/// <summary>
/// Full end-to-end integration test that exercises the complete OAuth 2.0 chain:
///   IdentityProvider.Api (Phase 1) → issues JWT → IdentityData.Api → JWT validation → scope check → DB → 200
///
/// Both servers run in-process via WebApplicationFactory.
/// The IdentityData.Api is configured to trust the Identity Provider's real signing key
/// (retrieved from the in-process JWK endpoint), bypassing no crypto steps.
/// </summary>
public sealed class FullFlowIntegrationTests
{
    [Fact]
    public async Task FullOAuthFlow_IssueTokenFromIdP_UseTokenOnResourceServer_Returns200()
    {
        // ── Step 1: Start IdentityProvider.Api in-process ─────────────────────
        await using var idpFactory = new InProcessIdentityProviderFactory();
        var idpClient = idpFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        // ── Step 2: Execute PKCE Authorization Code flow ───────────────────────
        var codeVerifier = PkceHelperLocal.GenerateCodeVerifier();
        var codeChallenge = PkceHelperLocal.GenerateCodeChallenge(codeVerifier);

        var authUrl = "/oauth/authorize" +
                      $"?response_type=code" +
                      $"&client_id=secure-demo-client" +
                      $"&redirect_uri={Uri.EscapeDataString("https://localhost:3000/callback")}" +
                      $"&scope={Uri.EscapeDataString("openid profile identity.read")}" +
                      $"&state=full-flow-test-state" +
                      $"&code_challenge={codeChallenge}" +
                      $"&code_challenge_method=S256";

        var authResponse = await idpClient.GetAsync(authUrl);
        authResponse.StatusCode.Should().Be(HttpStatusCode.Redirect,
            "authorization endpoint should redirect with a code");

        var location = authResponse.Headers.Location!.ToString();
        var queryString = location.Contains('?')
            ? location[location.IndexOf('?')..]
            : string.Empty;
        var queryParams = HttpUtility.ParseQueryString(queryString);
        var code = queryParams["code"];
        code.Should().NotBeNullOrEmpty("authorization code must be present in redirect");

        // ── Step 3: Exchange authorization code for access token ──────────────
        var tokenResponse = await idpClient.PostAsync("/oauth/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["redirect_uri"] = "https://localhost:3000/callback",
                ["client_id"] = "secure-demo-client",
                ["code_verifier"] = codeVerifier,
            }));

        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK,
            "token endpoint should return 200 for a valid code exchange");

        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        var tokenDoc = JsonDocument.Parse(tokenJson);
        var accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString();
        accessToken.Should().NotBeNullOrEmpty("access_token must be present in token response");

        // ── Step 4: Fetch the Identity Provider's public JWK ──────────────────
        var jwksResponse = await idpClient.GetAsync("/.well-known/jwks.json");
        jwksResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var jwksJson = await jwksResponse.Content.ReadAsStringAsync();
        var keySet = new JsonWebKeySet(jwksJson);
        var signingKeys = keySet.GetSigningKeys();
        signingKeys.Should().NotBeEmpty("IdP must expose at least one public key in JWKS");

        // ── Step 5: Start IdentityData.Api, trusting the IdP's key ────────────
        await using var resourceFactory = new FullFlowIdentityDataFactory(signingKeys);
        var resourceClient = resourceFactory.CreateClient();

        resourceClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        // ── Step 6: Call the protected profile endpoint ────────────────────────
        var profileResponse = await resourceClient.GetAsync("/api/profile");

        profileResponse.StatusCode.Should().Be(HttpStatusCode.OK,
            "a real JWT from the Identity Provider with identity.read scope should be accepted by the resource server");

        var profileJson = await profileResponse.Content.ReadAsStringAsync();
        profileJson.Should().Contain("user-001", "the seeded user subject should appear in the profile");
        profileJson.Should().Contain("Demo User", "the seeded user display name should appear in the profile");
    }
}

/// <summary>
/// In-process host for IdentityProvider.Api, used by the full-flow integration test.
/// Mirrors Phase 1's IdentityProviderFactory — no overrides needed because the real
/// in-memory stores and ephemeral RSA key are sufficient for testing.
/// Uses an extern alias to resolve the Program type from IdentityProvider.Api specifically.
/// </summary>
internal sealed class InProcessIdentityProviderFactory
    : WebApplicationFactory<IdpAssembly::Program>
{
    // No overrides — the real pipeline is used as-is.
}

/// <summary>
/// PKCE helpers duplicated here to keep the full-flow test self-contained
/// without a project reference to IdentityProvider.IntegrationTests.
/// </summary>
internal static class PkceHelperLocal
{
    public static string GenerateCodeVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string GenerateCodeChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
