using FluentAssertions;
using System.Net;
using System.Net.Http.Headers;

namespace IdentityData.IntegrationTests;

/// <summary>
/// Integration tests for GET /api/profile.
/// Verifies JWT authentication and scope-based authorization end-to-end
/// against the real IdentityData.Api pipeline with an InMemory database.
/// </summary>
public sealed class ProfileEndpointTests : IClassFixture<IdentityDataFactory>
{
    private readonly IdentityDataFactory _factory;
    private readonly HttpClient _client;

    public ProfileEndpointTests(IdentityDataFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GetProfile_WithoutToken_Returns401()
    {
        var response = await _client.GetAsync("/api/profile");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetProfile_WithInvalidToken_Returns401()
    {
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "this.is.not.a.valid.jwt");

        var response = await _client.GetAsync("/api/profile");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetProfile_WithExpiredToken_Returns401()
    {
        var token = _factory.CreateTestToken(lifetimeSeconds: -1);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/api/profile");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetProfile_WithValidToken_MissingScope_Returns403()
    {
        // Token has profile scope but NOT identity.read
        var token = _factory.CreateTestToken(scope: "openid profile");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/api/profile");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetProfile_WithValidToken_CorrectScope_Returns200WithProfile()
    {
        var token = _factory.CreateTestToken(scope: "openid profile identity.read");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/api/profile");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("user-001");
        content.Should().Contain("Demo User");
        content.Should().Contain("demo@example.test");
    }
}
