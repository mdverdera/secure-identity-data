using FluentAssertions;
using System.Net;
using System.Net.Http.Headers;

namespace IdentityData.IntegrationTests;

/// <summary>
/// Integration tests for GET /api/identity.
/// Verifies JWT authentication and scope-based authorization end-to-end
/// against the real IdentityData.Api pipeline with an InMemory database.
/// </summary>
public sealed class IdentityEndpointTests : IClassFixture<IdentityDataFactory>
{
    private readonly IdentityDataFactory _factory;
    private readonly HttpClient _client;

    public IdentityEndpointTests(IdentityDataFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task GetIdentity_WithoutToken_Returns401()
    {
        var response = await _client.GetAsync("/api/identity");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetIdentity_WithValidToken_MissingScope_Returns403()
    {
        var token = _factory.CreateTestToken(scope: "openid profile");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/api/identity");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GetIdentity_WithValidToken_Returns200WithIdentityData()
    {
        var token = _factory.CreateTestToken(scope: "openid profile identity.read");
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.GetAsync("/api/identity");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("user-001");
        content.Should().Contain("Demo User");
    }
}
