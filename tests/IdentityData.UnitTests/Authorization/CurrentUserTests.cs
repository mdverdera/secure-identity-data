using FluentAssertions;
using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Infrastructure.Authentication;
using Microsoft.AspNetCore.Http;
using Moq;
using System.Security.Claims;
using Xunit;

namespace IdentityData.UnitTests.Authorization;

public sealed class CurrentUserTests
{
    private static CurrentUser CreateCurrentUser(IEnumerable<Claim>? claims = null)
    {
        var claimsIdentity = new ClaimsIdentity(claims ?? [], "Bearer");
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        var httpContext = new DefaultHttpContext
        {
            User = claimsPrincipal
        };

        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(httpContext);

        return new CurrentUser(accessor.Object);
    }

    [Fact]
    public void Subject_ShouldReturnSubClaim()
    {
        var user = CreateCurrentUser([new Claim("sub", "user-001")]);
        user.Subject.Should().Be("user-001");
    }

    [Fact]
    public void Scopes_ShouldParseSpaceDelimitedScopeClaim()
    {
        var user = CreateCurrentUser([new Claim("scope", "openid profile identity.read")]);
        user.Scopes.Should().BeEquivalentTo(["openid", "profile", "identity.read"]);
    }

    [Fact]
    public void HasScope_WithMatchingScope_ShouldReturnTrue()
    {
        var user = CreateCurrentUser([new Claim("scope", "openid profile identity.read")]);
        user.HasScope("identity.read").Should().BeTrue();
    }

    [Fact]
    public void HasScope_WithMissingScope_ShouldReturnFalse()
    {
        var user = CreateCurrentUser([new Claim("scope", "openid profile")]);
        user.HasScope("identity.read").Should().BeFalse();
    }

    [Fact]
    public void Scopes_WhenNoScopeClaim_ShouldReturnEmpty()
    {
        var user = CreateCurrentUser([new Claim("sub", "user-001")]);
        user.Scopes.Should().BeEmpty();
    }

    [Fact]
    public void Subject_WhenNoSubClaim_ShouldThrowInvalidOperationException()
    {
        var user = CreateCurrentUser([]);
        var act = () => user.Subject;
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void ClientId_WhenPresent_ShouldReturnValue()
    {
        var user = CreateCurrentUser([new Claim("client_id", "secure-demo-client")]);
        user.ClientId.Should().Be("secure-demo-client");
    }

    [Fact]
    public void ClientId_WhenAbsent_ShouldReturnNull()
    {
        var user = CreateCurrentUser([new Claim("sub", "user-001")]);
        user.ClientId.Should().BeNull();
    }
}
