using FluentAssertions;
using IdentityProvider.Api.Domain.Entities;
using IdentityProvider.Api.Domain.Exceptions;
using IdentityProvider.Api.Features.Authorization.Commands.Authorize;
using IdentityProvider.Api.Infrastructure.Persistence;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace IdentityProvider.UnitTests.Features;

public sealed class AuthorizeUserCommandHandlerTests
{
    private readonly Mock<IClientStore> _clientStore = new();
    private readonly Mock<IUserStore> _userStore = new();
    private readonly Mock<IAuthorizationCodeStore> _codeStore = new();

    private readonly AuthorizeUserCommandHandler _sut;

    public AuthorizeUserCommandHandlerTests()
    {
        _sut = new AuthorizeUserCommandHandler(
            _clientStore.Object,
            _userStore.Object,
            _codeStore.Object,
            NullLogger<AuthorizeUserCommandHandler>.Instance);
    }

    private static OAuthClient BuildClient(
        string[] redirectUris = null!,
        string[] scopes = null!) =>
        new()
        {
            ClientId = "secure-demo-client",
            ClientName = "Secure Identity Demo Client",
            RedirectUris = redirectUris ?? ["https://localhost:3000/callback"],
            AllowedScopes = scopes ?? ["openid", "profile"],
        };

    private static User BuildUser() =>
        new() { UserId = "user-001", Name = "Demo User", Email = "demo@example.test" };

    private static AuthorizeUserCommand BuildCommand(
        string clientId = "secure-demo-client",
        string redirectUri = "https://localhost:3000/callback",
        string responseType = "code",
        string scope = "openid profile",
        string state = "state-123",
        string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        string codeChallengeMethod = "S256") =>
        new(clientId, redirectUri, responseType, scope, state, codeChallenge, codeChallengeMethod);

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_ValidRequest_ReturnsCodeAndState()
    {
        _clientStore.Setup(s => s.FindByClientIdAsync("secure-demo-client", default))
            .ReturnsAsync(BuildClient());
        _userStore.Setup(s => s.GetDemoUserAsync(default))
            .ReturnsAsync(BuildUser());
        _codeStore.Setup(s => s.StoreAsync(It.IsAny<AuthorizationCode>(), default))
            .Returns(Task.CompletedTask);

        var result = await _sut.Handle(BuildCommand(), default);

        result.Code.Should().NotBeNullOrEmpty();
        result.State.Should().Be("state-123");
        result.RedirectUri.Should().Be("https://localhost:3000/callback");
    }

    [Fact]
    public async Task Handle_ValidRequest_StoresAuthorizationCode()
    {
        _clientStore.Setup(s => s.FindByClientIdAsync("secure-demo-client", default))
            .ReturnsAsync(BuildClient());
        _userStore.Setup(s => s.GetDemoUserAsync(default))
            .ReturnsAsync(BuildUser());

        AuthorizationCode? storedCode = null;
        _codeStore.Setup(s => s.StoreAsync(It.IsAny<AuthorizationCode>(), default))
            .Callback<AuthorizationCode, CancellationToken>((c, _) => storedCode = c)
            .Returns(Task.CompletedTask);

        await _sut.Handle(BuildCommand(), default);

        storedCode.Should().NotBeNull();
        storedCode!.ClientId.Should().Be("secure-demo-client");
        storedCode.CodeChallenge.Should().Be("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        storedCode.CodeChallengeMethod.Should().Be("S256");
        storedCode.Used.Should().BeFalse();
        storedCode.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    // ── Client validation ─────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_UnknownClientId_ThrowsOAuthException_InvalidClient()
    {
        _clientStore.Setup(s => s.FindByClientIdAsync("unknown-client", default))
            .ReturnsAsync((OAuthClient?)null);

        var act = async () => await _sut.Handle(BuildCommand(clientId: "unknown-client"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_client");
    }

    // ── Redirect URI validation ───────────────────────────────────────────────

    [Fact]
    public async Task Handle_MismatchedRedirectUri_ThrowsOAuthException_InvalidRequest()
    {
        _clientStore.Setup(s => s.FindByClientIdAsync("secure-demo-client", default))
            .ReturnsAsync(BuildClient());

        var act = async () => await _sut.Handle(
            BuildCommand(redirectUri: "https://evil.example.com/callback"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_request");
    }

    [Fact]
    public async Task Handle_EmptyRedirectUri_Validation_ThrowsOAuthException()
    {
        // Validator fires before handler — empty redirect_uri should be caught
        // This test exercises the domain logic path: client has no redirect_uri match
        _clientStore.Setup(s => s.FindByClientIdAsync("secure-demo-client", default))
            .ReturnsAsync(BuildClient());

        var act = async () => await _sut.Handle(
            BuildCommand(redirectUri: "https://not-registered.example.com/callback"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_request");
    }

    // ── Scope validation ──────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_UnallowedScope_ThrowsOAuthException_InvalidScope()
    {
        _clientStore.Setup(s => s.FindByClientIdAsync("secure-demo-client", default))
            .ReturnsAsync(BuildClient(scopes: ["openid"])); // profile not allowed

        var act = async () => await _sut.Handle(BuildCommand(scope: "openid profile"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_scope");
    }
}
