using FluentAssertions;
using IdentityProvider.Api.Domain.Entities;
using IdentityProvider.Api.Domain.Exceptions;
using IdentityProvider.Api.Features.Token.Commands.ExchangeAuthorizationCode;
using IdentityProvider.Api.Infrastructure.Authentication;
using IdentityProvider.Api.Infrastructure.Cryptography;
using IdentityProvider.Api.Infrastructure.Jwt;
using IdentityProvider.Api.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace IdentityProvider.UnitTests.Features;

public sealed class ExchangeAuthorizationCodeCommandHandlerTests : IDisposable
{
    private readonly Mock<IAuthorizationCodeStore> _codeStore = new();
    private readonly PkceService _pkceService = new();
    private readonly RsaSigningKeyProvider _keyProvider = new();
    private readonly JwtService _jwtService;
    private readonly IConfiguration _config;

    private readonly ExchangeAuthorizationCodeCommandHandler _sut;

    public ExchangeAuthorizationCodeCommandHandlerTests()
    {
        _jwtService = new JwtService(_keyProvider);
        _config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IdentityProvider:Issuer"] = "https://localhost:7001",
                ["IdentityProvider:Audience"] = "secure-identity-data-api",
            })
            .Build();

        _sut = new ExchangeAuthorizationCodeCommandHandler(
            _codeStore.Object,
            _pkceService,
            _jwtService,
            _config,
            NullLogger<ExchangeAuthorizationCodeCommandHandler>.Instance);
    }

    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private AuthorizationCode BuildValidCode(
        string? codeChallenge = null,
        bool expired = false,
        bool used = false,
        string clientId = "secure-demo-client",
        string redirectUri = "https://localhost:3000/callback")
    {
        var challenge = codeChallenge ?? _pkceService.GenerateCodeChallenge(Verifier);
        var code = new AuthorizationCode
        {
            Code = "valid-auth-code",
            ClientId = clientId,
            RedirectUri = redirectUri,
            UserId = "user-001",
            Scope = "openid profile",
            CodeChallenge = challenge,
            CodeChallengeMethod = "S256",
            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-10),
            ExpiresAt = expired
                ? DateTimeOffset.UtcNow.AddSeconds(-1)
                : DateTimeOffset.UtcNow.AddSeconds(120),
        };
        if (used) code.MarkUsed();
        return code;
    }

    private static ExchangeAuthorizationCodeCommand BuildCommand(
        string code = "valid-auth-code",
        string redirectUri = "https://localhost:3000/callback",
        string clientId = "secure-demo-client",
        string codeVerifier = Verifier) =>
        new("authorization_code", code, redirectUri, clientId, codeVerifier);

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_ValidRequest_ReturnsAccessToken()
    {
        var authCode = BuildValidCode();
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        var result = await _sut.Handle(BuildCommand(), default);

        result.AccessToken.Should().NotBeNullOrWhiteSpace();
        result.TokenType.Should().Be("Bearer");
        result.ExpiresIn.Should().BeGreaterThan(0);
        result.Scope.Should().Be("openid profile");
    }

    [Fact]
    public async Task Handle_ValidRequest_MarksCodeAsUsed()
    {
        var authCode = BuildValidCode();
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        await _sut.Handle(BuildCommand(), default);

        authCode.Used.Should().BeTrue();
    }

    // ── Code not found ────────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_UnknownCode_ThrowsOAuthException_InvalidGrant()
    {
        _codeStore.Setup(s => s.FindAsync("nonexistent-code", default))
            .ReturnsAsync((AuthorizationCode?)null);

        var act = async () => await _sut.Handle(BuildCommand(code: "nonexistent-code"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    // ── Expired code ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_ExpiredCode_ThrowsOAuthException_InvalidGrant()
    {
        var expiredCode = BuildValidCode(expired: true);
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(expiredCode);
        _codeStore.Setup(s => s.RemoveAsync("valid-auth-code", default)).Returns(Task.CompletedTask);

        var act = async () => await _sut.Handle(BuildCommand(), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    [Fact]
    public async Task Handle_ExpiredCode_RemovesCodeFromStore()
    {
        var expiredCode = BuildValidCode(expired: true);
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(expiredCode);
        _codeStore.Setup(s => s.RemoveAsync("valid-auth-code", default)).Returns(Task.CompletedTask);

        await _sut.Handle(BuildCommand(), default).IgnoreExceptionsAsync();

        _codeStore.Verify(s => s.RemoveAsync("valid-auth-code", default), Times.Once);
    }

    // ── Already-used code ─────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_AlreadyUsedCode_ThrowsOAuthException_InvalidGrant()
    {
        var usedCode = BuildValidCode(used: true);
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(usedCode);
        _codeStore.Setup(s => s.RemoveAsync("valid-auth-code", default)).Returns(Task.CompletedTask);

        var act = async () => await _sut.Handle(BuildCommand(), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    [Fact]
    public async Task Handle_AlreadyUsedCode_RemovesCodeFromStore()
    {
        var usedCode = BuildValidCode(used: true);
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(usedCode);
        _codeStore.Setup(s => s.RemoveAsync("valid-auth-code", default)).Returns(Task.CompletedTask);

        await _sut.Handle(BuildCommand(), default).IgnoreExceptionsAsync();

        _codeStore.Verify(s => s.RemoveAsync("valid-auth-code", default), Times.Once);
    }

    // ── Client mismatch ───────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_WrongClientId_ThrowsOAuthException_InvalidGrant()
    {
        var authCode = BuildValidCode(clientId: "secure-demo-client");
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        var act = async () => await _sut.Handle(BuildCommand(clientId: "other-client"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    // ── Redirect URI mismatch ─────────────────────────────────────────────────

    [Fact]
    public async Task Handle_WrongRedirectUri_ThrowsOAuthException_InvalidGrant()
    {
        var authCode = BuildValidCode(redirectUri: "https://localhost:3000/callback");
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        var act = async () => await _sut.Handle(
            BuildCommand(redirectUri: "https://evil.example.com/callback"), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    // ── PKCE failures ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Handle_WrongCodeVerifier_ThrowsOAuthException_InvalidGrant()
    {
        var authCode = BuildValidCode();
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        var wrongVerifier = "wrong-verifier-that-is-long-enough-to-meet-rfc-7636";
        var act = async () => await _sut.Handle(BuildCommand(codeVerifier: wrongVerifier), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    [Fact]
    public async Task Handle_TamperedCodeChallenge_ThrowsOAuthException_InvalidGrant()
    {
        // Store a code with a tampered challenge (not matching any real verifier)
        var authCode = BuildValidCode(codeChallenge: "tampered-challenge-value-that-wont-match");
        _codeStore.Setup(s => s.FindAsync("valid-auth-code", default)).ReturnsAsync(authCode);

        var act = async () => await _sut.Handle(BuildCommand(codeVerifier: Verifier), default);

        await act.Should().ThrowAsync<OAuthException>()
            .Where(e => e.Error == "invalid_grant");
    }

    public void Dispose() => _keyProvider.Dispose();
}

// Extension helper for test cleanup
file static class TaskExtensions
{
    public static async Task IgnoreExceptionsAsync(this Task task)
    {
        try { await task; }
        catch { /* expected */ }
    }
}
