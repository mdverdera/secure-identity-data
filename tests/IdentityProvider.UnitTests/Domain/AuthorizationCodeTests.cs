using FluentAssertions;
using IdentityProvider.Api.Domain.Entities;

namespace IdentityProvider.UnitTests.Domain;

public sealed class AuthorizationCodeTests
{
    private static AuthorizationCode BuildCode(
        DateTimeOffset? expiresAt = null,
        bool used = false)
    {
        var code = new AuthorizationCode
        {
            Code = "test-code",
            ClientId = "test-client",
            RedirectUri = "https://localhost:3000/callback",
            UserId = "user-001",
            Scope = "openid profile",
            CodeChallenge = "test-challenge",
            CodeChallengeMethod = "S256",
            CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-10),
            ExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddSeconds(120),
        };

        if (used) code.MarkUsed();
        return code;
    }

    // ── Expiry ────────────────────────────────────────────────────────────────

    [Fact]
    public void IsExpired_BeforeExpiry_ReturnsFalse()
    {
        var code = BuildCode(expiresAt: DateTimeOffset.UtcNow.AddSeconds(120));

        code.IsExpired().Should().BeFalse();
    }

    [Fact]
    public void IsExpired_AfterExpiry_ReturnsTrue()
    {
        var code = BuildCode(expiresAt: DateTimeOffset.UtcNow.AddSeconds(-1));

        code.IsExpired().Should().BeTrue();
    }

    [Fact]
    public void IsExpired_AtExpiryBoundary_ReturnsTrue()
    {
        var expiry = DateTimeOffset.UtcNow;
        var code = BuildCode(expiresAt: expiry);

        // Pass the expiry time as "now"
        code.IsExpired(now: expiry).Should().BeTrue();
    }

    [Fact]
    public void IsExpired_WithCustomNow_BeforeExpiry_ReturnsFalse()
    {
        var expiry = DateTimeOffset.UtcNow.AddSeconds(60);
        var code = BuildCode(expiresAt: expiry);
        var nowBeforeExpiry = expiry.AddSeconds(-1);

        code.IsExpired(now: nowBeforeExpiry).Should().BeFalse();
    }

    // ── Single-use ────────────────────────────────────────────────────────────

    [Fact]
    public void MarkUsed_SetsUsedToTrue()
    {
        var code = BuildCode();

        code.MarkUsed();

        code.Used.Should().BeTrue();
    }

    [Fact]
    public void NewCode_IsNotUsed()
    {
        var code = BuildCode();

        code.Used.Should().BeFalse();
    }

    [Fact]
    public void MarkUsed_CalledTwice_RemainsTrue()
    {
        var code = BuildCode();

        code.MarkUsed();
        code.MarkUsed();

        code.Used.Should().BeTrue();
    }

    // ── Immutable binding fields ──────────────────────────────────────────────

    [Fact]
    public void AuthorizationCode_StoresAllBindingFields()
    {
        var code = new AuthorizationCode
        {
            Code = "abc123",
            ClientId = "secure-demo-client",
            RedirectUri = "https://localhost:3000/callback",
            UserId = "user-001",
            Scope = "openid profile",
            CodeChallenge = "challenge-value",
            CodeChallengeMethod = "S256",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(120),
        };

        code.Code.Should().Be("abc123");
        code.ClientId.Should().Be("secure-demo-client");
        code.RedirectUri.Should().Be("https://localhost:3000/callback");
        code.UserId.Should().Be("user-001");
        code.Scope.Should().Be("openid profile");
        code.CodeChallenge.Should().Be("challenge-value");
        code.CodeChallengeMethod.Should().Be("S256");
    }
}
