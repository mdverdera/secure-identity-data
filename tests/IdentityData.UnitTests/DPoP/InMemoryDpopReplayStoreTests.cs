using FluentAssertions;
using IdentityData.Api.Infrastructure.DPoP;

namespace IdentityData.UnitTests.DPoP;

/// <summary>
/// Unit tests for <see cref="InMemoryDpopReplayStore"/>.
/// </summary>
public sealed class InMemoryDpopReplayStoreTests
{
    private readonly InMemoryDpopReplayStore _sut = new();

    [Fact]
    public async Task FreshJti_HasBeenUsed_ReturnsFalse()
    {
        var result = await _sut.HasBeenUsedAsync("brand-new-jti");

        result.Should().BeFalse();
    }

    [Fact]
    public async Task AfterMarkAsUsed_HasBeenUsed_ReturnsTrue()
    {
        var jti    = Guid.NewGuid().ToString();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(10);

        await _sut.MarkAsUsedAsync(jti, expiry);

        var result = await _sut.HasBeenUsedAsync(jti);
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ExpiredEntry_HasBeenUsed_ReturnsFalse()
    {
        var jti    = Guid.NewGuid().ToString();
        // expiry in the past
        var expiry = DateTimeOffset.UtcNow.AddSeconds(-1);

        await _sut.MarkAsUsedAsync(jti, expiry);

        var result = await _sut.HasBeenUsedAsync(jti);
        result.Should().BeFalse("an expired entry should be treated as not used");
    }

    [Fact]
    public async Task DifferentJtis_AreIndependent()
    {
        var jti1 = Guid.NewGuid().ToString();
        var jti2 = Guid.NewGuid().ToString();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);

        await _sut.MarkAsUsedAsync(jti1, expiry);

        (await _sut.HasBeenUsedAsync(jti1)).Should().BeTrue();
        (await _sut.HasBeenUsedAsync(jti2)).Should().BeFalse("jti2 was never marked as used");
    }

    [Fact]
    public async Task MarkAsUsed_IsIdempotent_WhenCalledTwice()
    {
        var jti    = Guid.NewGuid().ToString();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);

        await _sut.MarkAsUsedAsync(jti, expiry);
        await _sut.MarkAsUsedAsync(jti, expiry); // second call should not throw

        (await _sut.HasBeenUsedAsync(jti)).Should().BeTrue();
    }
}
