using FluentAssertions;
using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Domain.Exceptions;
using IdentityData.Api.Features.Identity.Queries.GetIdentityAttributes;
using IdentityData.Api.Infrastructure.Persistence.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace IdentityData.UnitTests.Features;

public sealed class GetIdentityAttributesQueryHandlerTests
{
    private readonly Mock<IUserRepository> _userRepo = new();
    private readonly Mock<IAuditRepository> _auditRepo = new();
    private readonly Mock<ICurrentUser> _currentUser = new();

    private GetIdentityAttributesQueryHandler CreateHandler() =>
        new(_userRepo.Object, _auditRepo.Object, _currentUser.Object,
            NullLogger<GetIdentityAttributesQueryHandler>.Instance);

    [Fact]
    public async Task Handle_WhenUserFound_ReturnsIdentityAttributesDto()
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Subject = "user-001",
            Name = "Demo User",
            Email = "demo@example.test",
            DateOfBirth = new DateOnly(1995, 4, 12),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _currentUser.Setup(u => u.Subject).Returns("user-001");
        _userRepo.Setup(r => r.GetBySubjectAsync("user-001", default)).ReturnsAsync(user);
        _auditRepo.Setup(r => r.AppendAsync(It.IsAny<AuditLog>(), default)).Returns(Task.CompletedTask);

        var handler = CreateHandler();
        var result = await handler.Handle(new GetIdentityAttributesQuery(), default);

        result.Subject.Should().Be("user-001");
        result.Name.Should().Be("Demo User");
        result.Email.Should().Be("demo@example.test");
        result.DateOfBirth.Should().Be(new DateOnly(1995, 4, 12));
    }

    [Fact]
    public async Task Handle_WhenUserNotFound_ThrowsUserNotFoundException()
    {
        _currentUser.Setup(u => u.Subject).Returns("unknown-subject");
        _userRepo.Setup(r => r.GetBySubjectAsync("unknown-subject", default)).ReturnsAsync((User?)null);

        var handler = CreateHandler();
        var act = async () => await handler.Handle(new GetIdentityAttributesQuery(), default);

        await act.Should().ThrowAsync<UserNotFoundException>();
    }

    [Fact]
    public async Task Handle_WhenUserFound_AppendsAuditLogWithCorrectEventType()
    {
        var userId = Guid.NewGuid();
        var user = new User
        {
            Id = userId,
            Subject = "user-001",
            Name = "Demo User",
            Email = "demo@example.test",
            DateOfBirth = new DateOnly(1995, 4, 12),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        _currentUser.Setup(u => u.Subject).Returns("user-001");
        _userRepo.Setup(r => r.GetBySubjectAsync("user-001", default)).ReturnsAsync(user);
        _auditRepo.Setup(r => r.AppendAsync(It.IsAny<AuditLog>(), default)).Returns(Task.CompletedTask);

        var handler = CreateHandler();
        await handler.Handle(new GetIdentityAttributesQuery(), default);

        _auditRepo.Verify(r => r.AppendAsync(
            It.Is<AuditLog>(log =>
                log.UserId == userId &&
                log.EventType == "IdentityAccessed" &&
                log.Resource == "/api/identity"),
            default), Times.Once);
    }
}
