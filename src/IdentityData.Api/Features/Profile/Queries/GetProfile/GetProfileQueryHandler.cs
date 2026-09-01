using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Domain.Exceptions;
using IdentityData.Api.Domain.Services;
using IdentityData.Api.Features.Profile.Models;
using IdentityData.Api.Infrastructure.Persistence.Repositories;
using MediatR;
using Microsoft.Extensions.Logging;

namespace IdentityData.Api.Features.Profile.Queries.GetProfile;

public sealed class GetProfileQueryHandler : IRequestHandler<GetProfileQuery, ProfileDto>
{
    private readonly IUserRepository _userRepository;
    private readonly IAuditRepository _auditRepository;
    private readonly ICurrentUser _currentUser;
    private readonly ILogger<GetProfileQueryHandler> _logger;

    public GetProfileQueryHandler(
        IUserRepository userRepository,
        IAuditRepository auditRepository,
        ICurrentUser currentUser,
        ILogger<GetProfileQueryHandler> logger)
    {
        _userRepository = userRepository;
        _auditRepository = auditRepository;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<ProfileDto> Handle(GetProfileQuery request, CancellationToken cancellationToken)
    {
        var subject = _currentUser.Subject;

        var user = await _userRepository.GetBySubjectAsync(subject, cancellationToken);
        if (user is null)
            throw new UserNotFoundException(subject);

        // Write audit log — do NOT log the subject value at Information level (privacy)
        await _auditRepository.AppendAsync(new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            EventType = AuditEventTypes.ProfileAccessed,
            Resource = "/api/profile",
            CreatedAt = DateTimeOffset.UtcNow
        }, cancellationToken);

        _logger.LogDebug("Profile retrieved for authenticated user");

        return new ProfileDto(
            Subject: user.Subject,
            Name: user.Name,
            Email: user.Email,
            DateOfBirth: user.DateOfBirth
        );
    }
}
