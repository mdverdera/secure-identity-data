using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Domain.Exceptions;
using IdentityData.Api.Domain.Services;
using IdentityData.Api.Features.Identity.Models;
using IdentityData.Api.Infrastructure.Persistence.Repositories;
using MediatR;
using Microsoft.Extensions.Logging;

namespace IdentityData.Api.Features.Identity.Queries.GetIdentityAttributes;

public sealed class GetIdentityAttributesQueryHandler : IRequestHandler<GetIdentityAttributesQuery, IdentityAttributesDto>
{
    private readonly IUserRepository _userRepository;
    private readonly IAuditRepository _auditRepository;
    private readonly ICurrentUser _currentUser;
    private readonly ILogger<GetIdentityAttributesQueryHandler> _logger;

    public GetIdentityAttributesQueryHandler(
        IUserRepository userRepository,
        IAuditRepository auditRepository,
        ICurrentUser currentUser,
        ILogger<GetIdentityAttributesQueryHandler> logger)
    {
        _userRepository = userRepository;
        _auditRepository = auditRepository;
        _currentUser = currentUser;
        _logger = logger;
    }

    public async Task<IdentityAttributesDto> Handle(GetIdentityAttributesQuery request, CancellationToken cancellationToken)
    {
        var subject = _currentUser.Subject;

        var user = await _userRepository.GetBySubjectAsync(subject, cancellationToken);
        if (user is null)
            throw new UserNotFoundException(subject);

        await _auditRepository.AppendAsync(new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            EventType = AuditEventTypes.IdentityAccessed,
            Resource = "/api/identity",
            CreatedAt = DateTimeOffset.UtcNow
        }, cancellationToken);

        _logger.LogDebug("Identity attributes retrieved for authenticated user");

        return new IdentityAttributesDto(
            Subject: user.Subject,
            Name: user.Name,
            Email: user.Email,
            DateOfBirth: user.DateOfBirth
        );
    }
}
