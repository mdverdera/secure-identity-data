using IdentityData.Api.Infrastructure.Persistence;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace IdentityData.Api.Application.Features.Profile.Queries.GetProfile;

/// <summary>
/// Handles <see cref="GetProfileQuery"/> by looking up the identity record in the database.
/// Returns null (404) when no record exists for the requested user.
/// </summary>
public sealed class GetProfileQueryHandler : IRequestHandler<GetProfileQuery, ProfileResult?>
{
    private readonly IdentityDataDbContext _db;

    public GetProfileQueryHandler(IdentityDataDbContext db)
    {
        _db = db;
    }

    public async Task<ProfileResult?> Handle(GetProfileQuery request, CancellationToken cancellationToken)
    {
        var record = await _db.IdentityRecords
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.UserId == request.UserId, cancellationToken);

        if (record is null)
            return null;

        return new ProfileResult(record.UserId, record.FullName, record.Email);
    }
}
