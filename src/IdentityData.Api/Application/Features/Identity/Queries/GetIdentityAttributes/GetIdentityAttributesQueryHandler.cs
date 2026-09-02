using IdentityData.Api.Domain.ValueObjects;
using IdentityData.Api.Infrastructure.Persistence;
using MediatR;
using Microsoft.EntityFrameworkCore;

namespace IdentityData.Api.Application.Features.Identity.Queries.GetIdentityAttributes;

/// <summary>
/// Handles <see cref="GetIdentityAttributesQuery"/> by loading the identity record
/// and projecting it into a list of sensitivity-classified attributes.
/// </summary>
public sealed class GetIdentityAttributesQueryHandler
    : IRequestHandler<GetIdentityAttributesQuery, IReadOnlyList<IdentityAttributeResult>>
{
    private readonly IdentityDataDbContext _db;

    public GetIdentityAttributesQueryHandler(IdentityDataDbContext db)
    {
        _db = db;
    }

    public async Task<IReadOnlyList<IdentityAttributeResult>> Handle(
        GetIdentityAttributesQuery request,
        CancellationToken cancellationToken)
    {
        var record = await _db.IdentityRecords
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.UserId == request.UserId, cancellationToken);

        if (record is null)
            return [];

        return
        [
            new IdentityAttributeResult("FullName",    record.FullName,                    Sensitivity.Public),
            new IdentityAttributeResult("Email",       record.Email,                       Sensitivity.Public),
            new IdentityAttributeResult("NationalId",  record.NationalId,                  Sensitivity.Confidential),
            new IdentityAttributeResult("DateOfBirth", record.DateOfBirth.ToString("yyyy-MM-dd"), Sensitivity.Restricted),
        ];
    }
}
