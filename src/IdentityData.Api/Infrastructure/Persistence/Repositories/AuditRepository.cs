using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Infrastructure.Persistence.DbContext;

namespace IdentityData.Api.Infrastructure.Persistence.Repositories;

internal sealed class AuditRepository : IAuditRepository
{
    private readonly IdentityDataDbContext _dbContext;

    public AuditRepository(IdentityDataDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task AppendAsync(AuditLog entry, CancellationToken cancellationToken = default)
    {
        await _dbContext.AuditLogs.AddAsync(entry, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
