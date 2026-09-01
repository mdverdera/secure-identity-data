using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Infrastructure.Persistence.DbContext;
using Microsoft.EntityFrameworkCore;

namespace IdentityData.Api.Infrastructure.Persistence.Repositories;

internal sealed class UserRepository : IUserRepository
{
    private readonly IdentityDataDbContext _dbContext;

    public UserRepository(IdentityDataDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<User?> GetBySubjectAsync(string subject, CancellationToken cancellationToken = default)
    {
        return await _dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Subject == subject, cancellationToken);
    }

    public async Task<IReadOnlyList<IdentityAttribute>> GetAttributesBySubjectAsync(
        string subject, CancellationToken cancellationToken = default)
    {
        return await _dbContext.IdentityAttributes
            .AsNoTracking()
            .Where(a => a.User.Subject == subject)
            .ToListAsync(cancellationToken);
    }
}
