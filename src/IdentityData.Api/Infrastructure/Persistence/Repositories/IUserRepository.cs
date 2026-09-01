using IdentityData.Api.Domain.Entities;

namespace IdentityData.Api.Infrastructure.Persistence.Repositories;

public interface IUserRepository
{
    Task<User?> GetBySubjectAsync(string subject, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<IdentityAttribute>> GetAttributesBySubjectAsync(string subject, CancellationToken cancellationToken = default);
}
