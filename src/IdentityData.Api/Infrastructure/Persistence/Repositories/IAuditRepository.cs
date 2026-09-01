using IdentityData.Api.Domain.Entities;

namespace IdentityData.Api.Infrastructure.Persistence.Repositories;

public interface IAuditRepository
{
    Task AppendAsync(AuditLog entry, CancellationToken cancellationToken = default);
}
