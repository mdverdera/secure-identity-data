using IdentityData.Api.Infrastructure.Persistence.DbContext;
using IdentityData.Api.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityData.Api.Common.Extensions;

public static class PersistenceExtensions
{
    public static IServiceCollection AddIdentityDataPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDbContext<IdentityDataDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection");
            options.UseNpgsql(connectionString);
        });

        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IAuditRepository, AuditRepository>();

        return services;
    }
}
