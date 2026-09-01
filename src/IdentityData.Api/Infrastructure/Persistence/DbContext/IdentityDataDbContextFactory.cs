using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace IdentityData.Api.Infrastructure.Persistence.DbContext;

public sealed class IdentityDataDbContextFactory : IDesignTimeDbContextFactory<IdentityDataDbContext>
{
    public IdentityDataDbContext CreateDbContext(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.Development.json", optional: false)
            .AddEnvironmentVariables()
            .Build();

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDataDbContext>();
        optionsBuilder.UseNpgsql(
            configuration.GetConnectionString("DefaultConnection"),
            npgsql => npgsql.MigrationsHistoryTable("__ef_migrations_history", "public"));

        return new IdentityDataDbContext(optionsBuilder.Options);
    }
}
