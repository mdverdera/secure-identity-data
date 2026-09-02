using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace IdentityData.Api.Infrastructure.Persistence;

/// <summary>
/// Design-time factory used by EF Core migration tooling (dotnet ef migrations add).
/// Not used at runtime.
/// </summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<IdentityDataDbContext>
{
    public IdentityDataDbContext CreateDbContext(string[] args)
    {
        // Load configuration from appsettings.json so the connection string is available
        // when running EF Core CLI commands from the project directory.
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .Build();

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDataDbContext>();
        optionsBuilder.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));

        return new IdentityDataDbContext(optionsBuilder.Options);
    }
}
