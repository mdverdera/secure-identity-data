using IdentityData.Api.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IdentityData.Api.Infrastructure.Persistence.DbContext;

public sealed class IdentityDataDbContext : Microsoft.EntityFrameworkCore.DbContext
{
    public IdentityDataDbContext(DbContextOptions<IdentityDataDbContext> options)
        : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<IdentityAttribute> IdentityAttributes => Set<IdentityAttribute>();
    public DbSet<Consent> Consents => Set<Consent>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(IdentityDataDbContext).Assembly);
        base.OnModelCreating(modelBuilder);
    }
}
