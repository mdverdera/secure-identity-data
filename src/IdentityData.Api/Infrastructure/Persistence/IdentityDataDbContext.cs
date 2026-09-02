using IdentityData.Api.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IdentityData.Api.Infrastructure.Persistence;

/// <summary>
/// EF Core DbContext for the Identity Data resource server.
///
/// ⚠️ Educational POC — All seeded data is fictional.
/// This does NOT connect to any real government identity database.
/// </summary>
public sealed class IdentityDataDbContext : DbContext
{
    public IdentityDataDbContext(DbContextOptions<IdentityDataDbContext> options)
        : base(options)
    {
    }

    public DbSet<IdentityRecord> IdentityRecords => Set<IdentityRecord>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // ── IdentityRecord ────────────────────────────────────────────────────
        modelBuilder.Entity<IdentityRecord>(entity =>
        {
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.UserId).HasMaxLength(128);
            entity.Property(e => e.FullName).HasMaxLength(256).IsRequired();
            entity.Property(e => e.Email).HasMaxLength(256).IsRequired();
            entity.Property(e => e.NationalId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.DateOfBirth).IsRequired();
            entity.Property(e => e.CreatedAt).IsRequired();

            // ── Seed data — fictional test identities only ─────────────────
            entity.HasData(new IdentityRecord
            {
                UserId = "user-001",
                FullName = "Alex Morgan",
                Email = "alex.morgan@example.test",
                NationalId = "S1234567A",    // Fictional — not a real ID format
                DateOfBirth = new DateOnly(1990, 1, 15),
                CreatedAt = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
            });
        });

        // ── AuditLog ──────────────────────────────────────────────────────────
        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.UserId).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Action).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Resource).HasMaxLength(256).IsRequired();
            entity.Property(e => e.ClientId).HasMaxLength(256).IsRequired();
            entity.Property(e => e.Timestamp).IsRequired();
        });
    }
}
