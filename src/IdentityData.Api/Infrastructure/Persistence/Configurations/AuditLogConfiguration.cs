using IdentityData.Api.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityData.Api.Infrastructure.Persistence.Configurations;

internal sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("audit_logs");
        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).HasColumnName("id");
        builder.Property(a => a.UserId).HasColumnName("user_id");
        builder.Property(a => a.EventType).HasColumnName("event_type").HasMaxLength(128).IsRequired();
        builder.Property(a => a.Resource).HasColumnName("resource").HasMaxLength(512).IsRequired();
        builder.Property(a => a.CreatedAt).HasColumnName("created_at").IsRequired();

        // Note: AuditLog.UserId is optional (events may occur before auth succeeds)
        // No FK navigation on User entity side for audit logs — keep it simple
        builder.HasIndex(a => new { a.UserId, a.EventType });
    }
}
