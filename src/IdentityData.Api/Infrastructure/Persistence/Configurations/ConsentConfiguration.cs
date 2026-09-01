using IdentityData.Api.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityData.Api.Infrastructure.Persistence.Configurations;

internal sealed class ConsentConfiguration : IEntityTypeConfiguration<Consent>
{
    public void Configure(EntityTypeBuilder<Consent> builder)
    {
        builder.ToTable("consents");
        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id).HasColumnName("id");
        builder.Property(c => c.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(c => c.ClientId).HasColumnName("client_id").HasMaxLength(256).IsRequired();
        builder.Property(c => c.Scope).HasColumnName("scope").HasMaxLength(512).IsRequired();
        builder.Property(c => c.GrantedAt).HasColumnName("granted_at").IsRequired();
        builder.Property(c => c.ExpiresAt).HasColumnName("expires_at");

        builder.HasOne(c => c.User)
               .WithMany(u => u.Consents)
               .HasForeignKey(c => c.UserId)
               .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(c => new { c.UserId, c.ClientId, c.Scope });
    }
}
