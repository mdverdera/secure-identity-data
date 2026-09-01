using IdentityData.Api.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityData.Api.Infrastructure.Persistence.Configurations;

internal sealed class IdentityAttributeConfiguration : IEntityTypeConfiguration<IdentityAttribute>
{
    public void Configure(EntityTypeBuilder<IdentityAttribute> builder)
    {
        builder.ToTable("identity_attributes");
        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).HasColumnName("id");
        builder.Property(a => a.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(a => a.AttributeName).HasColumnName("attribute_name").HasMaxLength(256).IsRequired();
        builder.Property(a => a.AttributeValue).HasColumnName("attribute_value").HasMaxLength(2048).IsRequired();
        builder.Property(a => a.CreatedAt).HasColumnName("created_at").IsRequired();

        builder.HasOne(a => a.User)
               .WithMany(u => u.Attributes)
               .HasForeignKey(a => a.UserId)
               .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(a => a.UserId);
    }
}
