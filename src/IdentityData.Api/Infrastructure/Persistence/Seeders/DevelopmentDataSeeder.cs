using IdentityData.Api.Domain.Entities;
using IdentityData.Api.Infrastructure.Persistence.DbContext;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IdentityData.Api.Infrastructure.Persistence.Seeders;

public static class DevelopmentDataSeeder
{
    public static async Task SeedAsync(IdentityDataDbContext dbContext, ILogger logger)
    {
        // Only seed if no users exist
        if (await dbContext.Users.AnyAsync())
            return;

        var userId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        var user = new User
        {
            Id = userId,
            Subject = "user-001",
            Name = "Demo User",
            Email = "demo@example.test",
            DateOfBirth = new DateOnly(1995, 4, 12),
            CreatedAt = now,
            UpdatedAt = now
        };

        await dbContext.Users.AddAsync(user);

        // Seed some identity attributes
        var attributes = new[]
        {
            new IdentityAttribute
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                AttributeName = "nationality",
                AttributeValue = "Fictional",
                CreatedAt = now
            },
            new IdentityAttribute
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                AttributeName = "id_type",
                AttributeValue = "DEMO_ID",
                CreatedAt = now
            }
        };

        await dbContext.IdentityAttributes.AddRangeAsync(attributes);
        await dbContext.SaveChangesAsync();

        logger.LogInformation("Development seed data applied: 1 user, {Count} identity attributes", attributes.Length);
    }
}
