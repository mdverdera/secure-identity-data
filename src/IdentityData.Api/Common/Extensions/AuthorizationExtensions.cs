using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Infrastructure.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityData.Api.Common.Extensions;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddIdentityDataAuthorization(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy(Policies.IdentityRead, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireAssertion(context =>
                {
                    var scopeClaim = context.User.FindFirst("scope")?.Value
                        ?? context.User.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/scope")?.Value;

                    if (string.IsNullOrWhiteSpace(scopeClaim))
                        return false;

                    var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    return scopes.Contains("identity.read", StringComparer.OrdinalIgnoreCase);
                });
            });
        });

        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, CurrentUser>();

        return services;
    }
}
