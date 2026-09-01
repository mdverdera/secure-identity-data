using IdentityData.Api.Infrastructure.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Common.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddJwtBearerAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var idpOptions = configuration
            .GetSection(IdentityProviderOptions.SectionName)
            .Get<IdentityProviderOptions>()
            ?? throw new InvalidOperationException("IdentityProvider configuration section is required.");

        var jwtOptions = configuration
            .GetSection(JwtOptions.SectionName)
            .Get<JwtOptions>()
            ?? throw new InvalidOperationException("Jwt configuration section is required.");

        services.Configure<IdentityProviderOptions>(
            configuration.GetSection(IdentityProviderOptions.SectionName));
        services.Configure<JwtOptions>(
            configuration.GetSection(JwtOptions.SectionName));

        // Singleton key store — populated at startup by JwkStartupService.
        var keyStore = new JwkKeyStore();
        services.AddSingleton(keyStore);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = idpOptions.Issuer,

                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,

                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,

                    ValidateIssuerSigningKey = true,
                    ValidAlgorithms = ["RS256"],

                    // Delegate to the key store captured by closure.
                    // The JwkStartupService populates this store at startup.
                    // In tests, ReplaceJwkKeyStore replaces the singleton AND sets
                    // the resolver directly via PostConfigure<JwtBearerOptions>.
                    IssuerSigningKeyResolver = (_, _, _, _) => keyStore.Keys
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        var logger = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("IdentityData.Authentication");
                        logger.LogWarning("JWT authentication failed: {Message}", context.Exception.Message);
                        return Task.CompletedTask;
                    }
                };
            });

        return services;
    }

    public static IServiceCollection AddJwkStartupService(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var idpOptions = configuration
            .GetSection(IdentityProviderOptions.SectionName)
            .Get<IdentityProviderOptions>()
            ?? throw new InvalidOperationException("IdentityProvider configuration section is required.");

        services.AddHostedService(provider =>
            new JwkStartupService(
                provider.GetRequiredService<JwkKeyStore>(),
                idpOptions.JwksUri,
                provider.GetRequiredService<ILogger<JwkStartupService>>()));

        return services;
    }
}
