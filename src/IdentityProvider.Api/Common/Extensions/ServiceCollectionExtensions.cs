using FluentValidation;
using IdentityProvider.Api.Common.Behaviors;
using IdentityProvider.Api.Infrastructure.Authentication;
using IdentityProvider.Api.Infrastructure.Cryptography;
using IdentityProvider.Api.Infrastructure.Jwt;
using IdentityProvider.Api.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProvider.Api.Common.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all application services: CQRS, validation pipeline, infrastructure.
    /// </summary>
    public static IServiceCollection AddIdentityProviderServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // MediatR — registers all handlers in this assembly
        services.AddMediatR(cfg =>
        {
            cfg.RegisterServicesFromAssemblyContaining<Program>();
            cfg.AddOpenBehavior(typeof(ValidationBehavior<,>));
        });

        // FluentValidation — registers all validators in this assembly
        services.AddValidatorsFromAssemblyContaining<Program>();

        // Infrastructure — Cryptography
        services.AddSingleton<IPkceService, PkceService>();

        // Infrastructure — RSA key management
        // Registered as singleton so the same key is used for all tokens in a process lifetime.
        // Production: replace with an implementation backed by AWS KMS / Secrets Manager.
        services.AddSingleton<ISigningKeyProvider, RsaSigningKeyProvider>();

        // Infrastructure — JWT service
        var jwtLifetimeSeconds = configuration.GetValue<int>("IdentityProvider:AccessTokenLifetimeSeconds");
        if (jwtLifetimeSeconds <= 0) jwtLifetimeSeconds = 900; // Default: 15 minutes

        services.AddSingleton<IJwtService>(sp =>
            new JwtService(sp.GetRequiredService<ISigningKeyProvider>(), jwtLifetimeSeconds));

        // Infrastructure — In-memory stores (singletons for Phase 1)
        services.AddSingleton<IClientStore, InMemoryClientStore>();
        services.AddSingleton<IUserStore, InMemoryUserStore>();
        services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();

        return services;
    }
}
