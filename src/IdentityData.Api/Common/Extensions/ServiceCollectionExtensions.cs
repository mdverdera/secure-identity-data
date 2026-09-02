using FluentValidation;
using IdentityData.Api.Common.Behaviors;
using IdentityData.Api.Infrastructure.Authentication;
using IdentityData.Api.Infrastructure.DPoP;
using IdentityData.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityData.Api.Common.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all application services: authentication, EF Core, CQRS, validation pipeline.
    /// </summary>
    public static IServiceCollection AddIdentityDataServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // ── JWT Bearer Authentication ─────────────────────────────────────────
        // Register signing key resolver — tests can replace this with a fixed in-process key.
        var jwksUri = configuration["IdentityData:JwksUri"] ?? string.Empty;
        services.AddSingleton<ISigningKeyResolver>(new JwksSigningKeyResolver(jwksUri));
        services.AddSingleton<IConfigureOptions<JwtBearerOptions>, JwtBearerOptionsSetup>();
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer()
            .AddScheme<DpopAuthenticationOptions, DpopAuthenticationHandler>("DPoP", _ => { });

        // ── DPoP Infrastructure ───────────────────────────────────────────────
        services.Configure<DpopOptions>(configuration.GetSection(DpopOptions.SectionName));
        services.AddSingleton<IJwkThumbprintService, JwkThumbprintService>();
        services.AddSingleton<IDpopReplayStore, InMemoryDpopReplayStore>();
        services.AddSingleton<IDpopProofValidator>(sp =>
        {
            var opts     = sp.GetRequiredService<IOptions<DpopOptions>>().Value;
            var replay   = sp.GetRequiredService<IDpopReplayStore>();
            var thumbprint = sp.GetRequiredService<IJwkThumbprintService>();
            return new DpopProofValidator(opts, replay, thumbprint);
        });

        // ── Authorization — scope policy ──────────────────────────────────────
        services.AddAuthorizationBuilder()
            .AddPolicy("IdentityReadScope", policy =>
                policy.RequireAuthenticatedUser()
                      .RequireAssertion(ctx =>
                      {
                          var scope = ctx.User.FindFirst("scope")?.Value ?? string.Empty;
                          return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                      .Contains("identity.read", StringComparer.Ordinal);
                      }));

        // ── EF Core + PostgreSQL ───────────────────────────────────────────────
        services.AddDbContext<IdentityDataDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));

        // ── MediatR — registers all handlers in this assembly ─────────────────
        services.AddMediatR(cfg =>
        {
            cfg.RegisterServicesFromAssemblyContaining<Program>();
            cfg.AddOpenBehavior(typeof(ValidationBehavior<,>));
        });

        // ── FluentValidation — registers all validators in this assembly ───────
        services.AddValidatorsFromAssemblyContaining<Program>();

        return services;
    }
}
