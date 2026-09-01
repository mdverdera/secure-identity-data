using IdentityData.Api.Infrastructure.Authentication;
using IdentityData.Api.Infrastructure.Persistence.DbContext;
using IdentityData.Api.Infrastructure.Persistence.Seeders;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IdentityData.IntegrationTests;

/// <summary>
/// WebApplicationFactory for IdentityData.Api integration tests.
/// Replaces PostgreSQL with an EF Core InMemory database and injects a
/// known test RSA key pair so tests can issue verifiable JWT tokens without
/// a running IdentityProvider.Api instance.
///
/// For the full-flow test that uses keys from a real IdP, use
/// <see cref="FullFlowIdentityDataFactory"/> instead.
/// </summary>
public sealed class IdentityDataFactory : WebApplicationFactory<IdentityData.Api.IdentityDataApiMarker>
{
    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _verificationKey;

    public IdentityDataFactory()
    {
        // Generate a fresh RSA key pair for this factory instance
        var rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(rsa);

        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(rsa.ExportParameters(false));
        _verificationKey = new RsaSecurityKey(publicRsa);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");

        builder.ConfigureServices(services =>
        {
            ReplaceDbContextWithInMemory(services);
            ReplaceJwkKeyStore(services, [_verificationKey]);
            RemoveJwkStartupService(services);
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        SeedDatabase(host);
        return host;
    }

    /// <summary>Creates a signed JWT for use in tests.</summary>
    public string CreateTestToken(
        string subject = "user-001",
        string issuer = "https://localhost:7001",
        string audience = "secure-identity-data-api",
        string scope = "openid profile identity.read",
        int lifetimeSeconds = 900)
    {
        var handler = new JwtSecurityTokenHandler();
        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(lifetimeSeconds);
        // For expired token tests (negative lifetimeSeconds), set notBefore before expires.
        // For normal tokens, notBefore is the current time.
        var notBefore = lifetimeSeconds >= 0 ? now : expires.AddSeconds(-1);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims:
            [
                new Claim("sub", subject),
                new Claim("scope", scope),
                new Claim("jti", Guid.NewGuid().ToString()),
            ],
            notBefore: notBefore,
            expires: expires,
            signingCredentials: credentials);

        return handler.WriteToken(token);
    }

    // ── Shared helpers used by both factory variants ──────────────────────────

    // A shared InMemoryDatabaseRoot ensures all DbContext instances (seed + request scopes)
    // access the same in-memory store within one factory lifetime.
    private static readonly Microsoft.EntityFrameworkCore.Storage.InMemoryDatabaseRoot _dbRoot = new();

    internal static void ReplaceDbContextWithInMemory(IServiceCollection services)
    {
        // Remove ALL descriptors for IdentityDataDbContext and its options so that
        // no Npgsql configuration survives into the rebuilt options.
        var toRemove = services
            .Where(d =>
                d.ServiceType == typeof(IdentityDataDbContext) ||
                d.ServiceType == typeof(DbContextOptions<IdentityDataDbContext>) ||
                d.ServiceType == typeof(DbContextOptions))
            .ToList();

        // Also remove IDbContextOptionsConfiguration<IdentityDataDbContext> delegates
        // (internal EF Core type registered by AddDbContext to apply the Npgsql provider)
        var optionsCfgToRemove = services
            .Where(d =>
                d.ServiceType.IsGenericType &&
                d.ServiceType.GenericTypeArguments.Length == 1 &&
                d.ServiceType.GenericTypeArguments[0] == typeof(IdentityDataDbContext))
            .ToList();

        foreach (var d in toRemove.Concat(optionsCfgToRemove))
            services.Remove(d);

        services.AddDbContext<IdentityDataDbContext>(options =>
            options.UseInMemoryDatabase("IdentityDataTestDb", _dbRoot));
    }

    internal static void ReplaceJwkKeyStore(
        IServiceCollection services,
        IEnumerable<SecurityKey> verificationKeys)
    {
        var keyStore = new JwkKeyStore();
        keyStore.SetKeys(verificationKeys);

        services.RemoveAll<JwkKeyStore>();
        services.AddSingleton(keyStore);

        // Directly set the signing keys on the TokenValidationParameters.
        // PostConfigure runs last, after all Configure callbacks, so this wins.
        var keyList = keyStore.Keys.ToList();
        services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            options =>
            {
                options.TokenValidationParameters.IssuerSigningKeys = keyList;
                options.TokenValidationParameters.IssuerSigningKeyResolver =
                    (_, _, _, _) => keyList;
            });
    }

    internal static void RemoveJwkStartupService(IServiceCollection services)
    {
        // JwkStartupService is the only IHostedService in IdentityData.Api.
        // Remove it so it does not attempt to contact a real IdP URL at startup.
        services.RemoveAll<IHostedService>();
    }

    internal static void SeedDatabase(IHost host)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDataDbContext>();
        db.Database.EnsureCreated();

        var loggerFactory = scope.ServiceProvider.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger<IdentityDataFactory>();
        DevelopmentDataSeeder.SeedAsync(db, logger).GetAwaiter().GetResult();
    }
}

/// <summary>
/// Variant of <see cref="IdentityDataFactory"/> that accepts externally-provided signing keys.
/// Used by the full-flow integration test to configure IdentityData.Api to trust the
/// IdentityProvider's real ephemeral key (obtained from its in-process JWK endpoint).
/// </summary>
public sealed class FullFlowIdentityDataFactory
    : WebApplicationFactory<IdentityData.Api.IdentityDataApiMarker>
{
    private readonly IEnumerable<SecurityKey> _externalKeys;

    public FullFlowIdentityDataFactory(IEnumerable<SecurityKey> externalKeys)
    {
        _externalKeys = externalKeys;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");

        builder.ConfigureServices(services =>
        {
            IdentityDataFactory.ReplaceDbContextWithInMemory(services);
            IdentityDataFactory.ReplaceJwkKeyStore(services, _externalKeys);
            IdentityDataFactory.RemoveJwkStartupService(services);
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        IdentityDataFactory.SeedDatabase(host);
        return host;
    }
}
