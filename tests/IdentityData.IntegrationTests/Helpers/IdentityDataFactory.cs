using System.Security.Cryptography;
using IdentityData.Api.Infrastructure.Authentication;
using IdentityData.Api.Infrastructure.DPoP;
using IdentityData.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityData.IntegrationTests.Helpers;

/// <summary>
/// WebApplicationFactory for IdentityData.Api integration tests.
///
/// Overrides:
/// - EF Core: replaces Npgsql with an in-memory database.
/// - ISigningKeyResolver: returns a locally-generated RSA key so tests can mint their own
///   JWT access tokens without a live IdentityProvider.Api instance.
/// - IDpopReplayStore: fresh instance per factory so replayed JTIs are detected within a
///   single test run but do not bleed across factory instances.
/// </summary>
public sealed class IdentityDataFactory : WebApplicationFactory<Program>
{
    private readonly RSA _rsa;

    /// <summary>The RSA security key used to sign test JWT access tokens.</summary>
    public RsaSecurityKey IssuerSigningKey { get; }

    /// <summary>RS256 signing credentials backed by <see cref="IssuerSigningKey"/>.</summary>
    public SigningCredentials SigningCredentials { get; }

    public IdentityDataFactory()
    {
        _rsa = RSA.Create(2048);
        IssuerSigningKey   = new RsaSecurityKey(_rsa) { KeyId = "test-key-1" };
        SigningCredentials = new SigningCredentials(IssuerSigningKey, SecurityAlgorithms.RsaSha256);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            // Provide required configuration values so the app starts without a real
            // IdentityProvider.Api or PostgreSQL instance.
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["IdentityData:JwksUri"]        = "https://localhost:7001/.well-known/jwks.json",
                ["IdentityData:ValidIssuer"]    = TestConstants.Issuer,
                ["IdentityData:ValidAudience"]  = TestConstants.Audience,
                ["ConnectionStrings:DefaultConnection"] = "Host=test;Database=test",
            });
        });

        builder.ConfigureServices(services =>
        {
            // ── Replace EF Core Npgsql with in-memory database ────────────────
            // EF Core's UseNpgsql registers its extensions internally in a way that persists
            // in the DI container's service provider even after removing DbContextOptions<T>.
            // The reliable fix is to directly register a pre-built DbContextOptions<T> instance
            // that uses InMemory, and let EF Core use that instead of building its own.
            // We remove the factory descriptor and add a concrete value descriptor so there
            // is only one options object and it uses the InMemory provider.
            var dbContextOptionsDescriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<IdentityDataDbContext>));
            if (dbContextOptionsDescriptor is not null)
                services.Remove(dbContextOptionsDescriptor);

            // Also remove IdentityDataDbContext so it gets re-registered by AddDbContext below
            var dbContextDescriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(IdentityDataDbContext));
            if (dbContextDescriptor is not null)
                services.Remove(dbContextDescriptor);

            // Build standalone options without touching the outer DI container's service provider
            var inMemoryOptions = new DbContextOptionsBuilder<IdentityDataDbContext>()
                .UseInMemoryDatabase("TestDb_" + Guid.NewGuid())
                .Options;

            // Register the pre-built options as a singleton value (no Npgsql involvement)
            services.AddSingleton(inMemoryOptions);

            // Register the context using those options
            services.AddScoped<IdentityDataDbContext>(sp =>
                new IdentityDataDbContext(
                    sp.GetRequiredService<DbContextOptions<IdentityDataDbContext>>()));

            // ── Override ISigningKeyResolver with a fixed test key ────────────
            services.RemoveAll<ISigningKeyResolver>();
            services.AddSingleton<ISigningKeyResolver>(
                new TestSigningKeyResolver(IssuerSigningKey));

            // ── Fresh DPoP replay store per factory instance ──────────────────
            services.RemoveAll<IDpopReplayStore>();
            services.AddSingleton<IDpopReplayStore, InMemoryDpopReplayStore>();
        });
    }

    /// <summary>
    /// Seeds the in-memory database with the HasData seed records.
    /// Call once per test that requires database access.
    /// </summary>
    public void EnsureDbSeeded()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDataDbContext>();
        db.Database.EnsureCreated();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _rsa.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>
/// Test implementation of <see cref="ISigningKeyResolver"/> that always returns the
/// single pre-generated RSA key used to sign test JWT tokens.
/// </summary>
internal sealed class TestSigningKeyResolver : ISigningKeyResolver
{
    private readonly SecurityKey _key;

    public TestSigningKeyResolver(SecurityKey key) => _key = key;

    public IEnumerable<SecurityKey> ResolveSigningKeys(
        string token,
        SecurityToken? securityToken,
        string kid,
        TokenValidationParameters validationParameters) => [_key];
}

/// <summary>Shared test constants used across IdentityData integration tests.</summary>
internal static class TestConstants
{
    public const string Issuer   = "https://localhost:7001";
    public const string Audience = "secure-identity-data-api";
}
