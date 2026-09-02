using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace IdentityData.Api.Infrastructure.Authentication;

/// <summary>
/// Configures JWT Bearer authentication to validate tokens issued by the IdentityProvider.Api.
/// Tokens are validated using JWKS discovery (RS256) via the injected <see cref="ISigningKeyResolver"/>.
///
/// ⚠️ Never log the token value or any key material here.
/// </summary>
public sealed class JwtBearerOptionsSetup : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IConfiguration _configuration;
    private readonly ISigningKeyResolver _signingKeyResolver;

    public JwtBearerOptionsSetup(IConfiguration configuration, ISigningKeyResolver signingKeyResolver)
    {
        _configuration      = configuration;
        _signingKeyResolver = signingKeyResolver;
    }

    public void Configure(JwtBearerOptions options) => Configure(JwtBearerDefaults.AuthenticationScheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme)
            return;

        var section = _configuration.GetSection("IdentityData");
        var validIssuer = section["ValidIssuer"]
            ?? throw new InvalidOperationException("IdentityData:ValidIssuer is required.");
        var validAudience = section["ValidAudience"]
            ?? throw new InvalidOperationException("IdentityData:ValidAudience is required.");

        // Disable metadata discovery — key resolution is handled by ISigningKeyResolver.
        options.RequireHttpsMetadata = false;
        // Preserve JWT claim names as-is (do not map sub → NameIdentifier, etc.)
        // This ensures Bearer tokens use the same sub claim as DPoP-authenticated tokens.
        options.MapInboundClaims = false;

        options.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidIssuer = validIssuer,
            ValidateAudience = true,
            ValidAudience = validAudience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // Clock skew is intentionally tight for a security demo
            ClockSkew = TimeSpan.FromSeconds(30),
            IssuerSigningKeyResolver = _signingKeyResolver.ResolveSigningKeys,
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                // Log failure without including the token value
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILogger<JwtBearerOptionsSetup>>();
                logger.LogWarning("JWT authentication failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Reject DPoP-bound tokens presented under the Bearer scheme.
                // A DPoP-bound token carries a cnf claim with a jkt key binding.
                // Accepting it as Bearer would allow a token-downgrade attack.
                var cnfClaim = context.Principal?.FindFirst("cnf");
                if (cnfClaim is not null)
                {
                    context.Fail("DPoP-bound token must not be used with Bearer scheme.");
                }
                return Task.CompletedTask;
            },
        };
    }
}
