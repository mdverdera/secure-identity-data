using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using IdentityData.Api.Infrastructure.DPoP;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityData.Api.Infrastructure.Authentication;

/// <summary>
/// ASP.NET Core authentication handler for the DPoP scheme (RFC 9449).
///
/// Validates the complete RFC 9449 chain:
///   1. Parse Authorization: DPoP &lt;access-token&gt;
///   2. Validate JWT access token (signature, iss, aud, exp, nbf, typ)
///   3. Extract cnf.jkt from access token — must be present for DPoP scheme
///   4. Parse DPoP: &lt;proof-jwt&gt; header
///   5. Delegate full validation to <see cref="IDpopProofValidator"/>
///      (typ, alg, jwk, sig, jti, htm, htu, iat, ath, replay, cnf.jkt)
///   6. On success: return <see cref="ClaimsPrincipal"/> from access token claims
///
/// Security: DPoP proof alone is insufficient — the access token is always required.
/// Security: A DPoP-bound token (cnf.jkt present) is rejected under the Bearer scheme.
/// </summary>
public sealed class DpopAuthenticationHandler : AuthenticationHandler<DpopAuthenticationOptions>
{
    private const string DpopSchemePrefix = "DPoP ";

    private readonly DpopOptions _dpopOptions;
    private readonly IDpopProofValidator _dpopProofValidator;
    private readonly IConfiguration _configuration;
    private readonly ISigningKeyResolver _signingKeyResolver;

    public DpopAuthenticationHandler(
        IOptionsMonitor<DpopAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptions<DpopOptions> dpopOptions,
        IDpopProofValidator dpopProofValidator,
        IConfiguration configuration,
        ISigningKeyResolver signingKeyResolver)
        : base(options, logger, encoder)
    {
        _dpopOptions        = dpopOptions.Value;
        _dpopProofValidator = dpopProofValidator;
        _configuration      = configuration;
        _signingKeyResolver = signingKeyResolver;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Step 1: Check for Authorization: DPoP <token>
        var authHeader = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) ||
            !authHeader.StartsWith(DpopSchemePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        // Step 2: Extract raw access token
        var rawAccessToken = authHeader[DpopSchemePrefix.Length..].Trim();
        if (string.IsNullOrEmpty(rawAccessToken))
            return AuthenticateResult.Fail("Missing access token in DPoP authorization header.");

        // Step 3: Read the DPoP proof header
        var dpopHeader = Request.Headers["DPoP"].ToString();
        if (string.IsNullOrEmpty(dpopHeader))
            return AuthenticateResult.Fail("Missing DPoP proof.");

        // Step 4: Validate the JWT access token
        var section       = _configuration.GetSection("IdentityData");
        var validIssuer   = section["ValidIssuer"] ?? string.Empty;
        var validAudience = section["ValidAudience"] ?? string.Empty;

        SecurityToken? validatedToken = null;
        ClaimsPrincipal? principal    = null;

        var parameters = new TokenValidationParameters
        {
            ValidIssuer              = validIssuer,
            ValidAudience            = validAudience,
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ClockSkew                = TimeSpan.FromSeconds(_dpopOptions.ClockSkewSeconds),
            // Delegate signing key resolution to the injected resolver (overridable in tests)
            IssuerSigningKeyResolver = _signingKeyResolver.ResolveSigningKeys,
        };

        try
        {
            var handler = new JwtSecurityTokenHandler();
            principal   = handler.ValidateToken(rawAccessToken, parameters, out validatedToken);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(
                "DPoP access token validation failed for {HttpMethod} {Resource}: {Message}",
                Request.Method, Request.Path, ex.Message);
            return AuthenticateResult.Fail("Invalid access token.");
        }

        // Step 4b: Verify cnf claim is present (DPoP-bound tokens must have cnf.jkt)
        var cnfClaim = principal.FindFirst("cnf");
        if (cnfClaim is null)
            return AuthenticateResult.Fail("DPoP token missing cnf.jkt binding.");

        // Step 5: Extract cnf.jkt from the cnf JSON object
        string? jkt = null;
        try
        {
            using var doc = JsonDocument.Parse(cnfClaim.Value);
            if (doc.RootElement.TryGetProperty("jkt", out var jktEl))
                jkt = jktEl.GetString();
        }
        catch (JsonException)
        {
            return AuthenticateResult.Fail("DPoP token cnf claim is not valid JSON.");
        }

        if (string.IsNullOrEmpty(jkt))
            return AuthenticateResult.Fail("DPoP token cnf.jkt is missing or empty.");

        // Step 6: Compute expected htu — scheme + host + path (no query, no fragment)
        var expectedHtu = $"{Request.Scheme}://{Request.Host}{Request.Path}";

        // Step 7: Delegate full DPoP proof validation
        try
        {
            await _dpopProofValidator.ValidateAsync(
                proofJwt:    dpopHeader,
                accessToken: rawAccessToken,
                expectedHtm: Request.Method.ToUpperInvariant(),
                expectedHtu: expectedHtu,
                cnfJkt:      jkt,
                ct:          Context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (DpopValidationException ex)
        {
            Logger.LogWarning(
                "DPoP authentication failed: {FailureCategory} for {HttpMethod} {Resource}",
                ex.ErrorCode, Request.Method, Request.Path);
            return AuthenticateResult.Fail(ex.Message);
        }

        // Step 8: Build ClaimsPrincipal from the validated access token claims
        var jwtToken = (JwtSecurityToken)validatedToken!;
        var identity = new ClaimsIdentity(jwtToken.Claims, "DPoP");
        var dpopPrincipal = new ClaimsPrincipal(identity);

        // Step 9: Return success
        var ticket = new AuthenticationTicket(dpopPrincipal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var description = properties.GetParameter<string>("error_description") ?? "DPoP token required.";
        Response.Headers.Append(
            "WWW-Authenticate",
            $"DPoP error=\"invalid_token\", error_description=\"{description}\"");
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
