using IdentityProvider.Api.Domain.Exceptions;
using IdentityProvider.Api.Infrastructure.Cryptography;
using IdentityProvider.Api.Infrastructure.Jwt;
using IdentityProvider.Api.Infrastructure.Persistence;
using MediatR;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace IdentityProvider.Api.Features.Token.Commands.ExchangeAuthorizationCode;

/// <summary>
/// Handles the token exchange:
/// 1. Validate authorization code exists, is not expired, is not used.
/// 2. Validate client_id matches.
/// 3. Validate redirect_uri matches.
/// 4. Validate PKCE code_verifier against stored code_challenge.
/// 5. Mark code as used (single-use enforcement).
/// 6. Issue JWT access token.
/// </summary>
public sealed class ExchangeAuthorizationCodeCommandHandler
    : IRequestHandler<ExchangeAuthorizationCodeCommand, ExchangeAuthorizationCodeResult>
{
    private readonly IAuthorizationCodeStore _codeStore;
    private readonly IPkceService _pkceService;
    private readonly IJwtService _jwtService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ExchangeAuthorizationCodeCommandHandler> _logger;

    public ExchangeAuthorizationCodeCommandHandler(
        IAuthorizationCodeStore codeStore,
        IPkceService pkceService,
        IJwtService jwtService,
        IConfiguration configuration,
        ILogger<ExchangeAuthorizationCodeCommandHandler> logger)
    {
        _codeStore = codeStore;
        _pkceService = pkceService;
        _jwtService = jwtService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<ExchangeAuthorizationCodeResult> Handle(
        ExchangeAuthorizationCodeCommand request,
        CancellationToken cancellationToken)
    {
        // 1. Find authorization code
        var authCode = await _codeStore.FindAsync(request.Code, cancellationToken);
        if (authCode is null)
        {
            _logger.LogWarning("Token request rejected: authorization code not found.");
            throw OAuthException.InvalidGrant("Authorization code not found or has been removed.");
        }

        // 2. Check expiry
        if (authCode.IsExpired())
        {
            await _codeStore.RemoveAsync(request.Code, cancellationToken);
            _logger.LogWarning("Token request rejected: authorization code expired for client {ClientId}.", request.ClientId);
            throw OAuthException.InvalidGrant("Authorization code has expired.");
        }

        // 3. Check single-use
        if (authCode.Used)
        {
            // Replay detected — remove code to prevent further attempts
            await _codeStore.RemoveAsync(request.Code, cancellationToken);
            _logger.LogWarning(
                "Token request rejected: authorization code already used for client {ClientId}. Possible replay attack.",
                request.ClientId);
            throw OAuthException.InvalidGrant("Authorization code has already been used.");
        }

        // 4. Validate client binding
        if (!string.Equals(authCode.ClientId, request.ClientId, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "Token request rejected: client_id mismatch. Expected {Expected}, got {Actual}.",
                authCode.ClientId, request.ClientId);
            throw OAuthException.InvalidGrant("client_id does not match the authorization code.");
        }

        // 5. Validate redirect_uri binding
        if (!string.Equals(authCode.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            _logger.LogWarning("Token request rejected: redirect_uri mismatch for client {ClientId}.", request.ClientId);
            throw OAuthException.InvalidGrant("redirect_uri does not match the authorization code.");
        }

        // 6. Validate PKCE S256
        if (!_pkceService.ValidateCodeVerifier(request.CodeVerifier, authCode.CodeChallenge))
        {
            _logger.LogWarning("Token request rejected: PKCE verification failed for client {ClientId}.", request.ClientId);
            throw OAuthException.InvalidGrant("PKCE code_verifier verification failed.");
        }

        // 7. Mark code as used (single-use enforcement)
        authCode.MarkUsed();

        // 8. Issue JWT
        var issuer = _configuration["IdentityProvider:Issuer"] ?? "https://localhost:7001";
        var audience = _configuration["IdentityProvider:Audience"] ?? "secure-identity-data-api";

        var tokenResult = _jwtService.GenerateAccessToken(new TokenRequest(
            UserId: authCode.UserId,
            Scope: authCode.Scope,
            Issuer: issuer,
            Audience: audience));

        _logger.LogInformation(
            "Access token issued for user {UserId}, client {ClientId}.",
            authCode.UserId, request.ClientId);

        // NOTE: tokenResult.AccessToken is intentionally NOT logged.
        return new ExchangeAuthorizationCodeResult(
            tokenResult.AccessToken,
            tokenResult.TokenType,
            tokenResult.ExpiresInSeconds,
            authCode.Scope);
    }
}
