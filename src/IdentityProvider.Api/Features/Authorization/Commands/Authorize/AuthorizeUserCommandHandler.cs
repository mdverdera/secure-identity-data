using System.Security.Cryptography;
using IdentityProvider.Api.Domain.Entities;
using IdentityProvider.Api.Domain.Exceptions;
using IdentityProvider.Api.Infrastructure.Persistence;
using MediatR;
using Microsoft.Extensions.Logging;

namespace IdentityProvider.Api.Features.Authorization.Commands.Authorize;

/// <summary>
/// Handles the OAuth authorization request:
/// 1. Validates client_id and redirect_uri against registered clients.
/// 2. Validates requested scopes.
/// 3. Auto-authenticates the single demo user (Phase 1 — no login UI).
/// 4. Generates a cryptographically secure authorization code.
/// 5. Stores the code with PKCE binding and short TTL.
///
/// NOTE: Phase 1 auto-authenticates the demo user once the request is valid.
/// A real implementation would redirect to a login/consent page here.
/// </summary>
public sealed class AuthorizeUserCommandHandler
    : IRequestHandler<AuthorizeUserCommand, AuthorizeUserResult>
{
    private const int AuthCodeLifetimeSeconds = 120; // 2-minute TTL
    private const int AuthCodeByteLength = 32;       // 256-bit entropy

    private readonly IClientStore _clientStore;
    private readonly IUserStore _userStore;
    private readonly IAuthorizationCodeStore _codeStore;
    private readonly ILogger<AuthorizeUserCommandHandler> _logger;

    public AuthorizeUserCommandHandler(
        IClientStore clientStore,
        IUserStore userStore,
        IAuthorizationCodeStore codeStore,
        ILogger<AuthorizeUserCommandHandler> logger)
    {
        _clientStore = clientStore;
        _userStore = userStore;
        _codeStore = codeStore;
        _logger = logger;
    }

    public async Task<AuthorizeUserResult> Handle(
        AuthorizeUserCommand request,
        CancellationToken cancellationToken)
    {
        // 1. Validate client
        var client = await _clientStore.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (client is null)
        {
            _logger.LogWarning("Authorization rejected: unknown client_id {ClientId}", request.ClientId);
            throw OAuthException.InvalidClient($"Unknown client_id: {request.ClientId}");
        }

        // 2. Validate redirect_uri (exact match — security critical)
        if (!client.IsRedirectUriAllowed(request.RedirectUri))
        {
            _logger.LogWarning(
                "Authorization rejected: redirect_uri mismatch for client {ClientId}", request.ClientId);
            // Per RFC 6749 §4.1.2.1 — do NOT redirect back when redirect_uri is invalid
            throw OAuthException.InvalidRequest("redirect_uri does not match any registered URI for this client.");
        }

        // 3. Validate scopes
        var requestedScopes = request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!client.AreScopesAllowed(requestedScopes))
        {
            throw OAuthException.InvalidScope($"One or more requested scopes are not allowed for client '{request.ClientId}'.");
        }

        // 4. Authenticate demo user (Phase 1: auto-authenticate single demo user)
        var user = await _userStore.GetDemoUserAsync(cancellationToken);
        if (user is null)
        {
            throw OAuthException.InvalidRequest("Demo user not available.");
        }

        // 5. Generate cryptographically secure authorization code
        var codeBytes = RandomNumberGenerator.GetBytes(AuthCodeByteLength);
        var code = Convert.ToBase64String(codeBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        // 6. Store authorization code with PKCE binding
        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            UserId = user.UserId,
            Scope = request.Scope,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(AuthCodeLifetimeSeconds),
        };

        await _codeStore.StoreAsync(authCode, cancellationToken);

        _logger.LogInformation(
            "Authorization code issued for client {ClientId}, user {UserId}",
            request.ClientId, user.UserId);

        return new AuthorizeUserResult(code, request.State, request.RedirectUri);
    }
}
