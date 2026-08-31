using MediatR;

namespace IdentityProvider.Api.Features.Authorization.Commands.Authorize;

/// <summary>
/// Command: validate an OAuth authorization request, authenticate the demo user,
/// and issue a single-use PKCE-bound authorization code.
/// </summary>
public sealed record AuthorizeUserCommand(
    string ClientId,
    string RedirectUri,
    string ResponseType,
    string Scope,
    string State,
    string CodeChallenge,
    string CodeChallengeMethod
) : IRequest<AuthorizeUserResult>;

/// <summary>
/// Result of a successful authorization — the code and state to redirect back to the client.
/// </summary>
public sealed record AuthorizeUserResult(
    string Code,
    string State,
    string RedirectUri
);
