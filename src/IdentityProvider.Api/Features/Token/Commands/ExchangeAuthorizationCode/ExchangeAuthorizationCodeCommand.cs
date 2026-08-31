using MediatR;

namespace IdentityProvider.Api.Features.Token.Commands.ExchangeAuthorizationCode;

/// <summary>
/// Command: exchange an authorization code for a JWT access token.
/// Performs full PKCE S256 verification before issuing the token.
/// </summary>
public sealed record ExchangeAuthorizationCodeCommand(
    string GrantType,
    string Code,
    string RedirectUri,
    string ClientId,
    string CodeVerifier
) : IRequest<ExchangeAuthorizationCodeResult>;

/// <summary>
/// Result: the issued token response per RFC 6749 §5.1.
/// </summary>
public sealed record ExchangeAuthorizationCodeResult(
    string AccessToken,
    string TokenType,
    int ExpiresIn,
    string Scope
);
