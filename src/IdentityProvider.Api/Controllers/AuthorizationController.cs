using IdentityProvider.Api.Features.Authorization.Commands.Authorize;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Api.Controllers;

/// <summary>
/// Handles OAuth 2.x Authorization Code requests.
///
/// This is a DEMO identity provider. It auto-authenticates a single fictional
/// test user and immediately issues an authorization code. In a production
/// system this endpoint would redirect the user to a login/consent page.
///
/// ⚠️  DEMO IDENTITY PROVIDER — Not for production use.
/// </summary>
[ApiController]
public sealed class AuthorizationController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthorizationController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// OAuth 2.x Authorization Endpoint.
    /// Validates the authorization request and redirects back with an authorization code.
    /// </summary>
    /// <remarks>
    /// Required parameters: client_id, redirect_uri, response_type=code, scope,
    /// state, code_challenge, code_challenge_method=S256
    /// </remarks>
    [HttpGet("/oauth/authorize")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "client_id")] string clientId = "",
        [FromQuery(Name = "redirect_uri")] string redirectUri = "",
        [FromQuery(Name = "response_type")] string responseType = "",
        [FromQuery(Name = "scope")] string scope = "",
        [FromQuery(Name = "state")] string state = "",
        [FromQuery(Name = "code_challenge")] string codeChallenge = "",
        [FromQuery(Name = "code_challenge_method")] string codeChallengeMethod = "",
        CancellationToken cancellationToken = default)
    {
        var command = new AuthorizeUserCommand(
            ClientId: clientId,
            RedirectUri: redirectUri,
            ResponseType: responseType,
            Scope: scope,
            State: state,
            CodeChallenge: codeChallenge,
            CodeChallengeMethod: codeChallengeMethod);

        var result = await _mediator.Send(command, cancellationToken);

        // Redirect back to client with code and state
        var callbackUri = $"{result.RedirectUri}?code={Uri.EscapeDataString(result.Code)}&state={Uri.EscapeDataString(result.State)}";
        return Redirect(callbackUri);
    }
}
