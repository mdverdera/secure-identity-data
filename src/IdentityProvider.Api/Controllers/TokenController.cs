using IdentityProvider.Api.Features.Token.Commands.ExchangeAuthorizationCode;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Api.Controllers;

/// <summary>
/// Handles OAuth 2.x Token requests.
///
/// ⚠️  DEMO IDENTITY PROVIDER — Not for production use.
/// </summary>
[ApiController]
public sealed class TokenController : ControllerBase
{
    private readonly IMediator _mediator;

    public TokenController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// OAuth 2.x Token Endpoint.
    /// Exchanges an authorization code for a JWT access token.
    /// Performs full PKCE S256 verification before issuing the token.
    /// </summary>
    /// <remarks>
    /// Required parameters (application/x-www-form-urlencoded):
    /// grant_type=authorization_code, code, redirect_uri, client_id, code_verifier
    /// </remarks>
    [HttpPost("/oauth/token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Token(
        [FromForm(Name = "grant_type")] string grantType = "",
        [FromForm(Name = "code")] string code = "",
        [FromForm(Name = "redirect_uri")] string redirectUri = "",
        [FromForm(Name = "client_id")] string clientId = "",
        [FromForm(Name = "code_verifier")] string codeVerifier = "",
        CancellationToken cancellationToken = default)
    {
        var command = new ExchangeAuthorizationCodeCommand(
            GrantType: grantType,
            Code: code,
            RedirectUri: redirectUri,
            ClientId: clientId,
            CodeVerifier: codeVerifier);

        var result = await _mediator.Send(command, cancellationToken);

        return Ok(new TokenResponse(
            result.AccessToken,
            result.TokenType,
            result.ExpiresIn,
            result.Scope));
    }

    // Response DTO — snake_case serialized per OAuth spec
    private sealed record TokenResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")]
        string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")]
        string TokenType,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")]
        int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("scope")]
        string Scope
    );
}
