using IdentityData.Api.Application.Features.Profile.Queries.GetProfile;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityData.Api.Controllers;

/// <summary>
/// Exposes the authenticated user's profile information.
/// Requires a valid JWT with the <c>identity.read</c> scope.
/// </summary>
[ApiController]
[Route("api/profile")]
[Authorize(AuthenticationSchemes = "Bearer,DPoP", Policy = "IdentityReadScope")]
public sealed class ProfileController : ControllerBase
{
    private readonly IMediator _mediator;

    public ProfileController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// Returns the basic profile (name, email) for the token holder.
    /// </summary>
    /// <response code="200">Profile returned successfully.</response>
    /// <response code="401">Missing or invalid bearer token.</response>
    /// <response code="403">Token lacks the required <c>identity.read</c> scope.</response>
    /// <response code="404">No identity record found for the authenticated user.</response>
    [HttpGet]
    [ProducesResponseType(typeof(ProfileResult), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetProfile(CancellationToken cancellationToken)
    {
        var userId = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(userId))
            return Unauthorized();

        var result = await _mediator.Send(new GetProfileQuery(userId), cancellationToken);
        return result is null ? NotFound() : Ok(result);
    }
}
