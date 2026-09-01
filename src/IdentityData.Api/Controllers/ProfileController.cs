using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Features.Profile.Models;
using IdentityData.Api.Features.Profile.Queries.GetProfile;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityData.Api.Controllers;

[ApiController]
[Route("api/profile")]
[Produces("application/json")]
public sealed class ProfileController : ControllerBase
{
    private readonly IMediator _mediator;

    public ProfileController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// Gets the authenticated user's profile.
    /// </summary>
    /// <remarks>
    /// Requires a valid JWT Bearer access token with scope: <c>identity.read</c>.
    /// The user identity is derived from the access token — the caller cannot specify an arbitrary user ID.
    /// </remarks>
    /// <returns>The authenticated user's profile.</returns>
    /// <response code="200">Profile returned successfully.</response>
    /// <response code="401">Missing or invalid access token.</response>
    /// <response code="403">Valid token but missing required scope: identity.read</response>
    /// <response code="404">Authenticated user not found in database.</response>
    [HttpGet]
    [Authorize(Policy = Policies.IdentityRead)]
    [ProducesResponseType(typeof(ProfileDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ProfileDto>> GetProfile(CancellationToken cancellationToken)
    {
        var result = await _mediator.Send(new GetProfileQuery(), cancellationToken);
        return Ok(result);
    }
}
