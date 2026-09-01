using IdentityData.Api.Common.Authorization;
using IdentityData.Api.Features.Identity.Models;
using IdentityData.Api.Features.Identity.Queries.GetIdentityAttributes;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityData.Api.Controllers;

[ApiController]
[Route("api/identity")]
[Produces("application/json")]
public sealed class IdentityController : ControllerBase
{
    private readonly IMediator _mediator;

    public IdentityController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// Gets the authenticated user's identity attributes.
    /// </summary>
    /// <remarks>
    /// Requires a valid JWT Bearer access token with scope: <c>identity.read</c>.
    /// Returns fictional identity information associated with the authenticated subject.
    /// </remarks>
    /// <returns>The authenticated user's identity attributes.</returns>
    /// <response code="200">Identity attributes returned successfully.</response>
    /// <response code="401">Missing or invalid access token.</response>
    /// <response code="403">Valid token but missing required scope: identity.read</response>
    /// <response code="404">Authenticated user not found in database.</response>
    [HttpGet]
    [Authorize(Policy = Policies.IdentityRead)]
    [ProducesResponseType(typeof(IdentityAttributesDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IdentityAttributesDto>> GetIdentityAttributes(CancellationToken cancellationToken)
    {
        var result = await _mediator.Send(new GetIdentityAttributesQuery(), cancellationToken);
        return Ok(result);
    }
}
