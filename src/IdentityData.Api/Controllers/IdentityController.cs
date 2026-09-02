using IdentityData.Api.Application.Features.Identity.Queries.GetIdentityAttributes;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityData.Api.Controllers;

/// <summary>
/// Exposes the authenticated user's identity attributes with sensitivity classification.
/// Requires a valid JWT with the <c>identity.read</c> scope.
///
/// ⚠️ All data served by this controller is fictional test data.
/// This API does NOT connect to any real government identity system.
/// </summary>
[ApiController]
[Route("api/identity")]
[Authorize(AuthenticationSchemes = "Bearer,DPoP", Policy = "IdentityReadScope")]
public sealed class IdentityController : ControllerBase
{
    private readonly IMediator _mediator;

    public IdentityController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// Returns all identity attributes for the token holder, with sensitivity labels.
    /// </summary>
    /// <response code="200">Attributes returned successfully.</response>
    /// <response code="401">Missing or invalid bearer token.</response>
    /// <response code="403">Token lacks the required <c>identity.read</c> scope.</response>
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<IdentityAttributeResult>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetIdentityAttributes(CancellationToken cancellationToken)
    {
        var userId = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(userId))
            return Unauthorized();

        var results = await _mediator.Send(new GetIdentityAttributesQuery(userId), cancellationToken);
        return Ok(results);
    }
}
