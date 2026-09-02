using IdentityData.Api.Domain.ValueObjects;
using MediatR;

namespace IdentityData.Api.Application.Features.Identity.Queries.GetIdentityAttributes;

/// <summary>
/// Query to retrieve all identity attributes for the authenticated user.
/// </summary>
public sealed record GetIdentityAttributesQuery(string UserId) : IRequest<IReadOnlyList<IdentityAttributeResult>>;
