using IdentityData.Api.Features.Identity.Models;
using MediatR;

namespace IdentityData.Api.Features.Identity.Queries.GetIdentityAttributes;

public sealed record GetIdentityAttributesQuery : IRequest<IdentityAttributesDto>;
