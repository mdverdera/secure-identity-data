using IdentityData.Api.Features.Profile.Models;
using MediatR;

namespace IdentityData.Api.Features.Profile.Queries.GetProfile;

public sealed record GetProfileQuery : IRequest<ProfileDto>;
