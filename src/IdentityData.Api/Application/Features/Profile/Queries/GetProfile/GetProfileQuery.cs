using MediatR;

namespace IdentityData.Api.Application.Features.Profile.Queries.GetProfile;

/// <summary>
/// Query to retrieve the profile of the authenticated user.
/// </summary>
public sealed record GetProfileQuery(string UserId) : IRequest<ProfileResult>;
