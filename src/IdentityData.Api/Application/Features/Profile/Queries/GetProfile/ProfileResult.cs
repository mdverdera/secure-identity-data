namespace IdentityData.Api.Application.Features.Profile.Queries.GetProfile;

/// <summary>
/// The profile data returned for the authenticated user.
/// All values are fictional test data.
/// </summary>
public sealed record ProfileResult(string UserId, string FullName, string Email);
