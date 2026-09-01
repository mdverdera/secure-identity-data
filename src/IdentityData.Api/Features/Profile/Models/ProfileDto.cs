namespace IdentityData.Api.Features.Profile.Models;

public sealed record ProfileDto(
    string Subject,
    string Name,
    string Email,
    DateOnly DateOfBirth
);
