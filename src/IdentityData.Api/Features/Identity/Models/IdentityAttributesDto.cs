namespace IdentityData.Api.Features.Identity.Models;

public sealed record IdentityAttributesDto(
    string Subject,
    string Name,
    string Email,
    DateOnly DateOfBirth
);
