namespace IdentityData.Api.Infrastructure.Authentication;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Audience { get; init; } = string.Empty;
}
