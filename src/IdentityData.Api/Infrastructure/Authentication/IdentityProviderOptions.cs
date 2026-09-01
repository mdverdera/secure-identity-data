namespace IdentityData.Api.Infrastructure.Authentication;

public sealed class IdentityProviderOptions
{
    public const string SectionName = "IdentityProvider";

    public string Authority { get; init; } = string.Empty;
    public string Issuer { get; init; } = string.Empty;
    public string JwksUri { get; init; } = string.Empty;
}
