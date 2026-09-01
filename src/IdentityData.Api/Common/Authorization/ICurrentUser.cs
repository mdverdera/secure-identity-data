namespace IdentityData.Api.Common.Authorization;

public interface ICurrentUser
{
    string Subject { get; }
    IReadOnlyList<string> Scopes { get; }
    string? ClientId { get; }
    bool HasScope(string scope);
}
