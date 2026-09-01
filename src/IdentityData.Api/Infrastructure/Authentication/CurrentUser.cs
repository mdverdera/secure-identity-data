using IdentityData.Api.Common.Authorization;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace IdentityData.Api.Infrastructure.Authentication;

public sealed class CurrentUser : ICurrentUser
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUser(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    private ClaimsPrincipal? Principal => _httpContextAccessor.HttpContext?.User;

    public string Subject =>
        Principal?.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? Principal?.FindFirstValue("sub")
        ?? throw new InvalidOperationException("No authenticated subject in current context.");

    public IReadOnlyList<string> Scopes
    {
        get
        {
            var scopeClaim = Principal?.FindFirstValue("scope");
            if (string.IsNullOrWhiteSpace(scopeClaim))
                return [];

            return scopeClaim
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .ToList()
                .AsReadOnly();
        }
    }

    public string? ClientId => Principal?.FindFirstValue("client_id");

    public bool HasScope(string scope) =>
        Scopes.Contains(scope, StringComparer.OrdinalIgnoreCase);
}
