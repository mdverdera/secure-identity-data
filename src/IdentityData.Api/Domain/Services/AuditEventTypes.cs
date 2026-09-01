namespace IdentityData.Api.Domain.Services;

public static class AuditEventTypes
{
    public const string ProfileAccessed = "ProfileAccessed";
    public const string IdentityAccessed = "IdentityAccessed";
    public const string UnauthorizedRequest = "UnauthorizedRequest";
    public const string ForbiddenRequest = "ForbiddenRequest";
}
