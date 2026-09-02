namespace IdentityData.Api.Domain.ValueObjects;

/// <summary>
/// Classifies how sensitive an identity attribute is.
/// </summary>
public enum Sensitivity
{
    Public,
    Restricted,
    Confidential,
}

/// <summary>
/// An individual attribute of a user's identity, tagged with its sensitivity level.
/// All values are fictional test data.
/// </summary>
public sealed record IdentityAttribute(string Name, string Value, Sensitivity Sensitivity);
