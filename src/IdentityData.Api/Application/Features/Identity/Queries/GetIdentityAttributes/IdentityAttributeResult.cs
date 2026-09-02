using IdentityData.Api.Domain.ValueObjects;

namespace IdentityData.Api.Application.Features.Identity.Queries.GetIdentityAttributes;

/// <summary>
/// A single identity attribute with its sensitivity classification.
/// All values are fictional test data.
/// </summary>
public sealed record IdentityAttributeResult(string Name, string Value, Sensitivity Sensitivity);
