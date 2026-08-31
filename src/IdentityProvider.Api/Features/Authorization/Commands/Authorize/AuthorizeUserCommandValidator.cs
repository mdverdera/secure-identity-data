using FluentValidation;

namespace IdentityProvider.Api.Features.Authorization.Commands.Authorize;

public sealed class AuthorizeUserCommandValidator : AbstractValidator<AuthorizeUserCommand>
{
    public AuthorizeUserCommandValidator()
    {
        RuleFor(x => x.ClientId)
            .NotEmpty().WithMessage("client_id is required.");

        RuleFor(x => x.RedirectUri)
            .NotEmpty().WithMessage("redirect_uri is required.")
            .Must(uri => Uri.TryCreate(uri, UriKind.Absolute, out _))
            .WithMessage("redirect_uri must be a valid absolute URI.");

        RuleFor(x => x.ResponseType)
            .NotEmpty().WithMessage("response_type is required.")
            .Equal("code").WithMessage("unsupported_response_type: only 'code' is supported.");

        RuleFor(x => x.Scope)
            .NotEmpty().WithMessage("scope is required.");

        RuleFor(x => x.CodeChallenge)
            .NotEmpty().WithMessage("code_challenge is required (PKCE is mandatory).");

        RuleFor(x => x.CodeChallengeMethod)
            .NotEmpty().WithMessage("code_challenge_method is required.")
            .Equal("S256").WithMessage("unsupported code_challenge_method: only 'S256' is supported.");
    }
}
