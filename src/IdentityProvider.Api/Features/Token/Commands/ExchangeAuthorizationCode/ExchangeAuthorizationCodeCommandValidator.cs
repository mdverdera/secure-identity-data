using FluentValidation;

namespace IdentityProvider.Api.Features.Token.Commands.ExchangeAuthorizationCode;

public sealed class ExchangeAuthorizationCodeCommandValidator
    : AbstractValidator<ExchangeAuthorizationCodeCommand>
{
    public ExchangeAuthorizationCodeCommandValidator()
    {
        RuleFor(x => x.GrantType)
            .NotEmpty().WithMessage("grant_type is required.")
            .Equal("authorization_code").WithMessage("unsupported_grant_type: only 'authorization_code' is supported.");

        RuleFor(x => x.Code)
            .NotEmpty().WithMessage("code is required.");

        RuleFor(x => x.RedirectUri)
            .NotEmpty().WithMessage("redirect_uri is required.");

        RuleFor(x => x.ClientId)
            .NotEmpty().WithMessage("client_id is required.");

        RuleFor(x => x.CodeVerifier)
            .NotEmpty().WithMessage("code_verifier is required (PKCE is mandatory).")
            .MinimumLength(43).WithMessage("code_verifier must be at least 43 characters (RFC 7636).")
            .MaximumLength(128).WithMessage("code_verifier must not exceed 128 characters (RFC 7636).");
    }
}
