using FluentValidation;

namespace OrkunPAM.Application.Commands.Auth;

public sealed class LoginCommandValidator : AbstractValidator<LoginCommand>
{
    public LoginCommandValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required.")
            .MaximumLength(100).WithMessage("Username must not exceed 100 characters.");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MaximumLength(256).WithMessage("Password must not exceed 256 characters.");

        RuleFor(x => x.IpAddress)
            .NotEmpty().WithMessage("IP address is required.");
    }
}
