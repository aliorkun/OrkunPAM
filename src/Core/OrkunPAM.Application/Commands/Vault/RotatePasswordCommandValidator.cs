using FluentValidation;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class RotatePasswordCommandValidator : AbstractValidator<RotatePasswordCommand>
{
    public RotatePasswordCommandValidator()
    {
        RuleFor(x => x.CredentialId)
            .NotEmpty().WithMessage("Credential ID is required.");
    }
}
