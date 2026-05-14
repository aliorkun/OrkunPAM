using FluentValidation;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class CheckInCredentialCommandValidator : AbstractValidator<CheckInCredentialCommand>
{
    public CheckInCredentialCommandValidator()
    {
        RuleFor(x => x.CredentialId)
            .NotEmpty().WithMessage("Credential ID is required.");
    }
}
