using FluentValidation;

namespace OrkunPAM.Application.Commands.Vault;

public sealed class CheckOutCredentialCommandValidator : AbstractValidator<CheckOutCredentialCommand>
{
    public CheckOutCredentialCommandValidator()
    {
        RuleFor(x => x.CredentialId)
            .NotEmpty().WithMessage("Credential ID is required.");

        RuleFor(x => x.MaxMinutes)
            .GreaterThan(0).When(x => x.MaxMinutes.HasValue)
            .WithMessage("Max minutes must be greater than 0.")
            .LessThanOrEqualTo(1440).When(x => x.MaxMinutes.HasValue)
            .WithMessage("Max minutes must not exceed 1440 (24 hours).");

        RuleFor(x => x.Reason)
            .MaximumLength(500).When(x => x.Reason != null)
            .WithMessage("Reason must not exceed 500 characters.");

        RuleFor(x => x.TicketNumber)
            .MaximumLength(50).When(x => x.TicketNumber != null)
            .WithMessage("Ticket number must not exceed 50 characters.");
    }
}
