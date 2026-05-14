using FluentValidation;

namespace OrkunPAM.Application.Commands.Sessions;

public sealed class StartSessionCommandValidator : AbstractValidator<StartSessionCommand>
{
    public StartSessionCommandValidator()
    {
        RuleFor(x => x.DeviceId)
            .NotEmpty().WithMessage("Device ID is required.");

        RuleFor(x => x.CredentialId)
            .NotEmpty().WithMessage("Credential ID is required.");

        RuleFor(x => x.SessionType)
            .IsInEnum().WithMessage("Invalid session type.");

        RuleFor(x => x.Reason)
            .MaximumLength(500).When(x => x.Reason != null)
            .WithMessage("Reason must not exceed 500 characters.");

        RuleFor(x => x.TicketNumber)
            .MaximumLength(50).When(x => x.TicketNumber != null)
            .WithMessage("Ticket number must not exceed 50 characters.");
    }
}
