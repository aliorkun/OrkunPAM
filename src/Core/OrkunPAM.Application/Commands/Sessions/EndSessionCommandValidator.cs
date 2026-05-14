using FluentValidation;

namespace OrkunPAM.Application.Commands.Sessions;

public sealed class EndSessionCommandValidator : AbstractValidator<EndSessionCommand>
{
    public EndSessionCommandValidator()
    {
        RuleFor(x => x.SessionId)
            .NotEmpty().WithMessage("Session ID is required.");

        RuleFor(x => x.TerminationReason)
            .MaximumLength(500).When(x => x.TerminationReason != null)
            .WithMessage("Termination reason must not exceed 500 characters.");
    }
}
