using FluentValidation;

namespace OrkunPAM.Application.Commands.Users;

public sealed class UpdateUserCommandValidator : AbstractValidator<UpdateUserCommand>
{
    public UpdateUserCommandValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("User ID is required.");

        RuleFor(x => x.Email)
            .EmailAddress().When(x => !string.IsNullOrEmpty(x.Email))
            .WithMessage("Invalid email address format.");

        RuleFor(x => x.DisplayName)
            .MaximumLength(100).When(x => x.DisplayName != null)
            .WithMessage("Display name must not exceed 100 characters.");

        RuleFor(x => x.Language)
            .MaximumLength(10).When(x => x.Language != null)
            .WithMessage("Language code must not exceed 10 characters.");

        RuleFor(x => x.Timezone)
            .MaximumLength(50).When(x => x.Timezone != null)
            .WithMessage("Timezone must not exceed 50 characters.");
    }
}
