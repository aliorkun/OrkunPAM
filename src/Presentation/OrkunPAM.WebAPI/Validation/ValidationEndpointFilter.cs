using FluentValidation;

namespace OrkunPAM.WebAPI.Validation;

internal sealed class ValidationEndpointFilter(IServiceProvider sp) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        foreach (var arg in ctx.Arguments)
        {
            if (arg is null) continue;

            var validatorType = typeof(IValidator<>).MakeGenericType(arg.GetType());
            if (sp.GetService(validatorType) is not IValidator validator) continue;

            var validationCtx = new ValidationContext<object>(arg);
            var result = await validator.ValidateAsync(
                validationCtx, ctx.HttpContext.RequestAborted);

            if (!result.IsValid)
            {
                var errors = result.Errors.Select(e => e.ErrorMessage).ToArray();
                return Results.BadRequest(new { success = false, errors });
            }
        }

        return await next(ctx);
    }
}
