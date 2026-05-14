using FluentValidation;
using MediatR;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Behaviors;

/// <summary>
/// MediatR pipeline behavior that runs FluentValidation validators before the handler.
/// Collects all validation errors and returns a Result failure if any exist.
/// </summary>
public sealed class ValidationBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    private readonly IEnumerable<IValidator<TRequest>> _validators;

    public ValidationBehavior(IEnumerable<IValidator<TRequest>> validators)
    {
        _validators = validators;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        if (!_validators.Any())
            return await next();

        var context = new ValidationContext<TRequest>(request);

        var validationResults = await Task.WhenAll(
            _validators.Select(v => v.ValidateAsync(context, cancellationToken)));

        var failures = validationResults
            .SelectMany(r => r.Errors)
            .Where(f => f != null)
            .ToList();

        if (failures.Count == 0)
            return await next();

        var errorMessage = string.Join("; ", failures.Select(f => f.ErrorMessage));
        var errorDetail = string.Join(Environment.NewLine, failures.Select(f => $"[{f.PropertyName}] {f.ErrorMessage}"));
        var error = Error.Validation(errorMessage, errorDetail);

        // Try to return Result<T>.Failure or Result.Failure depending on TResponse
        var responseType = typeof(TResponse);

        if (responseType == typeof(Result))
            return (TResponse)(object)Result.Failure(error);

        if (responseType.IsGenericType && responseType.GetGenericTypeDefinition() == typeof(Result<>))
        {
            var failureMethod = responseType.GetMethod(nameof(Result<object>.Failure),
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static,
                null, [typeof(Error)], null);

            if (failureMethod != null)
                return (TResponse)failureMethod.Invoke(null, [error])!;
        }

        // Fallback: throw if we can't construct a Result failure
        throw new ValidationException(failures);
    }
}
