namespace OrkunPAM.SharedKernel;

/// <summary>
/// Railway-oriented error handling. Every operation returns Result instead of throwing.
/// </summary>
public sealed class Result
{
    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public Error Error { get; }

    private Result(bool isSuccess, Error error)
    {
        IsSuccess = isSuccess;
        Error = error;
    }

    public static Result Success() => new(true, Error.None);
    public static Result Failure(Error error) => new(false, error);
    public static Result<T> Success<T>(T value) => Result<T>.Success(value);
    public static Result<T> Failure<T>(Error error) => Result<T>.Failure(error);
}

public sealed class Result<T>
{
    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public T Value { get; }
    public Error Error { get; }

    private Result(bool isSuccess, T value, Error error)
    {
        IsSuccess = isSuccess;
        Value = value;
        Error = error;
    }

    public static Result<T> Success(T value) => new(true, value, Error.None);
    public static Result<T> Failure(Error error) => new(false, default!, error);

    public Result<TOut> Map<TOut>(Func<T, TOut> mapper) =>
        IsSuccess ? Result<TOut>.Success(mapper(Value)) : Result<TOut>.Failure(Error);

    public async Task<Result<TOut>> MapAsync<TOut>(Func<T, Task<TOut>> mapper) =>
        IsSuccess ? Result<TOut>.Success(await mapper(Value)) : Result<TOut>.Failure(Error);
}

public sealed record Error(string Code, string Message, string? Detail = null)
{
    public static readonly Error None = new(string.Empty, string.Empty);
    public static Error Validation(string message, string? detail = null) => new("Validation", message, detail);
    public static Error NotFound(string entity, object id) => new("NotFound", $"{entity} with id '{id}' not found.");
    public static Error Conflict(string message) => new("Conflict", message);
    public static Error Unauthorized(string message = "Unauthorized") => new("Unauthorized", message);
    public static Error Forbidden(string message = "Access denied") => new("Forbidden", message);
    public static Error Internal(string message, string? detail = null) => new("Internal", message, detail);

    // Troubleshoot-friendly errors with actionable context
    public static Error Connection(string target, string reason, string? suggestion = null) =>
        new("ConnectionError", $"Failed to connect to {target}: {reason}", suggestion);
    public static Error Rotation(string credential, string reason, string? suggestion = null) =>
        new("RotationError", $"Password rotation failed for '{credential}': {reason}", suggestion);
    public static Error Encryption(string operation, string reason) =>
        new("EncryptionError", $"Encryption {operation} failed: {reason}");
}
