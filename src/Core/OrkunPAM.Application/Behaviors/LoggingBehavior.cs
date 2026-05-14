using System.Diagnostics;
using MediatR;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Application.Behaviors;

/// <summary>
/// MediatR pipeline behavior that logs command/query name and execution duration.
/// Warns on slow operations (> 500ms).
/// </summary>
public sealed class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
{
    private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;
    private const int SlowThresholdMs = 500;

    public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        var requestName = typeof(TRequest).Name;
        var traceId = Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("N")[..8];

        _logger.LogDebug("[{TraceId}] Handling {RequestName}", traceId, requestName);

        var sw = Stopwatch.StartNew();
        var response = await next();
        sw.Stop();

        if (sw.ElapsedMilliseconds > SlowThresholdMs)
        {
            _logger.LogWarning("[{TraceId}] {RequestName} completed in {ElapsedMs}ms (SLOW)",
                traceId, requestName, sw.ElapsedMilliseconds);
        }
        else
        {
            _logger.LogDebug("[{TraceId}] {RequestName} completed in {ElapsedMs}ms",
                traceId, requestName, sw.ElapsedMilliseconds);
        }

        return response;
    }
}
