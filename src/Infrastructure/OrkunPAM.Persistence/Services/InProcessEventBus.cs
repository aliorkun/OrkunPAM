using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// In-process event bus for single-instance deployment.
/// Uses System.Threading.Channels for high-performance async pub/sub.
/// Consumers: audit logger, SIEM forwarder, webhook delivery, analytics engine.
/// </summary>
public sealed class InProcessEventBus : IEventBus, IDisposable
{
    private readonly Channel<IDomainEvent> _channel;
    private readonly List<Func<IDomainEvent, CancellationToken, Task>> _handlers = new();
    private readonly ILogger<InProcessEventBus> _logger;
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;

    public InProcessEventBus(ILogger<InProcessEventBus> logger)
    {
        _logger = logger;
        _channel = Channel.CreateBounded<IDomainEvent>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public void Subscribe(Func<IDomainEvent, CancellationToken, Task> handler)
    {
        _handlers.Add(handler);
    }

    public void StartProcessing()
    {
        _processingTask = Task.Run(async () =>
        {
            await foreach (var evt in _channel.Reader.ReadAllAsync(_cts.Token))
            {
                foreach (var handler in _handlers)
                {
                    try
                    {
                        await handler(evt, _cts.Token);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Event handler failed for {EventType}", evt.EventType);
                    }
                }
            }
        });

        _logger.LogInformation("Event bus started with {HandlerCount} handlers", _handlers.Count);
    }

    public async Task PublishAsync<T>(T @event, CancellationToken ct = default) where T : IDomainEvent
    {
        await _channel.Writer.WriteAsync(@event, ct);
    }

    public void Dispose()
    {
        _cts.Cancel();
        _channel.Writer.Complete();
        _processingTask?.Wait(TimeSpan.FromSeconds(5));
        _cts.Dispose();
    }
}

// === Common Domain Events ===

public abstract record PamEvent : IDomainEvent
{
    public DateTime OccurredAtUtc { get; init; } = DateTime.UtcNow;
    public abstract string EventType { get; }
    public Guid? ActorUserId { get; init; }
    public string? ActorUsername { get; init; }
    public string? ActorIp { get; init; }
}

public record UserLoggedInEvent : PamEvent
{
    public override string EventType => "User.Login.Success";
    public string AuthSource { get; init; } = string.Empty;
}

public record UserLoginFailedEvent : PamEvent
{
    public override string EventType => "User.Login.Failed";
    public string Reason { get; init; } = string.Empty;
}

public record CredentialCheckedOutEvent : PamEvent
{
    public override string EventType => "Vault.Credential.CheckedOut";
    public Guid CredentialId { get; init; }
    public string CredentialName { get; init; } = string.Empty;
    public string? Reason { get; init; }
}

public record CredentialCheckedInEvent : PamEvent
{
    public override string EventType => "Vault.Credential.CheckedIn";
    public Guid CredentialId { get; init; }
}

public record PasswordRotatedEvent : PamEvent
{
    public override string EventType => "Vault.Password.Rotated";
    public Guid CredentialId { get; init; }
    public string CredentialName { get; init; } = string.Empty;
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

public record SessionStartedEvent : PamEvent
{
    public override string EventType => "Session.Started";
    public Guid SessionId { get; init; }
    public string SessionType { get; init; } = string.Empty;
    public string TargetDevice { get; init; } = string.Empty;
}

public record SessionTerminatedEvent : PamEvent
{
    public override string EventType => "Session.Terminated";
    public Guid SessionId { get; init; }
    public string Reason { get; init; } = string.Empty;
}

public record CommandBlockedEvent : PamEvent
{
    public override string EventType => "Session.Command.Blocked";
    public Guid SessionId { get; init; }
    public string Command { get; init; } = string.Empty;
    public string Rule { get; init; } = string.Empty;
}

public record PolicyViolationEvent : PamEvent
{
    public override string EventType => "Policy.Violation";
    public string ViolationType { get; init; } = string.Empty;
    public string Details { get; init; } = string.Empty;
}

public record ApprovalRequestedEvent : PamEvent
{
    public override string EventType => "Workflow.Approval.Requested";
    public Guid RequestId { get; init; }
    public string ResourceType { get; init; } = string.Empty;
}

public record BreakGlassActivatedEvent : PamEvent
{
    public override string EventType => "Security.BreakGlass.Activated";
    public string Reason { get; init; } = string.Empty;
}
