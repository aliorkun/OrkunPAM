using Microsoft.AspNetCore.SignalR;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Hubs;

/// <summary>
/// Bridges the in-process event bus to connected SignalR monitor clients.
/// Injects InProcessEventBus directly because Subscribe() is not on the IEventBus interface.
/// </summary>
internal sealed class SessionEventRelayService : IHostedService
{
    private readonly InProcessEventBus _bus;
    private readonly IHubContext<SessionMonitorHub> _hub;

    public SessionEventRelayService(InProcessEventBus bus, IHubContext<SessionMonitorHub> hub)
    {
        _bus = bus;
        _hub = hub;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _bus.Subscribe(async (evt, token) =>
        {
            switch (evt)
            {
                case SessionStartedEvent e:
                    await _hub.Clients.Group("monitor").SendAsync("SessionUpdate", new
                    {
                        sessionId    = e.SessionId,
                        eventType    = "Started",
                        sessionType  = e.SessionType,
                        targetDevice = e.TargetDevice,
                        actor        = e.ActorUsername,
                        timestamp    = e.OccurredAtUtc
                    }, token);
                    break;

                case SessionTerminatedEvent e:
                    await _hub.Clients.Group("monitor").SendAsync("SessionUpdate", new
                    {
                        sessionId = e.SessionId,
                        eventType = "Terminated",
                        reason    = e.Reason,
                        actor     = e.ActorUsername,
                        timestamp = e.OccurredAtUtc
                    }, token);
                    break;

                case CommandBlockedEvent e:
                    await _hub.Clients.Group("monitor").SendAsync("CommandBlocked", new
                    {
                        sessionId = e.SessionId,
                        command   = e.Command,
                        rule      = e.Rule,
                        actor     = e.ActorUsername,
                        timestamp = e.OccurredAtUtc
                    }, token);
                    break;
            }
        });

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
