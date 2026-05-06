using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class IntegrationEndpoints
{
    public static void MapIntegrationEndpoints(this WebApplication app)
    {
        // === Webhooks ===
        var webhooks = app.MapGroup("/api/v1/integrations/webhooks").WithTags("Integrations");

        webhooks.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.Set<WebhookConfig>()
                .Select(w => new
                {
                    w.Id, w.Name, w.Url, w.IsEnabled,
                    w.TimeoutSeconds, w.RetryCount,
                    w.LastDeliveryAtUtc, w.LastDeliverySuccess
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        webhooks.MapPost("/", async (CreateWebhookRequest req, OrkunPamDbContext db) =>
        {
            var webhook = new WebhookConfig
            {
                Name = req.Name,
                Url = req.Url,
                Secret = req.Secret,
                EventTypesJson = req.EventTypes ?? "[]",
                TimeoutSeconds = req.TimeoutSeconds ?? 10,
                RetryCount = req.RetryCount ?? 3
            };
            db.Set<WebhookConfig>().Add(webhook);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/webhooks/{webhook.Id}",
                new { success = true, data = new { webhook.Id, webhook.Name } });
        });

        webhooks.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var wh = await db.Set<WebhookConfig>().FindAsync(id);
            if (wh == null) return Results.NotFound(new { success = false, errors = new[] { "Webhook not found" } });

            // TODO: Actually send test payload to webhook URL
            logger.LogInformation("Testing webhook '{Name}' at {Url}", wh.Name, wh.Url);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    url = wh.Url,
                    message = "Test webhook delivery (placeholder - actual HTTP POST in full implementation)"
                }
            });
        });

        // === ITSM ===
        var itsm = app.MapGroup("/api/v1/integrations/itsm").WithTags("Integrations");

        itsm.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.Set<ItsmConfig>()
                .Select(i => new
                {
                    i.Id, i.Name, i.Provider, i.BaseUrl,
                    i.RequireTicket, i.ValidateTicket, i.IsEnabled
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        itsm.MapPost("/", async (CreateItsmConfigRequest req, OrkunPamDbContext db) =>
        {
            var config = new ItsmConfig
            {
                Name = req.Name,
                Provider = req.Provider,
                BaseUrl = req.BaseUrl,
                Username = req.Username,
                RequireTicket = req.RequireTicket,
                ValidateTicket = req.ValidateTicket
            };
            db.Set<ItsmConfig>().Add(config);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/itsm/{config.Id}",
                new { success = true, data = new { config.Id, config.Name, config.Provider } });
        });

        itsm.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var cfg = await db.Set<ItsmConfig>().FindAsync(id);
            if (cfg == null) return Results.NotFound(new { success = false, errors = new[] { "ITSM config not found" } });

            logger.LogInformation("Testing ITSM connection to {Provider} at {Url}", cfg.Provider, cfg.BaseUrl);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    provider = cfg.Provider,
                    baseUrl = cfg.BaseUrl,
                    message = $"Connection test to {cfg.Provider} (placeholder - actual API call in full implementation)"
                }
            });
        });

        itsm.MapPost("/validate-ticket", (ValidateTicketRequest req) =>
        {
            // TODO: Call ITSM API to validate ticket
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    ticketNumber = req.TicketNumber,
                    valid = true,
                    message = "Ticket validation placeholder"
                }
            });
        });

        // === Notification Channels ===
        var notifications = app.MapGroup("/api/v1/integrations/notifications").WithTags("Integrations");

        notifications.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.Set<NotificationConfig>()
                .Select(n => new { n.Id, n.Channel, n.IsEnabled })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        notifications.MapPost("/", async (CreateNotificationConfigRequest req, OrkunPamDbContext db) =>
        {
            var config = new NotificationConfig
            {
                Channel = req.Channel,
                ConfigJson = req.ConfigJson ?? "{}"
            };
            db.Set<NotificationConfig>().Add(config);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/notifications/{config.Id}",
                new { success = true, data = new { config.Id, config.Channel } });
        });

        notifications.MapPost("/test", (TestNotificationRequest req, ILogger<Program> logger) =>
        {
            logger.LogInformation("Sending test notification via {Channel} to {Recipient}", req.Channel, req.Recipient);

            return Results.Ok(new
            {
                success = true,
                message = $"Test {req.Channel} notification sent to {req.Recipient} (placeholder)"
            });
        });
    }
}

public record CreateWebhookRequest(string Name, string Url, string? Secret, string? EventTypes, int? TimeoutSeconds, int? RetryCount);
public record CreateItsmConfigRequest(string Name, string Provider, string BaseUrl, string? Username, bool RequireTicket, bool ValidateTicket);
public record ValidateTicketRequest(string TicketNumber, string? Provider);
public record CreateNotificationConfigRequest(string Channel, string? ConfigJson);
public record TestNotificationRequest(string Channel, string Recipient);
