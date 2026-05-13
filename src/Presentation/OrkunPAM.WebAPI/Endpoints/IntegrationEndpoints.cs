using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class IntegrationEndpoints
{
    public static void MapIntegrationEndpoints(this IEndpointRouteBuilder app)
    {
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

        webhooks.MapPost("/", async (CreateWebhookRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault) =>
        {
            byte[]? secretEnc = null;
            if (!string.IsNullOrEmpty(req.Secret))
            {
                var encResult = vault.EncryptString(req.Secret, "WebhookSecret");
                if (encResult.IsFailure)
                    return Results.Problem("Failed to protect webhook secret");
                secretEnc = encResult.Value;
            }
            var webhook = new WebhookConfig
            {
                Name = req.Name,
                Url = req.Url,
                SecretEnc = secretEnc,
                EventTypesJson = req.EventTypes ?? "[]",
                TimeoutSeconds = req.TimeoutSeconds ?? 10,
                RetryCount = req.RetryCount ?? 3
            };
            db.Set<WebhookConfig>().Add(webhook);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/webhooks/{webhook.Id}",
                new { success = true, data = new { webhook.Id, webhook.Name } });
        });

        webhooks.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db,
            OrkunPAM.Persistence.Services.IWebhookDeliveryService webhookService,
            IVaultEncryptionService vault, ILogger<Program> logger) =>
        {
            var wh = await db.Set<WebhookConfig>().FindAsync(id);
            if (wh == null) return Results.NotFound(new { success = false, errors = new[] { "Webhook not found" } });

            logger.LogInformation("Testing webhook '{Name}' at {Url}", wh.Name, wh.Url);

            string? secret = null;
            if (wh.SecretEnc != null)
            {
                var decResult = vault.DecryptString(wh.SecretEnc);
                if (decResult.IsFailure)
                    return Results.Problem("Failed to retrieve webhook secret");
                secret = decResult.Value;
            }
            var result = await webhookService.SendTestAsync(wh.Url, secret, wh.TimeoutSeconds);

            wh.LastDeliveryAtUtc = DateTime.UtcNow;
            wh.LastDeliverySuccess = result.Success;
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = result.Success,
                data = new
                {
                    url = wh.Url,
                    statusCode = result.StatusCode,
                    responseTimeMs = result.ResponseTimeMs,
                    error = result.Error,
                    message = result.Success ? "Test webhook delivered successfully" : $"Delivery failed: {result.Error}"
                }
            });
        });

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

        itsm.MapPost("/", async (CreateItsmConfigRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault) =>
        {
            byte[]? apiKeyEnc = null;
            if (!string.IsNullOrEmpty(req.ApiKey))
            {
                var enc = vault.EncryptString(req.ApiKey, "ItsmApiKey");
                if (enc.IsFailure) return Results.Problem("Failed to protect ITSM API key");
                apiKeyEnc = enc.Value;
            }
            byte[]? passwordEnc = null;
            if (!string.IsNullOrEmpty(req.Password))
            {
                var enc = vault.EncryptString(req.Password, "ItsmPassword");
                if (enc.IsFailure) return Results.Problem("Failed to protect ITSM password");
                passwordEnc = enc.Value;
            }
            var config = new ItsmConfig
            {
                Name = req.Name,
                Provider = req.Provider,
                BaseUrl = req.BaseUrl,
                Username = req.Username,
                ApiKeyEnc = apiKeyEnc != null ? Convert.ToBase64String(apiKeyEnc) : null,
                PasswordEnc = passwordEnc != null ? Convert.ToBase64String(passwordEnc) : null,
                RequireTicket = req.RequireTicket,
                ValidateTicket = req.ValidateTicket
            };
            db.Set<ItsmConfig>().Add(config);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/itsm/{config.Id}",
                new { success = true, data = new { config.Id, config.Name, config.Provider } });
        });

        itsm.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db,
            OrkunPAM.Persistence.Services.IItsmService itsmService,
            IVaultEncryptionService vault, ILogger<Program> logger) =>
        {
            var cfg = await db.Set<ItsmConfig>().FindAsync(id);
            if (cfg == null) return Results.NotFound(new { success = false, errors = new[] { "ITSM config not found" } });

            logger.LogInformation("Testing ITSM connection to {Provider} at {Url}", cfg.Provider, cfg.BaseUrl);

            string? password = null;
            if (!string.IsNullOrEmpty(cfg.PasswordEnc))
            {
                var dec = vault.DecryptString(Convert.FromBase64String(cfg.PasswordEnc));
                if (dec.IsFailure) return Results.Problem("Failed to retrieve ITSM credentials");
                password = dec.Value;
            }
            string? apiKey = null;
            if (!string.IsNullOrEmpty(cfg.ApiKeyEnc))
            {
                var dec = vault.DecryptString(Convert.FromBase64String(cfg.ApiKeyEnc));
                if (dec.IsFailure) return Results.Problem("Failed to retrieve ITSM API key");
                apiKey = dec.Value;
            }
            var result = await itsmService.TestConnectionAsync(cfg.Provider, cfg.BaseUrl, cfg.Username, password, apiKey);

            return Results.Ok(new
            {
                success = result.Success,
                data = new
                {
                    provider = cfg.Provider,
                    baseUrl = cfg.BaseUrl,
                    responseTimeMs = result.ResponseTimeMs,
                    serverVersion = result.ServerVersion,
                    message = result.Message
                }
            });
        });

        itsm.MapPost("/validate-ticket", async (ValidateTicketRequest req, OrkunPamDbContext db,
            OrkunPAM.Persistence.Services.IItsmService itsmService, IVaultEncryptionService vault) =>
        {
            var cfg = !string.IsNullOrEmpty(req.Provider)
                ? await db.Set<ItsmConfig>().FirstOrDefaultAsync(c => c.Provider == req.Provider && c.IsEnabled)
                : await db.Set<ItsmConfig>().FirstOrDefaultAsync(c => c.IsEnabled && c.ValidateTicket);

            if (cfg == null)
                return Results.BadRequest(new { success = false, errors = new[] { "No active ITSM configuration found for ticket validation" } });

            string? password = null;
            if (!string.IsNullOrEmpty(cfg.PasswordEnc))
            {
                var dec = vault.DecryptString(Convert.FromBase64String(cfg.PasswordEnc));
                if (dec.IsFailure) return Results.Problem("Failed to retrieve ITSM credentials");
                password = dec.Value;
            }
            string? apiKey = null;
            if (!string.IsNullOrEmpty(cfg.ApiKeyEnc))
            {
                var dec = vault.DecryptString(Convert.FromBase64String(cfg.ApiKeyEnc));
                if (dec.IsFailure) return Results.Problem("Failed to retrieve ITSM API key");
                apiKey = dec.Value;
            }
            var result = await itsmService.ValidateTicketAsync(cfg.Provider, cfg.BaseUrl, req.TicketNumber, cfg.Username, password, apiKey);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    ticketNumber = req.TicketNumber,
                    valid = result.Valid,
                    status = result.TicketStatus,
                    summary = result.Summary,
                    assignee = result.Assignee,
                    message = result.Message
                }
            });
        });

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

        // === SIEM Syslog/CEF (#63) ===
        var siem = app.MapGroup("/api/v1/integrations/siem").WithTags("Integrations");

        siem.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.SiemTargets
                .OrderBy(t => t.Name)
                .Select(t => new
                {
                    t.Id, t.Name, t.Host, t.Port, t.Protocol, t.Format, t.Facility,
                    t.IsEnabled, t.LastSentAtUtc, t.TotalEventsSent, t.LastError
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        siem.MapPost("/", async (CreateSiemTargetRequest req, OrkunPamDbContext db) =>
        {
            var target = new SiemTarget
            {
                Name = req.Name,
                Host = req.Host,
                Port = req.Port,
                Protocol = req.Protocol,
                Format = req.Format,
                Facility = req.Facility,
                EventFilterJson = req.EventFilterJson ?? "[]"
            };
            db.SiemTargets.Add(target);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/integrations/siem/{target.Id}",
                new { success = true, data = new { target.Id, target.Name } });
        });

        siem.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var target = await db.SiemTargets.FindAsync(id);
            if (target == null) return Results.NotFound(new { success = false, errors = new[] { "SIEM target not found" } });
            db.SiemTargets.Remove(target);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        siem.MapPost("/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var target = await db.SiemTargets.FindAsync(id);
            if (target == null) return Results.NotFound(new { success = false, errors = new[] { "SIEM target not found" } });
            target.IsEnabled = !target.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { target.Id, target.IsEnabled } });
        });

        siem.MapPost("/{id:guid}/test", async (Guid id,
            ISiemForwarderService siemForwarder, ILogger<Program> logger) =>
        {
            logger.LogInformation("Testing SIEM target {Id}", id);
            var (success, error, ms) = await siemForwarder.TestTargetAsync(id);
            return Results.Ok(new
            {
                success,
                data = new { targetId = id, responseTimeMs = ms, error, message = success ? "Test message sent successfully" : error }
            });
        });
    }
}

public record CreateSiemTargetRequest(string Name, string Host, int Port, string Protocol, string Format, int Facility, string? EventFilterJson);
public record CreateWebhookRequest(string Name, string Url, string? Secret, string? EventTypes, int? TimeoutSeconds, int? RetryCount);
public record CreateItsmConfigRequest(string Name, string Provider, string BaseUrl, string? Username, string? ApiKey, string? Password, bool RequireTicket, bool ValidateTicket);
public record ValidateTicketRequest(string TicketNumber, string? Provider);
public record CreateNotificationConfigRequest(string Channel, string? ConfigJson);
public record TestNotificationRequest(string Channel, string Recipient);
