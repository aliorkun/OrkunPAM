using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class RdpProxySessionEndpoints
{
    public static void MapRdpProxySessionEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/rdp/proxy/sessions/{id}/status — RDP proxy polls to detect admin termination
        app.MapGet("/api/v1/rdp/proxy/sessions/{id:guid}/status",
            async (Guid id, OrkunPamDbContext db, IConfiguration config, HttpContext context) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            var session = await db.ProxySessions
                .Where(s => s.Id == id && s.SessionType == SessionType.Rdp)
                .Select(s => new { s.Status })
                .FirstOrDefaultAsync();

            if (session == null) return Results.NotFound();

            return Results.Ok(new
            {
                success = true,
                data = new { terminated = session.Status == SessionStatus.Terminated }
            });
        }).WithTags("RDP").AllowAnonymous();
    }

    private static bool ValidateProxySecret(HttpContext context, IConfiguration config)
    {
        var expected = config["ProxyService:Secret"] ?? config["PamApi:ProxySecret"] ?? "";
        if (expected.Length < 32) return false;
        var provided = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
        var expectedBytes = System.Text.Encoding.UTF8.GetBytes(expected);
        var providedBytes = System.Text.Encoding.UTF8.GetBytes(provided);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}
