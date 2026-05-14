using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace OrkunPAM.Persistence.Services;

public static class MigrationRunner
{
    public static async Task ApplyMigrationsAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        await db.Database.MigrateAsync();
    }
}
