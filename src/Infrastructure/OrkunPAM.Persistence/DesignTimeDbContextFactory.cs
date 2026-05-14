using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace OrkunPAM.Persistence;

public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<OrkunPamDbContext>
{
    public OrkunPamDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<OrkunPamDbContext>();
        optionsBuilder.UseSqlServer(
            "Server=(localdb)\\mssqllocaldb;Database=OrkunPAM_Dev;Trusted_Connection=True;");
        return new OrkunPamDbContext(optionsBuilder.Options);
    }
}
