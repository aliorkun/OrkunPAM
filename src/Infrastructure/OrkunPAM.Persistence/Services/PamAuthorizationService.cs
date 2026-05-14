using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public sealed class PamAuthorizationService : IPamAuthorizationService
{
    private readonly OrkunPamDbContext _db;

    public PamAuthorizationService(OrkunPamDbContext db) => _db = db;

    public async Task<bool> CanAccessCredentialAsync(Guid userId, bool isAdmin, Guid credentialId, CancellationToken ct = default)
    {
        if (isAdmin) return true;

        var cred = await _db.Credentials
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == credentialId, ct);

        if (cred is null) return false;

        var userGroupIds = await _db.UserGroups
            .Where(ug => ug.UserId == userId)
            .Select(ug => ug.GroupId)
            .ToListAsync(ct);

        var hasAccess = await _db.CredentialPermissions.AnyAsync(p =>
            (p.CredentialId == cred.Id || p.FolderId == cred.FolderId)
            && ((p.PrincipalType == PrincipalType.User && p.PrincipalId == userId)
                || (p.PrincipalType == PrincipalType.Group && userGroupIds.Contains(p.PrincipalId))),
            ct);

        if (!hasAccess) return false;

        if (cred.RequiresApproval &&
            !(cred.CheckedOutByUserId == userId && cred.Status == CredentialStatus.CheckedOut))
            return false;

        return true;
    }
}
