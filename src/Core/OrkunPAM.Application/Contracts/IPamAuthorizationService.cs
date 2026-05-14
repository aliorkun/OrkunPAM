namespace OrkunPAM.Application.Contracts;

public interface IPamAuthorizationService
{
    Task<bool> CanAccessCredentialAsync(Guid userId, bool isAdmin, Guid credentialId, CancellationToken ct = default);
}
