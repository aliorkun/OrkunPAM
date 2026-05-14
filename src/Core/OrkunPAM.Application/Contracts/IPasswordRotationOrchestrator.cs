using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Orchestrates password rotation across target systems.
/// </summary>
public interface IPasswordRotationOrchestrator
{
    Task<Result> RotateAsync(Guid credentialId, CancellationToken ct = default);
}
