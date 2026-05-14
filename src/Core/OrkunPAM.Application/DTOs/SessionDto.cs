using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Application.DTOs;

public record SessionDto(
    Guid Id,
    Guid UserId,
    Guid DeviceId,
    Guid CredentialId,
    SessionType SessionType,
    SessionStatus Status,
    DateTime StartedAtUtc,
    DateTime? EndedAtUtc,
    int? DurationSeconds,
    string? ClientIpAddress,
    string? TargetIpAddress,
    int? TargetPort,
    bool HasKeystrokeLog,
    bool HasOcrData,
    decimal RiskScore);

public record SessionRecordingDto(
    Guid SessionId,
    string? RecordingPath,
    long? RecordingSizeBytes,
    bool Exists);
