using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Sessions;

public record GetSessionRecordingQuery(Guid SessionId) : IRequest<Result<SessionRecordingDto>>;
