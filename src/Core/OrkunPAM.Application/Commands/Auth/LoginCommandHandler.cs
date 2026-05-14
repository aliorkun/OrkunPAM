using MediatR;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Auth;

public sealed class LoginCommandHandler : IRequestHandler<LoginCommand, Result<LoginResponse>>
{
    private readonly IAuthenticationService _auth;
    private readonly IAuditService _audit;
    private readonly ILogger<LoginCommandHandler> _logger;

    public LoginCommandHandler(
        IAuthenticationService auth,
        IAuditService audit,
        ILogger<LoginCommandHandler> logger)
    {
        _auth = auth;
        _audit = audit;
        _logger = logger;
    }

    public async Task<Result<LoginResponse>> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        var result = await _auth.LoginLocalAsync(request.Username, request.Password, request.IpAddress, cancellationToken);

        if (result.IsFailure)
        {
            await _audit.LogAsync("Auth", "LoginFailed", null, request.Username, request.IpAddress,
                "User", null, new { Reason = result.Error.Message },
                AuditOutcome.Failure, cancellationToken);

            return Result<LoginResponse>.Failure(result.Error);
        }

        var auth = result.Value;

        await _audit.LogAsync("Auth", "LoginSuccess", auth.UserId, auth.Username, request.IpAddress,
            "User", auth.UserId.ToString(), new { auth.MfaRequired, auth.MustChangePassword },
            AuditOutcome.Success, cancellationToken);

        var response = new LoginResponse(
            auth.Tokens.AccessToken,
            auth.Tokens.RefreshToken,
            auth.Tokens.AccessTokenExpiry,
            auth.Tokens.RefreshTokenExpiry,
            auth.UserId,
            auth.Username,
            auth.DisplayName,
            auth.MfaRequired,
            auth.MustChangePassword,
            auth.PasswordExpired);

        return Result<LoginResponse>.Success(response);
    }
}
