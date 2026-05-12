using System.Net;
using System.Text.Json;
using FluentValidation;
using OrkunPAM.WebAPI.Endpoints;

namespace OrkunPAM.WebAPI.Validators;

file static class V
{
    internal static bool ValidIp(string? ip) =>
        string.IsNullOrEmpty(ip) || IPAddress.TryParse(ip, out _);

    internal static bool ValidJson(string? json)
    {
        if (string.IsNullOrEmpty(json)) return true;
        try { JsonDocument.Parse(json); return true; }
        catch { return false; }
    }

    internal static bool ValidCidr(string? cidr)
    {
        if (string.IsNullOrEmpty(cidr)) return true;
        var parts = cidr.Split('/');
        return parts.Length == 2
            && IPAddress.TryParse(parts[0], out _)
            && int.TryParse(parts[1], out var p)
            && p is >= 0 and <= 128;
    }

    internal static bool ValidUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return true;
        return Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Password).NotEmpty().MaximumLength(256);
    }
}

public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MinimumLength(3).MaximumLength(50)
            .Matches(@"^[a-zA-Z0-9._@\-]+$")
            .WithMessage("Username may only contain letters, digits and ._@-");
        RuleFor(x => x.Password).NotEmpty().MinimumLength(8).MaximumLength(256);
        RuleFor(x => x.DisplayName).MaximumLength(100).When(x => x.DisplayName != null);
        RuleFor(x => x.Email).EmailAddress().MaximumLength(200)
            .When(x => !string.IsNullOrEmpty(x.Email));
    }
}

public sealed class MfaVerifyRequestValidator : AbstractValidator<MfaVerifyRequest>
{
    public MfaVerifyRequestValidator()
    {
        RuleFor(x => x.Code).NotEmpty().Length(6)
            .Matches(@"^\d{6}$").WithMessage("MFA code must be exactly 6 digits");
    }
}

public sealed class MfaDisableRequestValidator : AbstractValidator<MfaDisableRequest>
{
    public MfaDisableRequestValidator()
    {
        RuleFor(x => x.CurrentPassword).NotEmpty().MaximumLength(256);
        RuleFor(x => x.CurrentMfaCode).NotEmpty().Length(6)
            .Matches(@"^\d{6}$").WithMessage("MFA code must be exactly 6 digits");
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.NewPassword).NotEmpty().MinimumLength(8).MaximumLength(256);
    }
}

public sealed class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
{
    public UpdateUserRequestValidator()
    {
        RuleFor(x => x.DisplayName).MaximumLength(100).When(x => x.DisplayName != null);
        RuleFor(x => x.Email).EmailAddress().MaximumLength(200)
            .When(x => !string.IsNullOrEmpty(x.Email));
        RuleFor(x => x.Language).MaximumLength(10).When(x => x.Language != null);
        RuleFor(x => x.Timezone).MaximumLength(100).When(x => x.Timezone != null);
    }
}

public sealed class CreateFolderRequestValidator : AbstractValidator<CreateFolderRequest>
{
    public CreateFolderRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).MaximumLength(1000).When(x => x.Description != null);
    }
}

public sealed class CreateCredentialRequestValidator : AbstractValidator<CreateCredentialRequest>
{
    public CreateCredentialRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).MaximumLength(500).When(x => x.Description != null);
        RuleFor(x => x.Username).MaximumLength(100).When(x => x.Username != null);
        RuleFor(x => x.Password).MaximumLength(4096).When(x => x.Password != null);
        RuleFor(x => x.Tags).MaximumLength(500).When(x => x.Tags != null);
        RuleFor(x => x.MaxCheckoutMinutes).InclusiveBetween(1, 1440)
            .When(x => x.MaxCheckoutMinutes.HasValue);
    }
}

public sealed class CheckoutRequestValidator : AbstractValidator<CheckoutRequest>
{
    public CheckoutRequestValidator()
    {
        RuleFor(x => x.Reason).MaximumLength(500).When(x => x.Reason != null);
        RuleFor(x => x.TicketNumber).MaximumLength(50).When(x => x.TicketNumber != null);
        RuleFor(x => x.DurationMinutes).InclusiveBetween(1, 1440)
            .When(x => x.DurationMinutes.HasValue);
    }
}

public sealed class ShareCredentialRequestValidator : AbstractValidator<ShareCredentialRequest>
{
    public ShareCredentialRequestValidator()
    {
        RuleFor(x => x.SharedToUserId).NotEmpty();
        RuleFor(x => x.ExpiresInHours).GreaterThan(0).When(x => x.ExpiresInHours.HasValue);
        RuleFor(x => x.MaxUseCount).GreaterThan(0).When(x => x.MaxUseCount.HasValue);
    }
}

public sealed class CreateDeviceRequestValidator : AbstractValidator<CreateDeviceRequest>
{
    public CreateDeviceRequestValidator()
    {
        RuleFor(x => x.Hostname).NotEmpty().MaximumLength(253);
        RuleFor(x => x.Fqdn).MaximumLength(253).When(x => x.Fqdn != null);
        RuleFor(x => x.IpAddress).Must(V.ValidIp)
            .WithMessage("IpAddress must be a valid IP address")
            .When(x => !string.IsNullOrEmpty(x.IpAddress));
        RuleFor(x => x.Port).InclusiveBetween(1, 65535).When(x => x.Port.HasValue);
        RuleFor(x => x.Tags).MaximumLength(500).When(x => x.Tags != null);
        RuleFor(x => x.Notes).MaximumLength(2000).When(x => x.Notes != null);
        RuleFor(x => x.OperatingSystem).MaximumLength(100).When(x => x.OperatingSystem != null);
    }
}

public sealed class UpdateDeviceRequestValidator : AbstractValidator<UpdateDeviceRequest>
{
    public UpdateDeviceRequestValidator()
    {
        RuleFor(x => x.Hostname).MaximumLength(253).When(x => x.Hostname != null);
        RuleFor(x => x.Fqdn).MaximumLength(253).When(x => x.Fqdn != null);
        RuleFor(x => x.IpAddress).Must(V.ValidIp)
            .WithMessage("IpAddress must be a valid IP address")
            .When(x => !string.IsNullOrEmpty(x.IpAddress));
        RuleFor(x => x.Port).InclusiveBetween(1, 65535).When(x => x.Port.HasValue);
        RuleFor(x => x.Tags).MaximumLength(500).When(x => x.Tags != null);
        RuleFor(x => x.Notes).MaximumLength(2000).When(x => x.Notes != null);
        RuleFor(x => x.OperatingSystem).MaximumLength(100).When(x => x.OperatingSystem != null);
    }
}

public sealed class CreateDeviceGroupRequestValidator : AbstractValidator<CreateDeviceGroupRequest>
{
    public CreateDeviceGroupRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.SubnetCidr).Must(V.ValidCidr)
            .WithMessage("SubnetCidr must be valid CIDR notation (e.g. 192.168.1.0/24)")
            .When(x => !string.IsNullOrEmpty(x.SubnetCidr));
        RuleFor(x => x.VlanId).InclusiveBetween(1, 4094).When(x => x.VlanId.HasValue);
    }
}

public sealed class CreatePlatformRequestValidator : AbstractValidator<CreatePlatformRequest>
{
    public CreatePlatformRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Port).InclusiveBetween(1, 65535);
        RuleFor(x => x.RotationConnector).MaximumLength(100).When(x => x.RotationConnector != null);
        RuleFor(x => x.ConnectionTemplate).MaximumLength(500).When(x => x.ConnectionTemplate != null);
    }
}

public sealed class CreateGroupRequestValidator : AbstractValidator<CreateGroupRequest>
{
    public CreateGroupRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).MaximumLength(1000).When(x => x.Description != null);
    }
}

public sealed class UpdateGroupRequestValidator : AbstractValidator<UpdateGroupRequest>
{
    public UpdateGroupRequestValidator()
    {
        RuleFor(x => x.Name).MaximumLength(200).When(x => x.Name != null);
        RuleFor(x => x.Description).MaximumLength(1000).When(x => x.Description != null);
    }
}

public sealed class CreateRoleRequestValidator : AbstractValidator<CreateRoleRequest>
{
    public CreateRoleRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Description).MaximumLength(500).When(x => x.Description != null);
        RuleFor(x => x.PermissionCodes).Must(c => c == null || c.Length <= 200)
            .WithMessage("Maximum 200 permission codes per role");
    }
}

public sealed class CreatePolicyRequestValidator : AbstractValidator<CreatePolicyRequest>
{
    public CreatePolicyRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.PolicyType).NotEmpty().MaximumLength(50);
        RuleFor(x => x.PolicyJson).NotEmpty()
            .Must(V.ValidJson).WithMessage("PolicyJson must be valid JSON");
        RuleFor(x => x.Priority).InclusiveBetween(1, 1000);
    }
}

public sealed class UpdatePolicyRequestValidator : AbstractValidator<UpdatePolicyRequest>
{
    public UpdatePolicyRequestValidator()
    {
        RuleFor(x => x.Name).MaximumLength(200).When(x => x.Name != null);
        RuleFor(x => x.PolicyJson).Must(V.ValidJson)
            .WithMessage("PolicyJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.PolicyJson));
        RuleFor(x => x.Priority).InclusiveBetween(1, 1000).When(x => x.Priority.HasValue);
    }
}

public sealed class CreateSessionPolicyRequestValidator : AbstractValidator<CreateSessionPolicyRequest>
{
    public CreateSessionPolicyRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.MaxDurationMinutes).InclusiveBetween(1, 1440)
            .When(x => x.MaxDurationMinutes.HasValue);
        RuleFor(x => x.IdleTimeoutMinutes).InclusiveBetween(1, 480)
            .When(x => x.IdleTimeoutMinutes.HasValue);
        RuleFor(x => x.CommandFilterRulesJson).Must(V.ValidJson)
            .WithMessage("CommandFilterRulesJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.CommandFilterRulesJson));
    }
}

public sealed class UpdateSessionPolicyRequestValidator : AbstractValidator<UpdateSessionPolicyRequest>
{
    public UpdateSessionPolicyRequestValidator()
    {
        RuleFor(x => x.Name).MaximumLength(200).When(x => x.Name != null);
        RuleFor(x => x.MaxDurationMinutes).InclusiveBetween(1, 1440)
            .When(x => x.MaxDurationMinutes.HasValue);
        RuleFor(x => x.IdleTimeoutMinutes).InclusiveBetween(1, 480)
            .When(x => x.IdleTimeoutMinutes.HasValue);
    }
}

public sealed class ConnectRequestValidator : AbstractValidator<ConnectRequest>
{
    public ConnectRequestValidator()
    {
        RuleFor(x => x.Reason).MaximumLength(500).When(x => x.Reason != null);
        RuleFor(x => x.TicketNumber).MaximumLength(50).When(x => x.TicketNumber != null);
        RuleFor(x => x.ClientIp).Must(V.ValidIp)
            .WithMessage("ClientIp must be a valid IP address")
            .When(x => !string.IsNullOrEmpty(x.ClientIp));
    }
}

public sealed class TerminateSessionRequestValidator : AbstractValidator<TerminateSessionRequest>
{
    public TerminateSessionRequestValidator()
    {
        RuleFor(x => x.Reason).NotEmpty().MaximumLength(500);
    }
}

public sealed class CreateWorkflowRequestValidator : AbstractValidator<CreateWorkflowRequest>
{
    public CreateWorkflowRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).MaximumLength(1000).When(x => x.Description != null);
        RuleFor(x => x.TriggerType).NotEmpty().MaximumLength(50);
        RuleFor(x => x.StepsJson).Must(V.ValidJson)
            .WithMessage("StepsJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.StepsJson));
    }
}

public sealed class UpdateWorkflowRequestValidator : AbstractValidator<UpdateWorkflowRequest>
{
    public UpdateWorkflowRequestValidator()
    {
        RuleFor(x => x.Name).MaximumLength(200).When(x => x.Name != null);
        RuleFor(x => x.Description).MaximumLength(1000).When(x => x.Description != null);
        RuleFor(x => x.StepsJson).Must(V.ValidJson)
            .WithMessage("StepsJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.StepsJson));
    }
}

public sealed class CreateApprovalRequestValidator : AbstractValidator<CreateApprovalRequest>
{
    public CreateApprovalRequestValidator()
    {
        RuleFor(x => x.ResourceType).NotEmpty().MaximumLength(50);
        RuleFor(x => x.Reason).MaximumLength(500).When(x => x.Reason != null);
        RuleFor(x => x.TicketNumber).MaximumLength(50).When(x => x.TicketNumber != null);
        RuleFor(x => x.ExpiresInMinutes).InclusiveBetween(1, 10080)
            .When(x => x.ExpiresInMinutes.HasValue);
        RuleFor(x => x.ApproverIds).Must(ids => ids == null || ids.Length <= 20)
            .WithMessage("Maximum 20 approvers per request");
    }
}

public sealed class CreateLdapConfigRequestValidator : AbstractValidator<CreateLdapConfigRequest>
{
    public CreateLdapConfigRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Host).NotEmpty().MaximumLength(255);
        RuleFor(x => x.Port).InclusiveBetween(1, 65535).When(x => x.Port.HasValue);
        RuleFor(x => x.BaseDn).NotEmpty().MaximumLength(500);
        RuleFor(x => x.BindDn).MaximumLength(500).When(x => x.BindDn != null);
        RuleFor(x => x.UserSearchFilter).MaximumLength(500).When(x => x.UserSearchFilter != null);
        RuleFor(x => x.GroupSearchFilter).MaximumLength(500).When(x => x.GroupSearchFilter != null);
        RuleFor(x => x.SyncIntervalMinutes).InclusiveBetween(1, 1440)
            .When(x => x.SyncIntervalMinutes.HasValue);
    }
}

public sealed class UpdateLdapConfigRequestValidator : AbstractValidator<UpdateLdapConfigRequest>
{
    public UpdateLdapConfigRequestValidator()
    {
        RuleFor(x => x.Name).MaximumLength(100).When(x => x.Name != null);
        RuleFor(x => x.Host).MaximumLength(255).When(x => x.Host != null);
        RuleFor(x => x.Port).InclusiveBetween(1, 65535).When(x => x.Port.HasValue);
        RuleFor(x => x.BaseDn).MaximumLength(500).When(x => x.BaseDn != null);
        RuleFor(x => x.BindDn).MaximumLength(500).When(x => x.BindDn != null);
        RuleFor(x => x.SyncIntervalMinutes).InclusiveBetween(1, 1440)
            .When(x => x.SyncIntervalMinutes.HasValue);
    }
}

public sealed class CreateSamlProviderRequestValidator : AbstractValidator<CreateSamlProviderRequest>
{
    public CreateSamlProviderRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.EntityId).NotEmpty().MaximumLength(500);
        RuleFor(x => x.MetadataUrl).MaximumLength(500)
            .Must(V.ValidUrl).WithMessage("MetadataUrl must be a valid HTTP/HTTPS URL")
            .When(x => !string.IsNullOrEmpty(x.MetadataUrl));
    }
}

public sealed class CreateWebhookRequestValidator : AbstractValidator<CreateWebhookRequest>
{
    public CreateWebhookRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Url).NotEmpty().MaximumLength(500)
            .Must(V.ValidUrl).WithMessage("Url must be a valid HTTP/HTTPS URL");
        RuleFor(x => x.Secret).MaximumLength(256).When(x => x.Secret != null);
        RuleFor(x => x.TimeoutSeconds).InclusiveBetween(1, 60).When(x => x.TimeoutSeconds.HasValue);
        RuleFor(x => x.RetryCount).InclusiveBetween(0, 5).When(x => x.RetryCount.HasValue);
    }
}

public sealed class SiemConfigRequestValidator : AbstractValidator<SiemConfigRequest>
{
    public SiemConfigRequestValidator()
    {
        RuleFor(x => x.Host).NotEmpty().MaximumLength(255);
        RuleFor(x => x.Port).InclusiveBetween(1, 65535).When(x => x.Port.HasValue);
        RuleFor(x => x.Protocol).NotEmpty().MaximumLength(10);
        RuleFor(x => x.Transport).NotEmpty().MaximumLength(10);
    }
}

public sealed class CreateItsmConfigRequestValidator : AbstractValidator<CreateItsmConfigRequest>
{
    public CreateItsmConfigRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Provider).NotEmpty().MaximumLength(50);
        RuleFor(x => x.BaseUrl).NotEmpty().MaximumLength(500)
            .Must(V.ValidUrl).WithMessage("BaseUrl must be a valid HTTP/HTTPS URL");
        RuleFor(x => x.Username).MaximumLength(100).When(x => x.Username != null);
    }
}

public sealed class CreateAlertRuleRequestValidator : AbstractValidator<CreateAlertRuleRequest>
{
    public CreateAlertRuleRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.ConditionJson).NotEmpty()
            .Must(V.ValidJson).WithMessage("ConditionJson must be valid JSON");
        RuleFor(x => x.ActionJson).NotEmpty()
            .Must(V.ValidJson).WithMessage("ActionJson must be valid JSON");
        RuleFor(x => x.CooldownMinutes).InclusiveBetween(0, 10080)
            .When(x => x.CooldownMinutes.HasValue);
    }
}

public sealed class CreateRiskRuleRequestValidator : AbstractValidator<CreateRiskRuleRequest>
{
    public CreateRiskRuleRequestValidator()
    {
        RuleFor(x => x.Pattern).NotEmpty().MaximumLength(500);
        RuleFor(x => x.RiskScore).InclusiveBetween(0m, 10m);
        RuleFor(x => x.Category).MaximumLength(100).When(x => x.Category != null);
        RuleFor(x => x.Description).MaximumLength(500).When(x => x.Description != null);
    }
}

public sealed class CreateApiClientRequestValidator : AbstractValidator<CreateApiClientRequest>
{
    public CreateApiClientRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.AllowedIpRanges).MaximumLength(500).When(x => x.AllowedIpRanges != null);
        RuleFor(x => x.RateLimitPerMinute).InclusiveBetween(1, 10000)
            .When(x => x.RateLimitPerMinute.HasValue);
        RuleFor(x => x.CredentialIds).Must(ids => ids == null || ids.Length <= 100)
            .WithMessage("Maximum 100 credentials per API client");
    }
}

public sealed class UpdateConfigRequestValidator : AbstractValidator<UpdateConfigRequest>
{
    public UpdateConfigRequestValidator()
    {
        RuleFor(x => x.Value).NotEmpty().MaximumLength(4096);
        RuleFor(x => x.Category).MaximumLength(100).When(x => x.Category != null);
        RuleFor(x => x.Description).MaximumLength(500).When(x => x.Description != null);
    }
}

public sealed class CreateDiscoveryJobRequestValidator : AbstractValidator<CreateDiscoveryJobRequest>
{
    public CreateDiscoveryJobRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.TargetScope).MaximumLength(500).When(x => x.TargetScope != null);
        RuleFor(x => x.Schedule).MaximumLength(100).When(x => x.Schedule != null);
    }
}

public sealed class CreateRotationPolicyRequestValidator : AbstractValidator<CreateRotationPolicyRequest>
{
    public CreateRotationPolicyRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.IntervalDays).InclusiveBetween(1, 365).When(x => x.IntervalDays.HasValue);
        RuleFor(x => x.PasswordComplexityJson).Must(V.ValidJson)
            .WithMessage("PasswordComplexityJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.PasswordComplexityJson));
    }
}

public sealed class CreateFrameworkRequestValidator : AbstractValidator<CreateFrameworkRequest>
{
    public CreateFrameworkRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Version).MaximumLength(20).When(x => x.Version != null);
        RuleFor(x => x.ControlsJson).Must(V.ValidJson)
            .WithMessage("ControlsJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.ControlsJson));
    }
}

public sealed class CreateAttestationRequestValidator : AbstractValidator<CreateAttestationRequest>
{
    public CreateAttestationRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.ScopeJson).Must(V.ValidJson)
            .WithMessage("ScopeJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.ScopeJson));
        RuleFor(x => x.ReviewerRuleJson).Must(V.ValidJson)
            .WithMessage("ReviewerRuleJson must be valid JSON")
            .When(x => !string.IsNullOrEmpty(x.ReviewerRuleJson));
    }
}

public sealed class BulkUserImportRequestValidator : AbstractValidator<BulkUserImportRequest>
{
    public BulkUserImportRequestValidator()
    {
        RuleFor(x => x.Users).NotEmpty()
            .Must(u => u.Length <= 1000).WithMessage("Maximum 1000 users per import batch");
        RuleForEach(x => x.Users).SetValidator(new UserImportItemValidator());
    }
}

public sealed class UserImportItemValidator : AbstractValidator<UserImportItem>
{
    public UserImportItemValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MinimumLength(3).MaximumLength(50)
            .Matches(@"^[a-zA-Z0-9._@\-]+$")
            .WithMessage("Username may only contain letters, digits and ._@-");
        RuleFor(x => x.Password).MaximumLength(256).When(x => x.Password != null);
        RuleFor(x => x.DisplayName).MaximumLength(100).When(x => x.DisplayName != null);
        RuleFor(x => x.Email).EmailAddress().MaximumLength(200)
            .When(x => !string.IsNullOrEmpty(x.Email));
    }
}

public sealed class BulkCredentialImportRequestValidator : AbstractValidator<BulkCredentialImportRequest>
{
    public BulkCredentialImportRequestValidator()
    {
        RuleFor(x => x.Credentials).NotEmpty()
            .Must(c => c.Length <= 500).WithMessage("Maximum 500 credentials per import batch");
        RuleForEach(x => x.Credentials).SetValidator(new CredentialImportItemValidator());
    }
}

public sealed class CredentialImportItemValidator : AbstractValidator<CredentialImportItem>
{
    public CredentialImportItemValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Username).MaximumLength(100).When(x => x.Username != null);
        RuleFor(x => x.Password).MaximumLength(4096).When(x => x.Password != null);
        RuleFor(x => x.Tags).MaximumLength(500).When(x => x.Tags != null);
    }
}
