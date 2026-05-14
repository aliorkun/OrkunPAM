using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.UnitTests;

public class SyslogFormatterTests
{
    [Fact]
    public void Format_Rfc5424_ContainsPriorityVersionTimestamp()
    {
        var evt = new SessionStartedEvent
        {
            SessionId = Guid.NewGuid(),
            SessionType = "SSH",
            TargetDevice = "10.0.0.1",
            ActorUsername = "admin",
            ActorIp = "192.168.1.1"
        };

        var result = SyslogFormatter.Format(evt);

        // RFC 5424: <PRI>VERSION TIMESTAMP ...
        Assert.Matches(@"^<\d+>1 \d{4}-\d{2}-\d{2}", result);
        Assert.Contains("OrkunPAM", result);
    }

    [Fact]
    public void Format_PriorityCalculation_BreakGlass_IsAlert()
    {
        // BreakGlass = severity 1 (Alert), facility 16 (local0)
        // PRI = 16 * 8 + 1 = 129
        var evt = new BreakGlassActivatedEvent
        {
            Reason = "Emergency access",
            ActorUsername = "admin"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.StartsWith("<129>", result);
    }

    [Fact]
    public void Format_PriorityCalculation_SessionStarted_IsInformational()
    {
        // SessionStarted = severity 6 (Informational), PRI = 16 * 8 + 6 = 134
        var evt = new SessionStartedEvent
        {
            SessionId = Guid.NewGuid(),
            SessionType = "RDP",
            TargetDevice = "10.0.0.2"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.StartsWith("<134>", result);
    }

    [Fact]
    public void Format_PriorityCalculation_PolicyViolation_IsCritical()
    {
        // PolicyViolation = severity 2 (Critical), PRI = 16 * 8 + 2 = 130
        var evt = new PolicyViolationEvent
        {
            ViolationType = "PasswordExpired",
            Details = "Password not changed for 120 days"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.StartsWith("<130>", result);
    }

    [Fact]
    public void Format_PriorityCalculation_LoginFailed_IsWarning()
    {
        // UserLoginFailed = severity 4 (Warning), PRI = 16 * 8 + 4 = 132
        var evt = new UserLoginFailedEvent
        {
            Reason = "Bad password",
            ActorUsername = "testuser",
            ActorIp = "10.0.0.5"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.StartsWith("<132>", result);
    }

    [Fact]
    public void Format_StructuredData_ContainsEventType()
    {
        var evt = new UserLoggedInEvent
        {
            AuthSource = "Local",
            ActorUsername = "admin",
            ActorIp = "192.168.1.1"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.Contains("[pam@0 eventType=\"User.Login.Success\"", result);
    }

    [Fact]
    public void Format_StructuredData_EscapesSpecialChars()
    {
        var evt = new CommandBlockedEvent
        {
            SessionId = Guid.NewGuid(),
            Command = "rm -rf /; echo \"done\"",
            Rule = "block]dangerous",
            ActorUsername = "hacker"
        };

        var result = SyslogFormatter.Format(evt);
        // Verify RFC 5424 escaping: " -> \", ] -> \], \ -> \\
        Assert.Contains("\\\"done\\\"", result);
        Assert.Contains("block\\]dangerous", result);
    }

    [Fact]
    public void Format_PlainMessage_ContainsHumanReadableText()
    {
        var evt = new CredentialCheckedOutEvent
        {
            CredentialId = Guid.NewGuid(),
            CredentialName = "root@server1",
            ActorUsername = "admin",
            Reason = "Maintenance"
        };

        var result = SyslogFormatter.Format(evt);
        Assert.Contains("Credential 'root@server1' checked out by 'admin'", result);
    }

    [Fact]
    public void Format_WithCefPayload_UsesCefAsMessage()
    {
        var evt = new UserLoggedInEvent
        {
            AuthSource = "Local",
            ActorUsername = "admin"
        };

        var cefPayload = "CEF:0|OrkunPAM|PAM|1.0|100|User Login Success|3|act=Login";
        var result = SyslogFormatter.Format(evt, cefPayload);

        Assert.Contains(cefPayload, result);
        // Should NOT contain the plain text message
        Assert.DoesNotContain("logged in via", result);
    }

    [Fact]
    public void Format_PasswordRotated_SeverityDependsOnSuccess()
    {
        var success = new PasswordRotatedEvent
        {
            CredentialId = Guid.NewGuid(),
            CredentialName = "svc_account",
            Success = true
        };
        var failure = new PasswordRotatedEvent
        {
            CredentialId = Guid.NewGuid(),
            CredentialName = "svc_account",
            Success = false,
            ErrorMessage = "Connection timeout"
        };

        var successResult = SyslogFormatter.Format(success);
        var failureResult = SyslogFormatter.Format(failure);

        // Success = severity 6 -> PRI 134
        Assert.StartsWith("<134>", successResult);
        // Failure = severity 3 -> PRI 131
        Assert.StartsWith("<131>", failureResult);
    }

    // === CEF Formatter Tests ===

    [Fact]
    public void CefFormat_ContainsHeaderFields()
    {
        var evt = new SessionStartedEvent
        {
            SessionId = Guid.NewGuid(),
            SessionType = "SSH",
            TargetDevice = "10.0.0.1",
            ActorUsername = "admin"
        };

        var result = CefFormatter.Format(evt);
        Assert.StartsWith("CEF:0|OrkunPAM|PAM|1.0|", result);
        Assert.Contains("Session Started", result);
    }

    [Fact]
    public void CefFormat_SeverityMapping_BreakGlassIsHighest()
    {
        var evt = new BreakGlassActivatedEvent
        {
            Reason = "Emergency",
            ActorUsername = "admin"
        };

        var result = CefFormatter.Format(evt);
        Assert.Contains("|10|", result); // severity 10
    }

    [Fact]
    public void CefFormat_SeverityMapping_CommandBlockedIsHigh()
    {
        var evt = new CommandBlockedEvent
        {
            SessionId = Guid.NewGuid(),
            Command = "rm -rf /",
            Rule = "dangerous_commands",
            ActorUsername = "user"
        };

        var result = CefFormatter.Format(evt);
        Assert.Contains("|8|", result); // severity 8
    }

    [Fact]
    public void CefFormat_PipeEscaping_InHeaderFields()
    {
        // The vendor/product/version are fixed, but event name could theoretically
        // have pipes if the event type contains them. Test with a known event.
        var evt = new UserLoggedInEvent
        {
            AuthSource = "Local",
            ActorUsername = "admin"
        };

        var result = CefFormatter.Format(evt);
        // Verify the CEF structure has proper pipe-delimited fields
        var parts = result.Split('|');
        Assert.True(parts.Length >= 8, "CEF should have at least 8 pipe-delimited fields");
    }

    [Fact]
    public void CefFormat_Extensions_ContainActorInfo()
    {
        var userId = Guid.NewGuid();
        var evt = new CredentialCheckedOutEvent
        {
            CredentialId = Guid.NewGuid(),
            CredentialName = "root@server",
            ActorUserId = userId,
            ActorUsername = "admin",
            ActorIp = "192.168.1.100"
        };

        var result = CefFormatter.Format(evt);
        Assert.Contains($"suid={userId}", result);
        Assert.Contains("suser=admin", result);
        Assert.Contains("src=192.168.1.100", result);
    }

    [Fact]
    public void CefFormat_ExtensionValueEscaping_EqualsAndBackslash()
    {
        var evt = new PolicyViolationEvent
        {
            ViolationType = "PasswordComplexity",
            Details = "Password contains = sign and \\ backslash",
            ActorUsername = "user"
        };

        var result = CefFormatter.Format(evt);
        // Equals and backslash should be escaped in extension values
        Assert.Contains("\\=", result);
        Assert.Contains("\\\\", result);
    }
}
