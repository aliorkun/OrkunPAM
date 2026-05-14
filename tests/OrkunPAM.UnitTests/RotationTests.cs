using Microsoft.Extensions.Logging.Abstractions;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence.Services;
using IAuditService = OrkunPAM.Application.Contracts.IAuditService;

namespace OrkunPAM.UnitTests;

public class RotationTests
{
    #region Fakes

    private sealed class FakeRotator : IPasswordRotator
    {
        public RotationConnector ConnectorType { get; }
        public int CallCount { get; private set; }
        public bool ShouldSucceed { get; set; } = true;

        public FakeRotator(RotationConnector connector) => ConnectorType = connector;

        public Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
        {
            CallCount++;
            return Task.FromResult(new RotationResult(ShouldSucceed,
                ShouldSucceed ? "Rotated OK" : "Rotation failed",
                ConnectorType.ToString()));
        }
    }

    private sealed class FakeLegacyRotation : IRotationService
    {
        public int CallCount { get; private set; }
        public RotationConnector? LastConnector { get; private set; }

        public Task<RotationResult> RotatePasswordAsync(RotationConnector connector, RotationTarget target, CancellationToken ct)
        {
            CallCount++;
            LastConnector = connector;
            return Task.FromResult(new RotationResult(true, "Legacy rotation", connector.ToString()));
        }

        public string GeneratePassword(int length = 24, bool upper = true, bool lower = true,
            bool digits = true, bool special = true) => new('X', length);
    }

    private sealed class FakeAudit : IAuditService
    {
        public int CallCount { get; private set; }
        public string? LastCategory { get; private set; }
        public string? LastEventType { get; private set; }

        public Task LogAsync(string category, string eventType, Guid? actorUserId, string? actorUsername,
            string? actorIp, string? targetType, string? targetId, object? details,
            AuditOutcome outcome = AuditOutcome.Success, CancellationToken ct = default)
        {
            CallCount++;
            LastCategory = category;
            LastEventType = eventType;
            return Task.CompletedTask;
        }
    }

    #endregion

    private static RotationTarget MakeTarget(string host = "10.0.0.1", int port = 22,
        string username = "admin") =>
        new(host, port, username, "OldPass!", "NewPass123!", null, null);

    [Fact]
    public async Task RotateAsync_SelectsDedicatedRotator_WhenAvailable()
    {
        var sshRotator = new FakeRotator(RotationConnector.Ssh);
        var legacy = new FakeLegacyRotation();
        var audit = new FakeAudit();
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { sshRotator }, legacy, audit,
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var result = await orch.RotateAsync(RotationConnector.Ssh, MakeTarget());

        Assert.True(result.Success);
        Assert.Equal(1, sshRotator.CallCount);
        Assert.Equal(0, legacy.CallCount);
    }

    [Fact]
    public async Task RotateAsync_FallsBackToLegacy_WhenNoDedicatedRotator()
    {
        var sshRotator = new FakeRotator(RotationConnector.Ssh);
        var legacy = new FakeLegacyRotation();
        var audit = new FakeAudit();
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { sshRotator }, legacy, audit,
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var result = await orch.RotateAsync(RotationConnector.Ldap, MakeTarget());

        Assert.True(result.Success);
        Assert.Equal(0, sshRotator.CallCount);
        Assert.Equal(1, legacy.CallCount);
        Assert.Equal(RotationConnector.Ldap, legacy.LastConnector);
    }

    [Fact]
    public async Task RotateAsync_AuditLogsOnSuccess()
    {
        var sshRotator = new FakeRotator(RotationConnector.Ssh);
        var audit = new FakeAudit();
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { sshRotator }, new FakeLegacyRotation(), audit,
            NullLogger<PasswordRotationOrchestrator>.Instance);

        await orch.RotateAsync(RotationConnector.Ssh, MakeTarget());

        Assert.Equal(1, audit.CallCount);
        Assert.Equal("PasswordRotation", audit.LastCategory);
        Assert.Equal("RotationSuccess", audit.LastEventType);
    }

    [Fact]
    public async Task RotateAsync_AuditLogsOnFailure()
    {
        var sshRotator = new FakeRotator(RotationConnector.Ssh) { ShouldSucceed = false };
        var audit = new FakeAudit();
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { sshRotator }, new FakeLegacyRotation(), audit,
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var result = await orch.RotateAsync(RotationConnector.Ssh, MakeTarget());

        Assert.False(result.Success);
        Assert.Equal("RotationFailed", audit.LastEventType);
    }

    [Fact]
    public async Task RotateAsync_RecordsResponseTime()
    {
        var sshRotator = new FakeRotator(RotationConnector.Ssh);
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { sshRotator }, new FakeLegacyRotation(), new FakeAudit(),
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var result = await orch.RotateAsync(RotationConnector.Ssh, MakeTarget());

        Assert.NotNull(result.ResponseTimeMs);
        Assert.True(result.ResponseTimeMs >= 0);
    }

    [Theory]
    [InlineData(ConnectionProtocol.Ssh, DeviceType.LinuxServer, RotationConnector.Ssh)]
    [InlineData(ConnectionProtocol.MySql, DeviceType.DatabaseServer, RotationConnector.MySql)]
    [InlineData(ConnectionProtocol.PostgreSql, DeviceType.DatabaseServer, RotationConnector.PostgreSql)]
    [InlineData(ConnectionProtocol.SqlServer, DeviceType.DatabaseServer, RotationConnector.SqlServer)]
    [InlineData(ConnectionProtocol.Oracle, DeviceType.DatabaseServer, RotationConnector.Oracle)]
    [InlineData(ConnectionProtocol.Rdp, DeviceType.WindowsServer, RotationConnector.Wmi)]
    [InlineData(ConnectionProtocol.Rdp, DeviceType.LinuxServer, RotationConnector.WinRm)]
    public void ResolveConnector_ReturnsCorrectType(ConnectionProtocol protocol, DeviceType device,
        RotationConnector expected)
    {
        var actual = PasswordRotationOrchestrator.ResolveConnector(device, protocol);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GeneratePassword_UsesLegacyService()
    {
        var legacy = new FakeLegacyRotation();
        var orch = new PasswordRotationOrchestrator(
            Array.Empty<IPasswordRotator>(), legacy, new FakeAudit(),
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var password = orch.GeneratePassword(16);
        Assert.Equal(16, password.Length);
    }

    [Fact]
    public void GetAvailableRotators_ReturnsRegisteredConnectors()
    {
        var ssh = new FakeRotator(RotationConnector.Ssh);
        var wmi = new FakeRotator(RotationConnector.Wmi);
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { ssh, wmi }, new FakeLegacyRotation(), new FakeAudit(),
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var available = orch.GetAvailableRotators();
        Assert.Equal(2, available.Count);
        Assert.Contains(RotationConnector.Ssh, available);
        Assert.Contains(RotationConnector.Wmi, available);
    }

    [Fact]
    public async Task RotateAsync_HandlesExceptionFromRotator()
    {
        var badRotator = new ThrowingRotator();
        var audit = new FakeAudit();
        var orch = new PasswordRotationOrchestrator(
            new IPasswordRotator[] { badRotator }, new FakeLegacyRotation(), audit,
            NullLogger<PasswordRotationOrchestrator>.Instance);

        var result = await orch.RotateAsync(RotationConnector.Ssh, MakeTarget());

        Assert.False(result.Success);
        Assert.Contains("Rotation error", result.Message);
        Assert.Equal("RotationFailed", audit.LastEventType);
    }

    private sealed class ThrowingRotator : IPasswordRotator
    {
        public RotationConnector ConnectorType => RotationConnector.Ssh;
        public Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
            => throw new InvalidOperationException("Connection refused");
    }
}
