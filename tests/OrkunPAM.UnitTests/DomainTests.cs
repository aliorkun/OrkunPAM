using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.UnitTests;

public class DomainTests
{
    [Fact]
    public void User_RecordLoginSuccess_ResetsFailureCount()
    {
        var user = new User { FailedLoginCount = 4, Status = UserStatus.Active };
        user.RecordLoginSuccess("10.0.0.1");

        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockoutEndUtc);
        Assert.NotNull(user.LastLoginAtUtc);
        Assert.Equal("10.0.0.1", user.LastLoginIp);
    }

    [Fact]
    public void User_RecordLoginFailure_LocksAfterMaxAttempts()
    {
        var user = new User { FailedLoginCount = 4, Status = UserStatus.Active };
        user.RecordLoginFailure(maxAttempts: 5, lockoutMinutes: 30);

        Assert.Equal(5, user.FailedLoginCount);
        Assert.Equal(UserStatus.Locked, user.Status);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.True(user.LockoutEndUtc > DateTime.UtcNow);
    }

    [Fact]
    public void Credential_CheckOut_SetsCheckedOutState()
    {
        var cred = new Credential { Name = "admin", Status = CredentialStatus.Active };
        var userId = Guid.NewGuid();

        var result = cred.CheckOut(userId, 30);

        Assert.True(result.IsSuccess);
        Assert.Equal(CredentialStatus.CheckedOut, cred.Status);
        Assert.Equal(userId, cred.CheckedOutByUserId);
        Assert.NotNull(cred.CheckedOutAtUtc);
        Assert.NotNull(cred.CheckOutExpiresUtc);
    }

    [Fact]
    public void Credential_CheckOut_WhenAlreadyCheckedOut_Fails()
    {
        var cred = new Credential { Name = "admin", Status = CredentialStatus.CheckedOut, CheckedOutByUserId = Guid.NewGuid() };
        var result = cred.CheckOut(Guid.NewGuid(), 30);

        Assert.True(result.IsFailure);
        Assert.Contains("not available", result.Error.Message);
    }

    [Fact]
    public void Credential_CheckIn_ResetsState()
    {
        var cred = new Credential
        {
            Name = "admin",
            Status = CredentialStatus.CheckedOut,
            CheckedOutByUserId = Guid.NewGuid(),
            CheckedOutAtUtc = DateTime.UtcNow,
            CheckOutExpiresUtc = DateTime.UtcNow.AddMinutes(30)
        };

        var result = cred.CheckIn();

        Assert.True(result.IsSuccess);
        Assert.Equal(CredentialStatus.Active, cred.Status);
        Assert.Null(cred.CheckedOutByUserId);
    }

    [Fact]
    public void Credential_CheckIn_WhenNotCheckedOut_Fails()
    {
        var cred = new Credential { Name = "admin", Status = CredentialStatus.Active };
        var result = cred.CheckIn();

        Assert.True(result.IsFailure);
        Assert.Contains("not checked out", result.Error.Message);
    }

    [Fact]
    public void Result_Success_HasCorrectState()
    {
        var result = SharedKernel.Result.Success();
        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
    }

    [Fact]
    public void Result_Failure_HasErrorInfo()
    {
        var result = SharedKernel.Result.Failure(SharedKernel.Error.NotFound("User", 123));
        Assert.True(result.IsFailure);
        Assert.Contains("123", result.Error.Message);
    }

    [Fact]
    public void ResultT_Map_TransformsValue()
    {
        var result = SharedKernel.Result<int>.Success(42);
        var mapped = result.Map(x => x.ToString());
        Assert.True(mapped.IsSuccess);
        Assert.Equal("42", mapped.Value);
    }
}
