using OrkunPAM.SharedKernel;

namespace OrkunPAM.UnitTests;

public class ResultTests
{
    [Fact]
    public void Success_IsSuccessTrue()
    {
        var result = Result.Success();
        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
    }

    [Fact]
    public void Failure_IsFailureTrue()
    {
        var result = Result.Failure(Error.NotFound("User", 1));
        Assert.True(result.IsFailure);
        Assert.Equal("NotFound", result.Error.Code);
    }

    [Fact]
    public void ResultT_Success_HasValue()
    {
        var result = Result<int>.Success(42);
        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void ResultT_Failure_HasError()
    {
        var result = Result<int>.Failure(Error.Internal("boom"));
        Assert.True(result.IsFailure);
        Assert.Equal("Internal", result.Error.Code);
    }

    [Fact]
    public void ResultT_Map_Success_Transforms()
    {
        var result = Result<int>.Success(10);
        var mapped = result.Map(x => x * 2);
        Assert.True(mapped.IsSuccess);
        Assert.Equal(20, mapped.Value);
    }

    [Fact]
    public void ResultT_Map_Failure_PropagatesError()
    {
        var result = Result<int>.Failure(Error.Validation("bad"));
        var mapped = result.Map(x => x * 2);
        Assert.True(mapped.IsFailure);
        Assert.Equal("Validation", mapped.Error.Code);
    }

    [Fact]
    public void Error_Connection_HasActionableMessage()
    {
        var err = Error.Connection("10.0.1.5:22", "timeout after 30s", "Check firewall rules");
        Assert.Equal("ConnectionError", err.Code);
        Assert.Contains("10.0.1.5:22", err.Message);
        Assert.Contains("timeout", err.Message);
        Assert.Contains("firewall", err.Detail!);
    }

    [Fact]
    public void Error_Rotation_HasActionableMessage()
    {
        var err = Error.Rotation("admin@server1", "WinRM connection refused", "Check WinRM service on target");
        Assert.Equal("RotationError", err.Code);
        Assert.Contains("admin@server1", err.Message);
    }

    [Fact]
    public void ApiResponse_Ok_HasSuccessTrue()
    {
        var resp = ApiResponse<int>.Ok(42);
        Assert.True(resp.Success);
        Assert.Equal(42, resp.Data);
    }

    [Fact]
    public void ApiResponse_Fail_HasErrors()
    {
        var resp = ApiResponse<int>.Fail("Error 1", "Error 2");
        Assert.False(resp.Success);
        Assert.Equal(2, resp.Errors.Count);
    }

    [Fact]
    public void ApiResponse_FromResult_Success()
    {
        var result = Result<string>.Success("hello");
        var resp = ApiResponse<string>.FromResult(result);
        Assert.True(resp.Success);
        Assert.Equal("hello", resp.Data);
    }

    [Fact]
    public void ApiResponse_FromResult_Failure()
    {
        var result = Result<string>.Failure(Error.NotFound("Item", 5));
        var resp = ApiResponse<string>.FromResult(result);
        Assert.False(resp.Success);
        Assert.Contains("not found", resp.Errors[0], StringComparison.OrdinalIgnoreCase);
    }
}
