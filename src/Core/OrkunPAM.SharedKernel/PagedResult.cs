namespace OrkunPAM.SharedKernel;

public sealed class PagedResult<T>
{
    public IReadOnlyList<T> Items { get; }
    public int Page { get; }
    public int PageSize { get; }
    public int TotalCount { get; }
    public int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);
    public bool HasPrevious => Page > 1;
    public bool HasNext => Page < TotalPages;

    public PagedResult(IReadOnlyList<T> items, int page, int pageSize, int totalCount)
    {
        Items = items;
        Page = page;
        PageSize = pageSize;
        TotalCount = totalCount;
    }
}

public sealed class ApiResponse<T>
{
    public bool Success { get; init; }
    public T? Data { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
    public ResponseMeta? Meta { get; init; }

    public static ApiResponse<T> Ok(T data, ResponseMeta? meta = null) =>
        new() { Success = true, Data = data, Meta = meta };

    public static ApiResponse<T> Fail(params string[] errors) =>
        new() { Success = false, Errors = errors };

    public static ApiResponse<T> FromResult(Result<T> result) =>
        result.IsSuccess
            ? Ok(result.Value)
            : Fail(result.Error.Message);
}

public sealed class ResponseMeta
{
    public int? Page { get; init; }
    public int? PageSize { get; init; }
    public int? TotalCount { get; init; }
    public string? TraceId { get; init; }
}
