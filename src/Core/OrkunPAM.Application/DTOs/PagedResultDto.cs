namespace OrkunPAM.Application.DTOs;

public record PagedResultDto<T>(
    IReadOnlyList<T> Items,
    int Page,
    int PageSize,
    int TotalCount,
    int TotalPages,
    bool HasPrevious,
    bool HasNext);

public static class PagedResultDtoExtensions
{
    public static PagedResultDto<TDto> ToDto<TEntity, TDto>(
        this SharedKernel.PagedResult<TEntity> paged,
        Func<TEntity, TDto> mapper) =>
        new(
            paged.Items.Select(mapper).ToList(),
            paged.Page,
            paged.PageSize,
            paged.TotalCount,
            paged.TotalPages,
            paged.HasPrevious,
            paged.HasNext);
}
