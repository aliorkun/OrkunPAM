using Microsoft.AspNetCore.Components;

namespace OrkunPAM.Web.Services;

public class CultureService
{
    private readonly NavigationManager _nav;

    public CultureService(NavigationManager nav) => _nav = nav;

    public string CurrentCulture =>
        System.Globalization.CultureInfo.CurrentUICulture.Name;

    public void SetCulture(string culture)
    {
        var relative = _nav.ToBaseRelativePath(_nav.Uri);
        _nav.NavigateTo(
            "/api/culture/set?culture=" + Uri.EscapeDataString(culture) +
            "&redirectUri=/" + Uri.EscapeDataString(relative),
            forceLoad: true);
    }
}
