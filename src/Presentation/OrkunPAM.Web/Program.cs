using Microsoft.AspNetCore.Localization;
using OrkunPAM.Web.Components;
using OrkunPAM.Web.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddLocalization(opts => opts.ResourcesPath = "Resources");

// PAM API HTTP client (TLS dev bypass in Development only)
builder.Services.AddHttpClient("PamApi", client =>
{
    client.BaseAddress = new Uri(
        builder.Configuration["PamApi:BaseUrl"] ?? "https://localhost:5001");
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (builder.Environment.IsDevelopment())
        handler.ServerCertificateCustomValidationCallback =
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    return handler;
});

// Scoped per Blazor circuit
builder.Services.AddScoped<AuthStateService>();
builder.Services.AddScoped<PamApiService>();
builder.Services.AddScoped<CultureService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

var supportedCultures = new[] { "en-US", "tr-TR" };
app.UseRequestLocalization(opts =>
{
    opts.AddSupportedCultures(supportedCultures);
    opts.AddSupportedUICultures(supportedCultures);
    opts.SetDefaultCulture("en-US");
});

app.MapGet("/api/culture/set", (string? culture, string? redirectUri, HttpContext ctx) =>
{
    if (!string.IsNullOrEmpty(culture))
    {
        ctx.Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
            new CookieOptions
            {
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                IsEssential = true,
                SameSite = SameSiteMode.Lax
            });
    }
    return Results.LocalRedirect(string.IsNullOrEmpty(redirectUri) ? "/" : redirectUri);
});

app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
