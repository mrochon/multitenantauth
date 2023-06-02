using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.Cookies;
using mysaasapp.Models;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http.Extensions;

var builder = WebApplication.CreateBuilder(args);

var tenants = builder.Configuration.GetSection("Tenants").Get<TenantOptions>();

// Add services to the container.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));
builder.Services.ConfigureAll<OpenIdConnectOptions>(options =>
{
    options.Events ??= new OpenIdConnectEvents();
    var nextRedirectHandler = options.Events.OnRedirectToIdentityProvider;
    options.Events.OnRedirectToIdentityProvider = async ctx =>
    {
        ctx.ProtocolMessage.RedirectUri = "https://beitmerari.com/signin-oidc";
        options.CorrelationCookie.Domain = tenants.Domain;
        options.NonceCookie.Domain = tenants.Domain;
        await nextRedirectHandler(ctx);
    };
});
builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.Domain = tenants.Domain;
});

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});
builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.Use(async (context, next) =>
{
    if(context.User != null)
    {
        var subdomain = string.Empty;
        if(tenants.TenantSubDomainMap.ContainsKey(context.User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value))
            subdomain = tenants.TenantSubDomainMap[context.User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value];
        if(string.IsNullOrEmpty(subdomain))
            context.Response.StatusCode = 403;
        else if(!context.Request.Host.Host.StartsWith(subdomain, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Redirect($"https://{subdomain}.{tenants.Domain}");
            return;
        }
    }
    await next.Invoke();
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
