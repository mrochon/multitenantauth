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
using System.Globalization;

var builder = WebApplication.CreateBuilder(args);

var tenantOptions = builder.Configuration.GetSection("Tenants").Get<TenantOptions>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        if ((tenantOptions == null) || String.IsNullOrEmpty(tenantOptions.Domain))
            throw new Exception("Missing main application domain name in configuration.");
        if (tenantOptions.TenantSubDomainMap == null)
            throw new Exception("No SubDomainMap in configuration.");
        options.Cookie.Domain = $".localhost";
        options.ForwardAuthenticate = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ForwardSignIn = CookieAuthenticationDefaults.AuthenticationScheme;
        options.ForwardDefaultSelector = ctx =>
        {
            return ctx.Request.Host.Host.StartsWith("cust2", StringComparison.InvariantCultureIgnoreCase) ? "B2C" : "AAD";
        };
        options.Events.OnValidatePrincipal = (ctx) =>
        {
            return Task.CompletedTask;
        };
        options.Events.OnSigningIn = (ctx) =>
        {
            return Task.CompletedTask;
        };
        options.Events.OnSignedIn = (ctx) =>
        {
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(authenticationScheme: "AAD", displayName: "AAD", options =>
    {
        builder.Configuration.Bind("AzureAD", options);
        options.CorrelationCookie.Domain = $".localhost";
        options.NonceCookie.Domain = $".localhost";
        options.UseTokenLifetime = true;
        options.TokenValidationParameters = new TokenValidationParameters() { ValidateIssuer = false };
        options.Events ??= new OpenIdConnectEvents();
        options.Events.OnRedirectToIdentityProvider = async ctx =>
        {
            ctx.ProtocolMessage.RedirectUri = $"https://{tenantOptions.Domain}/signin-oidc";

            await Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(authenticationScheme: "B2C", displayName: "B2C", options =>
    {
        builder.Configuration.Bind("AzureB2C", options);
        options.CorrelationCookie.Domain = $".localhost";
        options.NonceCookie.Domain = $".localhost";
        //options.CorrelationCookie.Domain = $".{tenantOptions.Domain}";
        //options.NonceCookie.Domain = $".{tenantOptions.Domain}";
        options.UseTokenLifetime = true;
        options.Events ??= new OpenIdConnectEvents();
        options.Events.OnRedirectToIdentityProvider = async ctx =>
        {
            ctx.ProtocolMessage.RedirectUri = $"https://{tenantOptions.Domain}/b2c/signin-oidc";
            await Task.CompletedTask;
        };
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
    // This code will ensure that an authenticated user is always redirected
    // to the correct subdomain    
    if((context.User.Identity != null) && context.User.Identity.IsAuthenticated)
    {
        var subdomain = string.Empty;
        var error = String.Empty;
        var tid = context.User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value;
        tid ??= context.User.FindFirst("appTenantName")?.Value; // in case its a B2C app tenant
        if (tid == null)
            error = "No tid in ClaimsPrincipal";
        else if (!tenantOptions!.TenantSubDomainMap!.TryGetValue(tid, out subdomain))
            error = $"{tid} not found in SubDomainMap";
        else if (!context.Request.Host.Host.StartsWith(subdomain, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Redirect($"https://{subdomain}.{tenantOptions.Domain}");
            return;
        }
        if(!String.IsNullOrEmpty(error))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsJsonAsync(new { msg = error });
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
