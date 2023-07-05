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

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "B2C_OR_AAD";
    options.DefaultChallengeScheme = "B2C_OR_AAD";
    options.DefaultAuthenticateScheme = "B2C_OR_AAD";
})
.AddOpenIdConnect(authenticationScheme: "AAD", displayName: "AAD", options =>
{
    builder.Configuration.Bind("AzureAD", options);
    options.UseTokenLifetime = true;
    options.TokenValidationParameters = new TokenValidationParameters() { ValidateIssuer = false };
    options.Events ??= new OpenIdConnectEvents();
    options.Events.OnRedirectToIdentityProvider = async ctx =>
    {
        ctx.ProtocolMessage.RedirectUri = $"https://{tenantOptions.Domain}/signin-oidc";
        options.CorrelationCookie.Domain = tenantOptions.Domain;
        options.NonceCookie.Domain = tenantOptions.Domain;
        await Task.CompletedTask;
    };
})
.AddOpenIdConnect(authenticationScheme: "B2C", displayName: "B2C", options =>
{
    builder.Configuration.Bind("AzureB2C", options);
    options.UseTokenLifetime = true;
    options.Events ??= new OpenIdConnectEvents();
    options.Events.OnRedirectToIdentityProvider = async ctx =>
    {
        ctx.ProtocolMessage.RedirectUri = $"https://{tenantOptions.Domain}/signin-oidc";
        options.CorrelationCookie.Domain = tenantOptions.Domain;
        options.NonceCookie.Domain = tenantOptions.Domain;
        await Task.CompletedTask;
    };
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddPolicyScheme("B2C_OR_AAD", "B2C_OR_AAD", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        var tenantName = context.Request.Host.Host.Split('.')[0];
        return tenantName.Equals("cust2", StringComparison.InvariantCultureIgnoreCase) ? "B2C" : "AAD";
    };
}
)
;

builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    if ((tenantOptions == null) || String.IsNullOrEmpty(tenantOptions.Domain))
        throw new Exception("Missing main application domain name in configuration.");
    if (tenantOptions.TenantSubDomainMap == null)
        throw new Exception("No SubDomainMap in configuration.");
    options.Cookie.Domain = tenantOptions.Domain;
});

builder.Services.AddControllersWithViews(options =>
{
    //var policy = new AuthorizationPolicyBuilder()
    //    .RequireAuthenticatedUser()
    //    .Build();
    //options.Filters.Add(new AuthorizeFilter(policy));
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
    if(context.User != null)
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
