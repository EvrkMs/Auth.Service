using Auth.Domain.Entity;
using Auth.EntityFramework;
using Auth.Host.Endpoints;
using Auth.Host.Services;
using Auth.Host.Oidc;
using Auth.Infrastructure;
using Auth.Telegram;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

var oidcSection = builder.Configuration.GetSection("Oidc");
var oidcOptions = oidcSection.Get<OidcOptions>() ?? new OidcOptions();
oidcOptions.SigningKey ??= builder.Configuration["OIDC__SIGNING_KEY"];
var configuredIssuer =
    builder.Configuration["OIDC__ISSUER"]
    ?? builder.Configuration["AUTH_ISSUER"]
    ?? builder.Configuration["AUTH_DOMAIN"]
    ?? builder.Configuration["AUTH_HOST_DOMAIN"];

if (!string.IsNullOrWhiteSpace(configuredIssuer))
{
    oidcOptions.Issuer = configuredIssuer!;
}

builder.Services.AddSingleton(oidcOptions);
builder.Services.AddSingleton<OidcSigningKeyProvider>();
builder.Services.AddSingleton<OidcIdTokenFactory>();
builder.Services.AddTelegramIntegration(builder.Configuration);

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? builder.Configuration["DATABASE__CONNECTION"];

builder.Services.AddDbContext<AppDbContext>(options =>
{
    var resolvedConnection = connectionString ?? "Host=auth-db;Port=5432;Database=auth;Username=auth;Password=authpassword";
    options.UseNpgsql(resolvedConnection);
});

var dataProtectionPath = builder.Configuration["DATA_PROTECTION_PATH"] ?? "/app/keys/data-protection";
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionPath));

builder.Services
    .AddIdentityCore<Employee>()
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events ??= new CookieAuthenticationEvents();
    options.Events.OnRedirectToLogin = context =>
    {
        if (ShouldReturnApiStatus(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };

    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (ShouldReturnApiStatus(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
}).AddIdentityCookies();

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

builder.Services.AddAuthInfrastructure(options =>
{
    options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
    options.RefreshTokenLifetime = TimeSpan.FromDays(30);
});

builder.Services.AddScoped<IdentitySeeder>();
builder.Services.AddSingleton<ClientRegistry>();
builder.Services.AddSingleton<AuthorizationCodeStore>();

var forwardedOptions = BuildForwardedHeadersOptions(builder.Configuration);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(options =>
{
    var origins = GetClientOrigins(builder.Configuration);
    options.AddPolicy("ClientOrigins", policy =>
    {
        policy.WithOrigins(origins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();

    var seeder = scope.ServiceProvider.GetRequiredService<IdentitySeeder>();
    await seeder.SeedAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
if (forwardedOptions is not null)
{
    app.UseForwardedHeaders(forwardedOptions);
}
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("ClientOrigins");

app.MapRazorPages();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.MapTokenEndpoints();
app.MapConnectEndpoints();
app.MapSessionsEndpoints();
app.MapUserManagementEndpoints();
app.MapOidcEndpoints();
app.MapTelegramEndpoints();

app.Run();

static string[] GetClientOrigins(IConfiguration configuration)
{
    var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var section = configuration.GetSection("AuthClients");
    if (section.Exists())
    {
        foreach (var child in section.GetChildren())
        {
            var redirect = child["RedirectUri"];
            if (string.IsNullOrWhiteSpace(redirect))
            {
                continue;
            }

            if (Uri.TryCreate(redirect, UriKind.Absolute, out var uri))
            {
                origins.Add(uri.GetLeftPart(UriPartial.Authority));
            }
        }
    }

    if (origins.Count == 0)
    {
        origins.Add("http://localhost:4173");
    }

    return origins.ToArray();
}

static ForwardedHeadersOptions? BuildForwardedHeadersOptions(IConfiguration configuration)
{
    var entries = configuration["AUTH_REVERSE_PROXY"]
        ?? configuration["FORWARDED_PROXY"]
        ?? configuration["NGINX_FORWARDER"];

    var hosts = entries?
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray() ?? Array.Empty<string>();

    var options = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedFor
    };

    foreach (var host in hosts)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            options.KnownProxies.Add(address);
            continue;
        }

        try
        {
            var resolved = Dns.GetHostAddresses(host);
            foreach (var ip in resolved)
            {
                options.KnownProxies.Add(ip);
            }
        }
        catch
        {
            // ignore resolution failure, app will simply not trust this host
        }
    }

    if (options.KnownProxies.Count == 0)
    {
        // Fall back to trusting the entire Docker bridge network if hosts couldn't be resolved.
        var networkCidr = configuration["AUTH_REVERSE_PROXY_NETWORK"]
            ?? configuration["FORWARDED_PROXY_NETWORK"];
        if (!string.IsNullOrEmpty(networkCidr) && TryAddNetwork(options, networkCidr))
        {
            return options;
        }

        // Default to 172.16.0.0/12 which covers docker bridge networks (172.16-172.31)
        TryAddNetwork(options, "172.16.0.0/12");
    }

    return options;
}

static bool TryAddNetwork(ForwardedHeadersOptions options, string cidr)
{
    var parts = cidr.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length != 2)
    {
        return false;
    }

    if (!IPAddress.TryParse(parts[0], out var address))
    {
        return false;
    }

    if (!int.TryParse(parts[1], out var prefixLength))
    {
        return false;
    }

    options.KnownIPNetworks.Add(new System.Net.IPNetwork(address, prefixLength));
    return true;
}

static bool ShouldReturnApiStatus(HttpRequest request)
{
    if (request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    if (request.Headers.TryGetValue("Accept", out var accept) &&
        accept.Any(value => value.Contains("application/json", StringComparison.OrdinalIgnoreCase)))
    {
        return true;
    }

    if (request.Headers.TryGetValue("X-Requested-With", out var requestedWith) &&
        requestedWith.Any(value => value.Equals("XMLHttpRequest", StringComparison.OrdinalIgnoreCase)))
    {
        return true;
    }

    return false;
}
