using Auth.Host.Endpoints;
using Auth.Host.Extensions;
using Auth.Host.Services;
using Auth.Oidc.Extensions;
using Auth.Oidc.Services;
using Auth.Telegram;
using Auth.Host.Filters;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOidcCoreWithCors(builder.Configuration)
    .AddTelegramIntegration(builder.Configuration)
    .AddAuthDatabase(builder.Configuration)
    .AddAuthDataProtection(builder.Configuration)
    .AddAuthIdentity()
    .AddAuthAntiforgery()
    .AddAuthInfrastructureDefaults();

builder.Services.AddRazorPages();
builder.Services.AddScoped<IdentitySeeder>();

var forwardedOptions = BuildForwardedHeadersOptions(builder.Configuration);
var clientOrigins = OidcClientOrigins.Resolve(builder.Configuration);
builder.Services.AddSingleton<RedirectUrlPolicy>(sp =>
{
    var clients = sp.GetRequiredService<ClientRegistry>();
    return new RedirectUrlPolicy(clientOrigins, clients);
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
await app.ApplyAuthMigrationsAsync();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseStaticFiles();

if (forwardedOptions is not null)
{
    app.UseForwardedHeaders(forwardedOptions);
}
app.UseAuthPipeline(builder.Configuration);
app.UseOidcCore();

app.MapRazorPages();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.MapSessionsEndpoints();
app.MapUserManagementEndpoints();
app.MapTelegramEndpoints<AntiforgeryValidationFilter>();
app.MapAntiforgeryEndpoints();

app.Run();

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
