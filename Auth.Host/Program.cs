using Auth.Domain.Entity;
using Auth.EntityFramework;
using Auth.Host.Endpoints;
using Auth.Host.Services;
using Auth.Host.Oidc;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using Auth.Application.Tokens;

var builder = WebApplication.CreateBuilder(args);

var oidcSection = builder.Configuration.GetSection("Oidc");
var oidcOptions = oidcSection.Get<OidcOptions>() ?? new OidcOptions();
oidcOptions.SigningKey ??= builder.Configuration["OIDC__SIGNING_KEY"];
if (string.IsNullOrWhiteSpace(oidcOptions.Issuer))
{
    oidcOptions.Issuer = builder.Configuration["OIDC__ISSUER"]
        ?? builder.Configuration["AUTH_ISSUER"]
        ?? oidcOptions.Issuer;
}

builder.Services.AddSingleton(oidcOptions);
builder.Services.AddSingleton<OidcSigningKeyProvider>();
builder.Services.AddSingleton<OidcIdTokenFactory>();
builder.Services.AddSingleton<IAccessTokenEncoder, JwtAccessTokenEncoder>();

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? builder.Configuration["DATABASE__CONNECTION"];

builder.Services.AddDbContext<AppDbContext>(options =>
{
    var resolvedConnection = connectionString ?? "Host=auth-db;Port=5432;Database=auth;Username=auth;Password=authpassword";
    options.UseNpgsql(resolvedConnection);
});

builder.Services.AddDataProtection();

builder.Services
    .AddIdentityCore<Employee>()
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

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
app.UseAuthentication();
app.UseAuthorization();
app.UseCors("ClientOrigins");

app.MapRazorPages();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.MapTokenEndpoints();
app.MapConnectEndpoints();
app.MapOidcEndpoints();

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
