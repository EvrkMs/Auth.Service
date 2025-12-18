using System;
using System.Collections.Generic;
using System.Linq;
using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Auth.Domain.Tokens;
using Auth.Host.Services;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.Host.Endpoints;

public static class TokenEndpoints
{
    public static IEndpointRouteBuilder MapTokenEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/tokens").WithTags("Tokens");

        group.MapPost("/", IssueTokenAsync);
        group.MapPost("/refresh", RefreshTokenAsync);
        group.MapPost("/introspect", IntrospectAsync);

        return app;
    }

    private static async Task<IResult> IssueTokenAsync(
        IssueTokenDto request,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        TokenService tokenService,
        ClientRegistry clients,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var logger = loggerFactory.CreateLogger("Auth.TokenEndpoints");
        var clientValidation = ClientValidationHelper.Validate(clients, request.ClientId, request.ClientSecret);
        if (!clientValidation.IsValid)
        {
            return Results.BadRequest(new { error = "invalid_client" });
        }

        var employee = await userManager.FindByIdAsync(request.EmployeeId.ToString());
        if (employee is null)
        {
            return Results.BadRequest(new { error = "Employee not found." });
        }

        Session? session = null;
        if (request.SessionId is Guid sessionId)
        {
            session = await sessionRepository.FindByIdAsync(sessionId, cancellationToken);
            if (session is null)
            {
                return Results.BadRequest(new { error = "Session not found." });
            }
        }

        var scopes = request.Scopes?.Where(static s => !string.IsNullOrWhiteSpace(s)).Distinct().ToArray()
            ?? Array.Empty<string>();

        var result = await tokenService.IssueAsync(new IssueTokenRequest(
            employee,
            session,
            request.ClientId,
            scopes,
            request.IncludeRefreshToken), cancellationToken);

        if (environment.IsDevelopment())
        {
            logger.LogInformation(
                "Issued token via /tokens for client {ClientId}, user {UserId}, scopes {Scopes}, includeRefresh {IncludeRefresh}",
                request.ClientId,
                employee.Id,
                string.Join(' ', scopes),
                request.IncludeRefreshToken);
        }

        return Results.Ok(new IssueTokenResponse(
            result.AccessToken.Value,
            result.AccessToken.ExpiresAt,
            result.RefreshToken?.Value,
            result.RefreshToken?.ExpiresAt,
            result.Policy.RefreshTokenTransport.ToString()));
    }

    private static async Task<IResult> RefreshTokenAsync(
        RefreshTokenDto request,
        UserManager<Employee> userManager,
        TokenRefreshService refreshService,
        ClientRegistry clients,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var logger = loggerFactory.CreateLogger("Auth.TokenEndpoints");
        var clientValidation = ClientValidationHelper.Validate(clients, request.ClientId, request.ClientSecret);
        if (!clientValidation.IsValid)
        {
            return Results.BadRequest(new { error = "invalid_client" });
        }

        var employee = await userManager.FindByIdAsync(request.EmployeeId.ToString());
        if (employee is null)
        {
            return Results.BadRequest(new { error = "Employee not found." });
        }

        try
        {
            var result = await refreshService.RefreshAsync(request.RefreshToken, employee, cancellationToken);
            if (environment.IsDevelopment())
            {
                logger.LogInformation(
                    "Refreshed token via /tokens/refresh for client {ClientId}, user {UserId}, scopes {Scopes}",
                    request.ClientId,
                    employee.Id,
                    string.Join(' ', result.Scopes));
            }
            return Results.Ok(new IssueTokenResponse(
                result.AccessToken.Value,
                result.AccessToken.ExpiresAt,
                result.RefreshToken?.Value,
                result.RefreshToken?.ExpiresAt,
                result.Policy.RefreshTokenTransport.ToString()));
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> IntrospectAsync(
        HttpContext context,
        ClientRegistry clients,
        ITokenRepository tokenRepository,
        ITokenValueGenerator tokenValueGenerator,
        Auth.Application.Abstractions.ISystemClock clock,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory)
    {
        var logger = loggerFactory.CreateLogger("Auth.TokenIntrospection");
        var (tokenValue, hintedType, clientId, clientSecret) = await ParseIntrospectionRequestAsync(context);
        if (string.IsNullOrWhiteSpace(tokenValue))
        {
            return Results.Json(new { active = false });
        }

        var clientValidation = ClientValidationHelper.Validate(clients, clientId, clientSecret);
        if (!clientValidation.IsValid)
        {
            return Results.BadRequest(new { error = "invalid_client" });
        }

        var hash = tokenValueGenerator.ComputeHash(tokenValue);
        var token = await tokenRepository.FindByHashAsync(hash, context.RequestAborted);
        if (token is null || !token.IsActive(clock.UtcNow))
        {
            if (environment.IsDevelopment())
            {
                logger.LogInformation(
                    "Introspection inactive for client {ClientId}, hint {Hint}",
                    clientId ?? string.Empty,
                    hintedType ?? string.Empty);
            }
            return Results.Json(new { active = false });
        }

        var response = new Dictionary<string, object?>
        {
            ["active"] = true,
            ["client_id"] = token.ClientId,
            ["token_type"] = token.Type == TokenType.Refresh ? "refresh_token" : "access_token",
            ["aud"] = token.ClientId,
            ["scope"] = token.Scopes,
            ["exp"] = token.ExpiresAt.ToUnixTimeSeconds(),
            ["iat"] = token.CreatedAt.ToUnixTimeSeconds(),
            ["sub"] = token.EmployeeId.ToString(),
        };

        if (!string.IsNullOrEmpty(hintedType))
        {
            response["token_type_hint"] = hintedType;
        }

        if (!string.IsNullOrWhiteSpace(token.SessionHandleHash))
        {
            response["sid"] = token.SessionHandleHash;
        }

        if (environment.IsDevelopment())
        {
            logger.LogInformation(
                "Introspection active for client {ClientId}, sub {Sub}, scopes {Scopes}",
                token.ClientId,
                token.EmployeeId,
                token.Scopes ?? string.Empty);
        }

        return Results.Json(response);
    }

    private static async Task<(string Token, string? TokenTypeHint, string? ClientId, string? ClientSecret)> ParseIntrospectionRequestAsync(HttpContext context)
    {
        string tokenValue = string.Empty;
        string? tokenTypeHint = null;
        string? clientId = null;
        string? clientSecret = null;

        var header = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(header) && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var encoded = header["Basic ".Length..].Trim();
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var parts = decoded.Split(':', 2);
                if (parts.Length == 2)
                {
                    clientId = parts[0];
                    clientSecret = parts[1];
                }
            }
            catch
            {
                // ignore malformed header
            }
        }

        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            tokenValue = form["token"].ToString();
            tokenTypeHint = form["token_type_hint"].ToString();
            clientId ??= form["client_id"].ToString();
            clientSecret ??= form["client_secret"].ToString();
        }
        else if (context.Request.ContentLength > 0 &&
                 context.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            var body = await context.Request.ReadFromJsonAsync<IntrospectRequest>(cancellationToken: context.RequestAborted);
            tokenValue = body?.Token ?? string.Empty;
            tokenTypeHint = body?.TokenTypeHint;
            clientId ??= body?.ClientId;
            clientSecret ??= body?.ClientSecret;
        }

        return (tokenValue, tokenTypeHint, clientId, clientSecret);
    }

    public sealed record IssueTokenDto(
        Guid EmployeeId,
        string ClientId,
        string? ClientSecret,
        Guid? SessionId,
        List<string>? Scopes,
        bool IncludeRefreshToken = true);

    public sealed record RefreshTokenDto(Guid EmployeeId, string ClientId, string? ClientSecret, string RefreshToken);

    public sealed record IssueTokenResponse(
        string AccessToken,
        DateTimeOffset AccessTokenExpiresAt,
        string? RefreshToken,
        DateTimeOffset? RefreshTokenExpiresAt,
        string RefreshTokenTransport);

    public sealed record IntrospectRequest(string Token, string? ClientId, string? ClientSecret, string? TokenTypeHint);
}
