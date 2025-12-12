using System;
using System.Collections.Generic;
using System.Linq;
using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Auth.Host.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace Auth.Host.Endpoints;

public static class TokenEndpoints
{
    public static IEndpointRouteBuilder MapTokenEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/tokens").WithTags("Tokens");

        group.MapPost("/", IssueTokenAsync);
        group.MapPost("/refresh", RefreshTokenAsync);

        return app;
    }

    private static async Task<IResult> IssueTokenAsync(
        IssueTokenDto request,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        TokenService tokenService,
        ClientRegistry clients,
        CancellationToken cancellationToken)
    {
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
        CancellationToken cancellationToken)
    {
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
}
