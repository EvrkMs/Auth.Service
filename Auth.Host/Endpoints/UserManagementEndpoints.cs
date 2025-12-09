using Auth.Domain.Entity;
using Auth.Host.Models.Roles;
using Auth.Host.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace Auth.Host.Endpoints;

public static class UserManagementEndpoints
{
    public static IEndpointRouteBuilder MapUserManagementEndpoints(this IEndpointRouteBuilder app)
    {
        var users = app.MapGroup("/api/cruduser")
            .RequireAuthorization(policy => policy.RequireRole("root", "RoleManager"));

        users.MapGet("/", GetUsersAsync);
        users.MapGet("/{id:guid}", GetUserAsync);
        users.MapPost("/", CreateUserAsync);
        users.MapPut("/{id:guid}", UpdateUserAsync);
        users.MapPost("/{id:guid}/password", ResetPasswordAsync);

        var roles = users.MapGroup("/roles")
            .RequireAuthorization(policy => policy.RequireRole("root"));

        roles.MapGet("/", GetRolesAsync);
        roles.MapPost("/", CreateRoleAsync);
        roles.MapPut("/{id}", UpdateRoleAsync);
        roles.MapDelete("/{id}", DeleteRoleAsync);

        return app;
    }

    private static async Task<IResult> GetUsersAsync(
        [FromQuery] string? query,
        [FromQuery] string? status,
        UserManager<Employee> userManager,
        CancellationToken cancellationToken)
    {
        var users = userManager.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(query))
        {
            users = users.Where(u =>
                u.UserName!.Contains(query) ||
                (u.DisplayName != null && u.DisplayName.Contains(query)) ||
                (u.Email != null && u.Email.Contains(query)));
        }

        var list = await users.ToListAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var summaries = new List<UserSummaryResponse>(list.Count);

        foreach (var user in list)
        {
            var statusValue = GetStatus(user, now);
            if (!string.IsNullOrEmpty(status) && !statusValue.Equals(status, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var roles = await userManager.GetRolesAsync(user);
            summaries.Add(MapUserSummary(user, roles.ToArray(), statusValue));
        }

        return Results.Ok(summaries);
    }

    private static async Task<IResult> GetUserAsync(
        Guid id,
        UserManager<Employee> userManager)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }

        var roles = await userManager.GetRolesAsync(user);
        var status = GetStatus(user, DateTimeOffset.UtcNow);
        return Results.Ok(MapUserDetail(user, roles.ToArray(), status));
    }

    private static async Task<IResult> CreateUserAsync(
        CreateUserRequest request,
        UserManager<Employee> userManager,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        if (string.IsNullOrWhiteSpace(request.UserName) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.FullName))
        {
            return Results.BadRequest(new { error = "username, password and fullName are required" });
        }

        var employee = new Employee
        {
            Id = Guid.NewGuid(),
            UserName = request.UserName.Trim(),
            Email = request.Email?.Trim(),
            DisplayName = request.FullName.Trim(),
            PhoneNumber = request.PhoneNumber?.Trim(),
            EmailConfirmed = true
        };

        var createResult = await userManager.CreateAsync(employee, request.Password);
        if (!createResult.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", createResult.Errors.Select(e => e.Description)) });
        }

        ApplyStatus(employee, request.Status);
        await userManager.UpdateAsync(employee);

        if (request.Roles is { Count: > 0 })
        {
            await AssignRolesAsync(employee, request.Roles, userManager, roleManager);
        }

        return Results.Created($"/api/cruduser/{employee.Id}", MapUserDetail(employee, Array.Empty<string>(), GetStatus(employee, DateTimeOffset.UtcNow)));
    }

    private static async Task<IResult> UpdateUserAsync(
        Guid id,
        UpdateUserRequest request,
        UserManager<Employee> userManager,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }

        ApplyStatus(user, request.Status);

        if (!string.IsNullOrWhiteSpace(request.FullName))
        {
            user.DisplayName = request.FullName.Trim();
        }

        user.PhoneNumber = request.PhoneNumber?.Trim();

        var updateResult = await userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", updateResult.Errors.Select(e => e.Description)) });
        }

        if (request.Roles is not null)
        {
            await ReplaceRolesAsync(user, request.Roles, userManager, roleManager);
        }

        var roles = await userManager.GetRolesAsync(user);
        return Results.Ok(MapUserDetail(user, roles.ToArray(), GetStatus(user, DateTimeOffset.UtcNow)));
    }

    private static async Task<IResult> ResetPasswordAsync(
        Guid id,
        ResetPasswordRequest request,
        UserManager<Employee> userManager)
    {
        if (string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return Results.BadRequest(new { error = "New password is required." });
        }

        var user = await userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var reset = await userManager.ResetPasswordAsync(user, token, request.NewPassword);
        if (!reset.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", reset.Errors.Select(e => e.Description)) });
        }

        return Results.Ok(new { status = "PasswordReset" });
    }

    private static async Task<IResult> GetRolesAsync(RoleManager<IdentityRole<Guid>> roleManager)
    {
        var roles = await roleManager.Roles
            .OrderBy(r => r.Name)
            .Select(r => new RoleResponse(r.Id.ToString(), r.Name!))
            .ToListAsync();

        return Results.Ok(roles);
    }

    private static async Task<IResult> CreateRoleAsync(
        CreateRoleRequest request,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Results.BadRequest(new { error = "Role name is required." });
        }

        var role = new IdentityRole<Guid>(request.Name.Trim());
        var result = await roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", result.Errors.Select(e => e.Description)) });
        }

        return Results.Created($"/api/cruduser/roles/{role.Id}", new RoleResponse(role.Id.ToString(), role.Name!));
    }

    private static async Task<IResult> UpdateRoleAsync(
        string id,
        UpdateRoleRequest request,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return Results.NotFound();
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Results.BadRequest(new { error = "Role name is required." });
        }

        role.Name = request.Name.Trim();
        role.NormalizedName = role.Name.ToUpperInvariant();
        var result = await roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", result.Errors.Select(e => e.Description)) });
        }

        return Results.Ok(new RoleResponse(role.Id.ToString(), role.Name));
    }

    private static async Task<IResult> DeleteRoleAsync(
        string id,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return Results.NotFound();
        }

        var result = await roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            return Results.BadRequest(new { error = string.Join("; ", result.Errors.Select(e => e.Description)) });
        }

        return Results.NoContent();
    }

    private static UserSummaryResponse MapUserSummary(Employee user, IReadOnlyCollection<string> roles, string status) =>
        new(
            user.Id,
            user.UserName ?? string.Empty,
            user.DisplayName,
            user.Email,
            user.PhoneNumber,
            string.Equals(status, "Active", StringComparison.OrdinalIgnoreCase),
            status,
            false,
            roles);

    private static UserDetailResponse MapUserDetail(Employee user, IReadOnlyCollection<string> roles, string status) =>
        new(
            user.Id,
            user.UserName ?? string.Empty,
            user.DisplayName,
            user.Email,
            user.PhoneNumber,
            string.Equals(status, "Active", StringComparison.OrdinalIgnoreCase),
            status,
            false,
            roles);

    private static string GetStatus(Employee user, DateTimeOffset now)
    {
        if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd.Value > now)
        {
            return "Inactive";
        }

        return "Active";
    }

    private static void ApplyStatus(Employee user, string? status)
    {
        user.LockoutEnabled = true;

        if (string.IsNullOrWhiteSpace(status) || status.Equals("Active", StringComparison.OrdinalIgnoreCase))
        {
            user.LockoutEnd = null;
            return;
        }

        user.LockoutEnabled = true;
        user.LockoutEnd = DateTimeOffset.MaxValue;
    }

    private static async Task AssignRolesAsync(
        Employee user,
        IReadOnlyCollection<string> roles,
        UserManager<Employee> userManager,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        foreach (var role in roles
                     .Where(r => !string.IsNullOrWhiteSpace(r))
                     .Select(r => r.Trim())
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var existing = await roleManager.FindByNameAsync(role);
            if (existing is null)
            {
                continue;
            }

            if (!await userManager.IsInRoleAsync(user, existing.Name!))
            {
                await userManager.AddToRoleAsync(user, existing.Name!);
            }
        }
    }

    private static async Task ReplaceRolesAsync(
        Employee user,
        IReadOnlyCollection<string> newRoles,
        UserManager<Employee> userManager,
        RoleManager<IdentityRole<Guid>> roleManager)
    {
        var currentRoles = await userManager.GetRolesAsync(user);
        var currentSet = new HashSet<string>(currentRoles, StringComparer.OrdinalIgnoreCase);
        var normalizedNew = new HashSet<string>(
            newRoles.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var toRemove = currentSet.Where(r => !normalizedNew.Contains(r)).ToArray();
        if (toRemove.Length > 0)
        {
            await userManager.RemoveFromRolesAsync(user, toRemove);
        }

        foreach (var role in normalizedNew)
        {
            if (currentSet.Contains(role))
            {
                continue;
            }

            var exists = await roleManager.FindByNameAsync(role);
            if (exists is not null)
            {
                await userManager.AddToRoleAsync(user, exists.Name!);
            }
        }
    }
}
