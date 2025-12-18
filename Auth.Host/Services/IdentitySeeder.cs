using Auth.Domain.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

namespace Auth.Host.Services;

public sealed class IdentitySeeder
{
    private readonly UserManager<Employee> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILogger<IdentitySeeder> _logger;
    private readonly IConfiguration _configuration;

    private const string RootRoleName = "root";
    private const string SafeManagerRoleName = "SafeManager";
    private const string DefaultUserName = "root@ava";
    private const string DefaultDisplayName = "Root";
    private const string DefaultPassword = "ChangeMe_!123";

    public IdentitySeeder(
        UserManager<Employee> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ILogger<IdentitySeeder> logger,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRoleAsync(RootRoleName, cancellationToken);
        await EnsureRoleAsync(SafeManagerRoleName, cancellationToken);
        await EnsureRootUserAsync(cancellationToken);
    }

    private async Task EnsureRoleAsync(string roleName, CancellationToken cancellationToken)
    {
        if (await _roleManager.RoleExistsAsync(roleName))
        {
            return;
        }

        var role = new IdentityRole<Guid>(roleName);
        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"Failed to create role '{roleName}': {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        _logger.LogInformation("Created role {RoleName}", roleName);
    }

    private async Task EnsureRootUserAsync(CancellationToken cancellationToken)
    {
        var userName = _configuration["AUTH_ROOT_USERNAME"] ?? DefaultUserName;
        var displayName = _configuration["AUTH_ROOT_DISPLAYNAME"] ?? DefaultDisplayName;
        var password = _configuration["AUTH_ROOT_PASSWORD"] ?? DefaultPassword;

        var user = await _userManager.FindByNameAsync(userName);
        if (user is null)
        {
            user = new Employee
            {
                UserName = userName,
                Email = userName,
                DisplayName = displayName,
                EmailConfirmed = true
            };

            var create = await _userManager.CreateAsync(user, password);
            if (!create.Succeeded)
            {
                throw new InvalidOperationException($"Failed to create root user: {string.Join(", ", create.Errors.Select(e => e.Description))}");
            }

            _logger.LogInformation("Created root user {UserName}", userName);
        }

        if (!await _userManager.IsInRoleAsync(user, RootRoleName))
        {
            var assign = await _userManager.AddToRoleAsync(user, RootRoleName);
            if (!assign.Succeeded)
            {
                throw new InvalidOperationException($"Failed to assign root role: {string.Join(", ", assign.Errors.Select(e => e.Description))}");
            }

            _logger.LogInformation("Assigned root role to {UserName}", userName);
        }
    }
}
