namespace Auth.Host.Models.Roles;

public sealed record RoleResponse(string Id, string Name);

public sealed record CreateRoleRequest(string Name);

public sealed record UpdateRoleRequest(string Name);
