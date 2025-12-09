namespace Auth.Host.Models.Users;

public sealed record UserSummaryResponse(
    Guid Id,
    string UserName,
    string FullName,
    string? Email,
    string? PhoneNumber,
    bool IsActive,
    string Status,
    bool MustChangePassword,
    IReadOnlyCollection<string> Roles);

public sealed record UserDetailResponse(
    Guid Id,
    string UserName,
    string FullName,
    string? Email,
    string? PhoneNumber,
    bool IsActive,
    string Status,
    bool MustChangePassword,
    IReadOnlyCollection<string> Roles);

public sealed record CreateUserRequest(
    string UserName,
    string Password,
    string FullName,
    string? Email,
    string? PhoneNumber,
    string Status,
    IReadOnlyCollection<string>? Roles);

public sealed record UpdateUserRequest(
    string FullName,
    string? PhoneNumber,
    string Status,
    IReadOnlyCollection<string>? Roles);

public sealed record ResetPasswordRequest(
    string NewPassword,
    bool RequireChangeOnNextLogin = true);
