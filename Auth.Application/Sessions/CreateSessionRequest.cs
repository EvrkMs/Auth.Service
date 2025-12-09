namespace Auth.Application.Sessions;

public sealed record CreateSessionRequest(
    Guid EmployeeId,
    string ClientId,
    string? Device,
    string? IpAddress,
    string? Metadata,
    TimeSpan? Lifetime,
    bool IssueHandle = true);
