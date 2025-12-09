namespace Auth.Application.Sessions;

public sealed record CreateSessionResult(Guid SessionId, string? SessionHandle);
