namespace Auth.Host.Models.Telegram;

public sealed record TelegramBindRequest(
    long Id,
    string? FirstName,
    string? LastName,
    string? Username,
    string? PhotoUrl,
    long AuthDate,
    string? Hash,
    string Password);

public sealed record TelegramUnbindRequest(string Password);

public sealed record TelegramProfileResponse(
    long Id,
    string? Username,
    string? FirstName,
    string? LastName,
    string? PhotoUrl,
    DateTimeOffset BoundAt);
