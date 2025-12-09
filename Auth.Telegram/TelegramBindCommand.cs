namespace Auth.Telegram;

public sealed record TelegramBindCommand(
    TelegramAuthData AuthData,
    string Password);
