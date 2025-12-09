namespace Auth.Telegram;

public sealed class TelegramOptions
{
    public string BotToken { get; set; } = string.Empty;

    public string BotUsername { get; set; } = string.Empty;

    public int AllowedClockSkewSeconds { get; set; } = 300;
}
