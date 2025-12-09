namespace Auth.Telegram;

public sealed class TelegramValidationException : Exception
{
    public string Code { get; }

    public TelegramValidationException(string code, string message)
        : base(message)
    {
        Code = code;
    }
}
