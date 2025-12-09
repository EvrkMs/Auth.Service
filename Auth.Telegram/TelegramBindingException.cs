namespace Auth.Telegram;

public sealed class TelegramBindingException : Exception
{
    public string Code { get; }

    public TelegramBindingException(string code, string message)
        : base(message)
    {
        Code = code;
    }
}
