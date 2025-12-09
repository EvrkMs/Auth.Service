namespace Auth.Application.Tokens;

public interface ITokenValueGenerator
{
    TokenValue Generate(int size = 64);

    string ComputeHash(string value);
}
