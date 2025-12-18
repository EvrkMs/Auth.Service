using Auth.Oidc.Services;

namespace Auth.Oidc.Endpoints;

public static class ClientValidationHelper
{
    public static ClientValidationResult Validate(ClientRegistry clients, string? clientId, string? providedSecret)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return ClientValidationResult.Invalid;
        }

        var client = clients.Find(clientId);
        if (client is null)
        {
            return ClientValidationResult.Invalid;
        }

        if (string.IsNullOrWhiteSpace(client.ClientSecret))
        {
            return ClientValidationResult.Valid(client);
        }

        if (string.IsNullOrEmpty(providedSecret) || !string.Equals(providedSecret, client.ClientSecret, StringComparison.Ordinal))
        {
            return ClientValidationResult.Invalid;
        }

        return ClientValidationResult.Valid(client);
    }
}

public sealed record ClientValidationResult(bool IsValid, ClientRegistration? Client)
{
    public static ClientValidationResult Valid(ClientRegistration client) => new(true, client);
    public static ClientValidationResult Invalid => new(false, null);
}
