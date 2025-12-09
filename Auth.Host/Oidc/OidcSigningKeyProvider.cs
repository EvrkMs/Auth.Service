using System;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Host.Oidc;

public sealed class OidcSigningKeyProvider
{
    private readonly SigningCredentials _credentials;
    private readonly JsonWebKey _jsonWebKey;

    public OidcSigningKeyProvider(OidcOptions options, ILogger<OidcSigningKeyProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        var rsa = RSA.Create();
        var signingKey = ResolveSigningKey(options, logger);
        if (!string.IsNullOrWhiteSpace(signingKey))
        {
            try
            {
                var privateKey = Convert.FromBase64String(signingKey);
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Failed to parse OIDC signing key. Provide a Base64 encoded PKCS#8 RSA key.", ex);
            }
        }
        else
        {
            rsa.KeySize = 2048;
            var export = rsa.ExportPkcs8PrivateKey();
            var exportBase64 = Convert.ToBase64String(export);
            if (TryPersistSigningKey(options.SigningKeyPath, exportBase64, logger))
            {
                logger.LogInformation("Generated and persisted new OIDC signing key to {Path}", options.SigningKeyPath);
            }
            else
            {
                logger.LogWarning("Generated ephemeral OIDC signing key. Persist it by setting OIDC__SigningKey or OIDC__SigningKeyPath. Key: {Key}", exportBase64);
            }
        }

        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16))
        };

        _credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        jwk.Kid = securityKey.KeyId;
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        _jsonWebKey = jwk;
    }

    public SigningCredentials GetSigningCredentials() => _credentials;

    public JsonWebKey GetJsonWebKey() => _jsonWebKey;

    private static string? ResolveSigningKey(OidcOptions options, ILogger logger)
    {
        if (!string.IsNullOrWhiteSpace(options.SigningKey))
        {
            return options.SigningKey;
        }

        if (string.IsNullOrWhiteSpace(options.SigningKeyPath))
        {
            return null;
        }

        try
        {
            if (File.Exists(options.SigningKeyPath))
            {
                return File.ReadAllText(options.SigningKeyPath).Trim();
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to read OIDC signing key from {Path}", options.SigningKeyPath);
        }

        return null;
    }

    private static bool TryPersistSigningKey(string? path, string key, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, key);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to persist OIDC signing key to {Path}", path);
            return false;
        }
    }
}
