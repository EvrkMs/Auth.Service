namespace Auth.Application.Abstractions;

public interface ISystemClock
{
    DateTimeOffset UtcNow { get; }
}
