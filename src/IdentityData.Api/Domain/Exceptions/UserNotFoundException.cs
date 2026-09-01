namespace IdentityData.Api.Domain.Exceptions;

public sealed class UserNotFoundException : IdentityDataException
{
    public string Subject { get; }

    public UserNotFoundException(string subject)
        : base($"No user found for subject '{subject}'.")
    {
        Subject = subject;
    }
}
