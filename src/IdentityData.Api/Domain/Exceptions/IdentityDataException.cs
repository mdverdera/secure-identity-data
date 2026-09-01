namespace IdentityData.Api.Domain.Exceptions;

public class IdentityDataException : Exception
{
    public IdentityDataException(string message) : base(message) { }
    public IdentityDataException(string message, Exception inner) : base(message, inner) { }
}
