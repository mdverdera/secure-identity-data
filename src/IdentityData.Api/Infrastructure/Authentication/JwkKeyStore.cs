using Microsoft.IdentityModel.Tokens;

namespace IdentityData.Api.Infrastructure.Authentication;

public sealed class JwkKeyStore
{
    private IReadOnlyList<SecurityKey> _keys = [];

    public IReadOnlyList<SecurityKey> Keys => _keys;

    public void SetKeys(IEnumerable<SecurityKey> keys)
    {
        _keys = keys.ToList().AsReadOnly();
    }
}
