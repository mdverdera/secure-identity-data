using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IdentityData.Api.Infrastructure.Authentication;

public sealed class JwkStartupService : BackgroundService
{
    private readonly JwkKeyStore _keyStore;
    private readonly string _jwksUri;
    private readonly ILogger<JwkStartupService> _logger;

    public JwkStartupService(JwkKeyStore keyStore, string jwksUri, ILogger<JwkStartupService> logger)
    {
        _keyStore = keyStore;
        _jwksUri = jwksUri;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var keys = await JwksFetcher.FetchAsync(_jwksUri, _logger, stoppingToken);
        _keyStore.SetKeys(keys);
    }
}
