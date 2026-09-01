using Microsoft.Extensions.DependencyInjection;

namespace IdentityData.Api.Common.Extensions;

public static class ApplicationExtensions
{
    public static IServiceCollection AddIdentityDataApplication(this IServiceCollection services)
    {
        services.AddMediatR(cfg =>
            cfg.RegisterServicesFromAssembly(typeof(ApplicationExtensions).Assembly));

        return services;
    }
}
