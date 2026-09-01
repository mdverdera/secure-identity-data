using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using System.Reflection;

namespace IdentityData.Api.Common.Extensions;

public static class SwaggerExtensions
{
    public static IServiceCollection AddIdentityDataSwagger(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Identity Data API",
                Version = "v1",
                Description = """
                    **EDUCATIONAL POC — FICTIONAL DATA ONLY**
                    
                    This API is a standalone demonstration of OAuth 2.0 JWT Bearer authentication
                    and scope-based authorization. All users and identity data are completely fictional.
                    
                    This is NOT connected to any government, national identity, or external system.
                    
                    **Protected endpoints require a JWT Bearer access token** issued by the
                    companion Identity Provider (IdentityProvider.Api) with the `identity.read` scope.
                    
                    To obtain a token:
                    1. Run IdentityProvider.Api (https://localhost:7001)
                    2. Complete the OAuth Authorization Code + PKCE flow
                    3. Use the returned access token in the Authorization header below
                    """
            });

            // JWT Bearer security definition
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Enter your JWT access token. Example: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            });

            // Apply Bearer requirement to all endpoints
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    []
                }
            });

            // Include XML documentation comments
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            if (File.Exists(xmlPath))
                options.IncludeXmlComments(xmlPath);
        });

        return services;
    }
}
