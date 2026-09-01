using IdentityData.Api.Common.Extensions;
using IdentityData.Api.Common.Middleware;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) =>
        configuration
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

    // Services
    builder.Services.AddControllers();
    builder.Services.AddIdentityDataApplication();
    builder.Services.AddJwtBearerAuthentication(builder.Configuration);
    builder.Services.AddJwkStartupService(builder.Configuration);
    builder.Services.AddIdentityDataPersistence(builder.Configuration);
    builder.Services.AddIdentityDataAuthorization();
    builder.Services.AddIdentityDataSwagger();

    // CORS — locked to https://localhost:3000 for Phase 4 Next.js client
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
        {
            var allowedOrigins = builder.Configuration
                .GetSection("AllowedOrigins")
                .Get<string[]>() ?? ["https://localhost:3000"];

            policy
                .WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod();
        });
    });

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Data API v1");
            options.RoutePrefix = "swagger";
        });
    }

    app.UseMiddleware<GlobalExceptionMiddleware>();
    app.UseHttpsRedirection();
    app.UseCors();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();

    Log.Information("IdentityData.Api starting on {Urls}", builder.Configuration["ASPNETCORE_URLS"] ?? "default");

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "IdentityData.Api terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

