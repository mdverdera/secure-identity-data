using IdentityProvider.Api.Common.Extensions;
using IdentityProvider.Api.Common.Middleware;
using Serilog;

// ──────────────────────────────────────────────────────────────────────────────
// Demo Identity Provider — Phase 1
// ⚠️  This is an independent educational POC. It does NOT connect to, replicate,
//     or represent Singpass, MyInfo, or any government identity service.
//     All users and identity data are fictional test data.
// ──────────────────────────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);

// ── Structured Logging ────────────────────────────────────────────────────────
builder.Host.UseSerilog((context, loggerConfig) =>
    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console(outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext} {Message:lj}{NewLine}{Exception}"));

// ── Application Services ──────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddIdentityProviderServices(builder.Configuration);

// ── Swagger UI ────────────────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new()
    {
        Title = "Demo Identity Provider API",
        Version = "v1",
        Description = """
            ⚠️ Educational Proof of Concept — Not for production use.
            This is an independent POC demonstrating OAuth 2.1 Authorization Code + PKCE patterns.
            It does NOT connect to any government identity service.
            All users and identity data are fictional test data.
            """,
    });
});

// ── HTTPS / Security ──────────────────────────────────────────────────────────
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

// ── Middleware Pipeline ───────────────────────────────────────────────────────

// Global exception handler must be first
app.UseMiddleware<GlobalExceptionMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Demo Identity Provider v1");
        options.RoutePrefix = "swagger";
        options.DocumentTitle = "Demo Identity Provider — POC";
    });
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.MapControllers();

// ── Startup Banner ────────────────────────────────────────────────────────────
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("╔══════════════════════════════════════════════════════╗");
logger.LogInformation("║  DEMO Identity Provider — Phase 1                    ║");
logger.LogInformation("║  Educational POC — Not for production use            ║");
logger.LogInformation("║  Not affiliated with any government identity service  ║");
logger.LogInformation("╚══════════════════════════════════════════════════════╝");

app.Run();

// Required for WebApplicationFactory<Program> in integration tests
public partial class Program { }
