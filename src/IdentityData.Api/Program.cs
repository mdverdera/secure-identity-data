using IdentityData.Api.Common.Extensions;
using IdentityData.Api.Common.Middleware;
using IdentityData.Api.Infrastructure.Persistence;
using Serilog;

// ──────────────────────────────────────────────────────────────────────────────
// Demo Identity Data Resource Server — Phase 2
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
builder.Services.AddIdentityDataServices(builder.Configuration);

// ── Swagger UI ────────────────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new()
    {
        Title = "Demo Identity Data API",
        Version = "v1",
        Description = """
            ⚠️ Educational Proof of Concept — Not for production use.
            This is an independent POC demonstrating a protected resource server
            that validates OAuth 2.1 JWT bearer tokens.
            It does NOT connect to any government identity service.
            All users and identity data are fictional test data.
            """,
    });
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter your JWT access token.",
    });
    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer",
                },
            },
            Array.Empty<string>()
        },
    });
});

// ── HTTPS / Security ──────────────────────────────────────────────────────────
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

// ── Database Initialisation ───────────────────────────────────────────────────
// POC: Create and seed the database on startup
// Production: use proper migration strategy
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityDataDbContext>();
    db.Database.EnsureCreated();
}

// ── Middleware Pipeline ───────────────────────────────────────────────────────

// Global exception handler must be first
app.UseMiddleware<GlobalExceptionMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Demo Identity Data API v1");
        options.RoutePrefix = "swagger";
        options.DocumentTitle = "Demo Identity Data API — POC";
    });
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// ── Startup Banner ────────────────────────────────────────────────────────────
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("╔══════════════════════════════════════════════════════╗");
logger.LogInformation("║  DEMO Identity Data API — Phase 2                    ║");
logger.LogInformation("║  Educational POC — Not for production use            ║");
logger.LogInformation("║  Not affiliated with any government identity service  ║");
logger.LogInformation("╚══════════════════════════════════════════════════════╝");

app.Run();

// Required for WebApplicationFactory<Program> in integration tests
public partial class Program { }
