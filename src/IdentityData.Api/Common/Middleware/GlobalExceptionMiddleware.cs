using FluentValidation;
using System.Text.Json;

namespace IdentityData.Api.Common.Middleware;

/// <summary>
/// Global exception handler that maps exceptions to safe HTTP JSON responses.
/// Ensures no stack traces or internal details leak to clients.
/// </summary>
public sealed class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;

    public GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (ValidationException ex)
        {
            var firstError = ex.Errors.FirstOrDefault();
            var message = firstError?.ErrorMessage ?? "Validation failed.";
            _logger.LogWarning("Validation error: {Message}", message);
            await WriteErrorAsync(context, "invalid_request", message, StatusCodes.Status400BadRequest);
        }
        catch (Exception ex)
        {
            // Log the full exception internally but return a generic error to the client
            _logger.LogError(ex, "Unexpected error processing request to {Path}", context.Request.Path);
            await WriteErrorAsync(context, "server_error",
                "An unexpected error occurred.", StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task WriteErrorAsync(
        HttpContext context,
        string error,
        string? description,
        int statusCode)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";

        var body = new Dictionary<string, string?> { ["error"] = error };
        if (!string.IsNullOrWhiteSpace(description))
        {
            body["error_description"] = description;
        }

        await context.Response.WriteAsync(JsonSerializer.Serialize(body));
    }
}
