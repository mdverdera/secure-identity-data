using IdentityData.Api.Domain.Exceptions;
using System.Net;
using System.Text.Json;

namespace IdentityData.Api.Common.Middleware;

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
        catch (UserNotFoundException ex)
        {
            _logger.LogInformation("User not found: {Message}", ex.Message);
            await WriteErrorResponseAsync(context, HttpStatusCode.NotFound, "not_found", "The requested identity was not found.");
        }
        catch (IdentityDataException ex)
        {
            _logger.LogWarning("Domain exception: {Message}", ex.Message);
            await WriteErrorResponseAsync(context, HttpStatusCode.BadRequest, "bad_request", ex.Message);
        }
        catch (Exception ex)
        {
            // Do NOT expose internal details
            _logger.LogError(ex, "Unhandled exception processing {Method} {Path}", 
                context.Request.Method, context.Request.Path);
            await WriteErrorResponseAsync(context, HttpStatusCode.InternalServerError, 
                "server_error", "An unexpected error occurred.");
        }
    }

    private static async Task WriteErrorResponseAsync(
        HttpContext context, HttpStatusCode statusCode, string error, string description)
    {
        context.Response.StatusCode = (int)statusCode;
        context.Response.ContentType = "application/json";

        var response = new { error, error_description = description };
        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });

        await context.Response.WriteAsync(json);
    }
}
