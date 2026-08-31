using FluentValidation;
using IdentityProvider.Api.Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace IdentityProvider.Api.Common.Middleware;

/// <summary>
/// Global exception handler that maps domain exceptions to appropriate HTTP responses.
/// Ensures no stack traces or internal details leak to clients.
/// All OAuth errors are returned in the standard RFC 6749 error format.
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
        catch (OAuthException ex)
        {
            _logger.LogWarning("OAuth error: {Error} — {Description}", ex.Error, ex.ErrorDescription);
            await WriteOAuthErrorAsync(context, ex.Error, ex.ErrorDescription, StatusCodes.Status400BadRequest);
        }
        catch (ValidationException ex)
        {
            // Map FluentValidation errors to OAuth error responses
            var firstError = ex.Errors.FirstOrDefault();
            var message = firstError?.ErrorMessage ?? "invalid_request";

            // Detect specific OAuth error types from validation messages
            var (error, statusCode) = message switch
            {
                var m when m.StartsWith("unsupported_response_type") => ("unsupported_response_type", 400),
                var m when m.StartsWith("unsupported_grant_type") => ("unsupported_grant_type", 400),
                _ => ("invalid_request", 400),
            };

            _logger.LogWarning("Validation error: {Message}", message);
            await WriteOAuthErrorAsync(context, error, message, statusCode);
        }
        catch (Exception ex)
        {
            // Log full exception internally but return a generic error to the client
            _logger.LogError(ex, "Unexpected error processing request to {Path}", context.Request.Path);
            await WriteOAuthErrorAsync(context, "server_error",
                "An unexpected error occurred.", StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task WriteOAuthErrorAsync(
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
