using System.Collections.Concurrent;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace ShadowAudit.API.Services;

// Límite por IP para las acciones del escáner (escanear y verificar son costosas).
[AttributeUsage(AttributeTargets.Method)]
public sealed class SiteRateLimitAttribute : ActionFilterAttribute
{
    private static readonly ConcurrentDictionary<string, Queue<DateTime>> Hits = new();

    private readonly string _name;
    private readonly int _max;
    private readonly TimeSpan _window;

    public SiteRateLimitAttribute(string name, int max, int windowMinutes)
    {
        _name = name;
        _max = max;
        _window = TimeSpan.FromMinutes(windowMinutes);
    }

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var ip = context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (Hits.Count > 10_000) Hits.Clear();

        var queue = Hits.GetOrAdd($"{_name}:{ip}", _ => new Queue<DateTime>());
        var now = DateTime.UtcNow;

        lock (queue)
        {
            while (queue.Count > 0 && now - queue.Peek() > _window) queue.Dequeue();

            if (queue.Count >= _max)
            {
                context.Result = new ObjectResult(new { message = "Demasiados intentos. Espera un momento antes de volver a intentarlo." })
                {
                    StatusCode = StatusCodes.Status429TooManyRequests
                };
                return;
            }

            queue.Enqueue(now);
        }
    }
}