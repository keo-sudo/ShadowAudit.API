using Scalar.AspNetCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using ShadowAudit.API.Services;

var builder = WebApplication.CreateBuilder(args);

// No revelar el servidor en el header "Server"
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// Logs con Serilog. En desarrollo: texto legible. En producción: JSON (una línea por evento).
// Privacidad: NUNCA se registran cuerpos de peticiones ni query strings (contraseñas, tokens, datos
// consultados). Los logs de HttpClient quedan en Warning porque a nivel Information escriben la URL
// completa de cada consulta saliente (por ejemplo, qué URL o hash se consultó en VirusTotal).
builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .MinimumLevel.Information()
        .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.EntityFrameworkCore.Database.Command", LogEventLevel.Warning)
        .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Application", "ShadowAudit.API");

    if (context.HostingEnvironment.IsDevelopment())
    {
        configuration.WriteTo.Console();
    }
    else
    {
        configuration.WriteTo.Console(new RenderedCompactJsonFormatter());
    }
});

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddDbContext<ShadowAuditDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<SessionService>();

// Limpieza periódica de refresh tokens vencidos hace más de 30 días
builder.Services.AddHostedService<RefreshTokenCleanupService>();

// Cliente para Have I Been Pwned (consulta de contraseñas filtradas, sin clave de API)
builder.Services.AddHttpClient<PasswordCheckService>(client =>
{
    client.BaseAddress = new Uri("https://api.pwnedpasswords.com/");
    client.Timeout = TimeSpan.FromSeconds(5);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ShadowAudit-API");
    client.DefaultRequestHeaders.Add("Add-Padding", "true");
});

// Cliente para VirusTotal. La clave viene de user-secrets ("VirusTotal:ApiKey"),
// nunca del código. Plan gratuito: 4 consultas por minuto y 500 por día, solo uso no comercial.
builder.Services.AddHttpClient<VirusTotalService>(client =>
{
    client.BaseAddress = new Uri("https://www.virustotal.com/api/v3/");
    client.Timeout = TimeSpan.FromSeconds(10);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ShadowAudit-API");

    var apiKey = builder.Configuration["VirusTotal:ApiKey"];
    if (!string.IsNullOrWhiteSpace(apiKey))
    {
        client.DefaultRequestHeaders.Add("x-apikey", apiKey);
    }
});

// Cliente para AbuseIPDB. La clave viene de user-secrets ("AbuseIPDB:ApiKey"), nunca del código.
builder.Services.AddHttpClient<AbuseIpDbService>(client =>
{
    client.BaseAddress = new Uri("https://api.abuseipdb.com/api/v2/");
    client.Timeout = TimeSpan.FromSeconds(10);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("ShadowAudit-API");
    client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

    var apiKey = builder.Configuration["AbuseIPDB:ApiKey"];
    if (!string.IsNullOrWhiteSpace(apiKey))
    {
        client.DefaultRequestHeaders.Add("Key", apiKey);
    }
});

// Cifrado de secretos 2FA. Las claves de cifrado se guardan FUERA del proyecto
// y de la base de datos. En producción, configura "DataProtection:KeysPath"
// con una carpeta persistente y con copia de seguridad.
var keysPath = builder.Configuration["DataProtection:KeysPath"]
               ?? Path.Combine(
                   Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                   "ShadowAudit", "keys");

var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("ShadowAudit.API")
    .PersistKeysToFileSystem(new DirectoryInfo(keysPath));

if (OperatingSystem.IsWindows())
{
    dataProtection.ProtectKeysWithDpapi();
}

builder.Services.AddSingleton<TwoFactorSecretProtector>();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]!)),
            // Por defecto .NET tolera 5 minutos de margen: un token de 15 minutos valdría 20
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        options.Events = new JwtBearerEvents
        {
            // Además de la firma y la fecha, se comprueba que la sesión del token siga abierta.
            // Así un cierre de sesión surte efecto al instante.
            OnTokenValidated = async context =>
            {
                var sessionClaim = context.Principal?.FindFirstValue("session_id");
                if (!Guid.TryParse(sessionClaim, out var sessionId))
                {
                    context.Fail("Token sin sesión.");
                    return;
                }

                var sessions = context.HttpContext.RequestServices.GetRequiredService<SessionService>();
                if (!await sessions.IsSessionActiveAsync(sessionId))
                {
                    context.Fail("Sesión cerrada o expirada.");
                }
            }
        };
    });

builder.Services.AddAuthorization();

// CORS: cerrado por defecto. Para permitir un frontend, agrega en la configuración
// "Cors": { "AllowedOrigins": [ "https://tu-frontend.com" ] }
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                     ?? Array.Empty<string>();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        if (allowedOrigins.Length > 0)
        {
            policy.WithOrigins(allowedOrigins)
                  .WithMethods("GET", "POST")
                  .WithHeaders("Authorization", "Content-Type");
        }
    });
});

// Límites de solicitudes: login/registro (10 por minuto por IP), renovación de sesión (30 por minuto
// por IP), contraseñas y cabeceras de correo (20 por minuto por IP), reputación de IPs (10 por minuto
// en total, una sola clave de AbuseIPDB) y amenazas con VirusTotal (2 por minuto en total, una sola
// clave de VirusTotal)
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.OnRejected = async (context, cancellationToken) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString();
        }

        await context.HttpContext.Response.WriteAsJsonAsync(
            new { message = "Demasiadas solicitudes. Intenta más tarde." },
            cancellationToken);
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var path = httpContext.Request.Path;
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (path.StartsWithSegments("/api/auth/login") ||
            path.StartsWithSegments("/api/auth/register"))
        {
            return RateLimitPartition.GetFixedWindowLimiter($"auth:{ip}", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        if (path.StartsWithSegments("/api/auth/refresh"))
        {
            return RateLimitPartition.GetFixedWindowLimiter($"refresh:{ip}", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 30,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        if (path.StartsWithSegments("/api/passwords"))
        {
            return RateLimitPartition.GetFixedWindowLimiter($"passwords:{ip}", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 20,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        // Este análisis es local (no usa servicios externos), por eso va antes que el límite global de /api/threats
        if (path.StartsWithSegments("/api/threats/email-headers"))
        {
            return RateLimitPartition.GetFixedWindowLimiter($"email:{ip}", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 20,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        // Reputación de IPs (AbuseIPDB): una sola clave compartida por toda la API
        if (path.StartsWithSegments("/api/threats/ip"))
        {
            return RateLimitPartition.GetFixedWindowLimiter("abuseipdb:global", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        if (path.StartsWithSegments("/api/threats"))
        {
            return RateLimitPartition.GetFixedWindowLimiter("threats:global", _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 2,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        }

        return RateLimitPartition.GetNoLimiter("none");
    });
});

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
        {
            ["Bearer"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Pega aquí el token JWT que devuelve /api/auth/login"
            }
        };

        document.Security =
        [
            new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference("Bearer", document)] = []
            }
        ];

        return Task.CompletedTask;
    });
});

ShadowAudit.API.Services.WebScannerSetup.AddWebScanner(builder.Services);

var app = builder.Build();

// Aplicar las migraciones al arrancar. Está APAGADO por defecto: solo se activa con
// "Database:MigrateOnStartup" = true (el docker-compose lo enciende). En desarrollo local
// sigues usando Update-Database como siempre.
if (app.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();
    db.Database.Migrate();
}

// Detrás de un proxy inverso (Nginx, Caddy, un balanceador...) la IP que ve la API sería la del proxy,
// y el límite de solicitudes por IP quedaría roto. Con esta opción se lee la IP real del cliente
// (X-Forwarded-For), pero SOLO si la petición llega desde un proxy que tú listaste.
// Apagado por defecto. Para activarlo:
//   "ForwardedHeaders": { "Enabled": true, "KnownProxies": [ "10.0.0.5" ] }
// Actívalo solo si la API únicamente es alcanzable a través de ese proxy.
if (app.Configuration.GetValue<bool>("ForwardedHeaders:Enabled"))
{
    var forwardedOptions = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
        ForwardLimit = 1
    };

    var knownProxies = app.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>()
                       ?? Array.Empty<string>();
    foreach (var proxy in knownProxies)
    {
        if (IPAddress.TryParse(proxy, out var proxyIp))
        {
            forwardedOptions.KnownProxies.Add(proxyIp);
        }
    }

    app.UseForwardedHeaders(forwardedOptions);
}

// Headers de seguridad en todas las respuestas
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        var path = context.Request.Path;

        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        // La documentación de Scalar (solo existe en Development) necesita
        // scripts y estilos propios, así que no lleva la CSP estricta.
        var isDocs = path.StartsWithSegments("/scalar") || path.StartsWithSegments("/openapi");
        if (!isDocs)
        {
            headers["Content-Security-Policy"] =
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
        }

        // Las respuestas de la API (tokens, historial) no se deben guardar en caché
        if (path.StartsWithSegments("/api"))
        {
            headers["Cache-Control"] = "no-store";
        }

        return Task.CompletedTask;
    });

    await next();
});

// Errores no controlados: respuesta genérica al cliente, detalle completo solo en el log
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var feature = context.Features.Get<IExceptionHandlerFeature>();
        if (feature?.Error is not null)
        {
            var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError(feature.Error, "Error no controlado en {Path}", context.Request.Path);
        }

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new { message = "Error interno del servidor." });
    });
});

// Una línea de log por petición: método, ruta (sin query string), estado, duración e IP del cliente.
// Va después del manejador de errores para que un 500 quede registrado como error.
app.UseSerilogRequestLogging(options =>
{
    options.MessageTemplate = "{RequestMethod} {RequestPath} respondió {StatusCode} en {Elapsed:0} ms";
    options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
    {
        diagnosticContext.Set("ClientIp", httpContext.Connection.RemoteIpAddress?.ToString());
    };
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseCors();

app.UseRateLimiter();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();