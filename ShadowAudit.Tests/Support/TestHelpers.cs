using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace ShadowAudit.Tests.Support;

public sealed record TestUser(string Username, string Email, string Password)
{
    // Usuario nuevo y unico en cada llamada. La clave cumple la politica de la API.
    public static TestUser New()
    {
        var id = Guid.NewGuid().ToString("N")[..10];
        return new TestUser($"user{id}", $"user{id}@test.com", "Clave-Larga-De-Prueba-2031");
    }
}

public sealed record Session(string Token, string RefreshToken);

public static class Samples
{
    // Correo de phishing de ejemplo: el analisis local (sin servicios externos) lo califica "alto".
    public const string PhishingHeaders = """
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=paypa1-seguridad.com; dkim=none; dmarc=fail header.from=paypa1-seguridad.com
From: "PayPal" <soporte@paypa1-seguridad.com>
Reply-To: <cobros@otro-dominio.xyz>
Return-Path: <bounce@otro-dominio.xyz>
Subject: Cuenta suspendida
""";
}

public static class ApiExtensions
{
    public static Task<HttpResponseMessage> Register(this HttpClient client, TestUser user) =>
        client.PostAsJsonAsync("/api/auth/register",
            new { username = user.Username, email = user.Email, password = user.Password });

    public static Task<HttpResponseMessage> Login(
        this HttpClient client, TestUser user, string? twoFactorCode = null, string? password = null) =>
        client.PostAsJsonAsync("/api/auth/login",
            new { email = user.Email, password = password ?? user.Password, twoFactorCode });

    public static async Task<Session> LoginOk(this HttpClient client, TestUser user, string? twoFactorCode = null)
    {
        var response = await client.Login(user, twoFactorCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Json();
        return new Session(
            json.GetProperty("token").GetString()!,
            json.GetProperty("refreshToken").GetString()!);
    }

    public static async Task<JsonElement> Json(this HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    public static HttpClient Bearer(this HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    // Guarda un hallazgo usando el analisis de correos (es local: no usa servicios externos).
    public static Task<HttpResponseMessage> SaveEmailFinding(this HttpClient client, string? label) =>
        client.PostAsJsonAsync("/api/threats/email-headers",
            new { headers = Samples.PhishingHeaders, label });
}
