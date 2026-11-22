using System.Net;
using System.Net.Http.Json;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Integration;

[Collection("api")]
public class AuthTests
{
    private readonly TestApiFactory _f;

    public AuthTests(ApiFixture fixture)
    {
        _f = fixture.Factory;
    }

    [Fact]
    public async Task Register_works_and_a_duplicate_is_rejected()
    {
        var user = TestUser.New();
        var client = _f.NewClient();

        Assert.Equal(HttpStatusCode.OK, (await client.Register(user)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.Register(user)).StatusCode);
    }

    [Fact]
    public async Task Register_treats_the_email_as_case_insensitive()
    {
        var user = TestUser.New();
        var client = _f.NewClient();
        await client.Register(user);

        var upper = user with { Username = user.Username + "x", Email = user.Email.ToUpperInvariant() };

        Assert.Equal(HttpStatusCode.Conflict, (await client.Register(upper)).StatusCode);
    }

    [Theory]
    [InlineData("Corta1A")]
    [InlineData("todominusculas1234")]
    [InlineData("TODOMAYUSCULAS1234")]
    [InlineData("SinNumerosAquiHola")]
    [InlineData("Password1234")]
    public async Task Register_rejects_weak_passwords(string password)
    {
        var user = TestUser.New() with { Password = password };

        var response = await _f.NewClient().Register(user);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_rejects_a_password_that_contains_the_username()
    {
        var user = TestUser.New();
        var weak = user with { Password = $"Mi-{user.Username}-2031X" };

        var response = await _f.NewClient().Register(weak);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_rejects_an_invalid_email()
    {
        var response = await _f.NewClient().PostAsJsonAsync("/api/auth/register",
            new { username = "alguien", email = "esto-no-es-un-correo", password = "Clave-Larga-De-Prueba-2031" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_returns_tokens_and_wrong_credentials_look_identical()
    {
        var user = TestUser.New();
        var client = _f.NewClient();
        await client.Register(user);

        var ok = await client.Login(user);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var json = await ok.Json();
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("token").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(json.GetProperty("refreshToken").GetString()));

        var wrongPassword = await client.Login(user, password: "Otra-Clave-Equivocada-1");
        var unknownUser = await client.Login(TestUser.New());

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownUser.StatusCode);
        Assert.Equal(
            await wrongPassword.Content.ReadAsStringAsync(),
            await unknownUser.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Me_returns_the_account_for_a_valid_token()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var anonymous = _f.NewClient(ip);
        await anonymous.Register(user);
        var session = await anonymous.LoginOk(user);

        var response = await _f.NewClient(ip).Bearer(session.Token).GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(user.Email, (await response.Json()).GetProperty("email").GetString());
    }

    [Fact]
    public async Task Five_failed_logins_lock_the_account_even_with_the_right_password()
    {
        var user = TestUser.New();
        var client = _f.NewClient();
        await client.Register(user);

        for (var i = 0; i < 5; i++)
        {
            var wrong = await client.Login(user, password: "Otra-Clave-Equivocada-1");
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        var locked = await client.Login(user);

        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
    }

    [Fact]
    public async Task Refresh_rotates_the_token_and_reusing_the_old_one_closes_the_whole_session()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        var first = await client.LoginOk(user);

        var refreshed = await client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = first.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var json = await refreshed.Json();
        var newRefresh = json.GetProperty("refreshToken").GetString()!;
        var newAccess = json.GetProperty("token").GetString()!;
        Assert.NotEqual(first.RefreshToken, newRefresh);

        // Se vuelve a presentar el token viejo: se asume robo
        var reuse = await client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = first.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, reuse.StatusCode);

        // Y toda la sesion queda cerrada: ni el refresh nuevo ni el token de acceso nuevo sirven
        var afterReuse = await client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = newRefresh });
        Assert.Equal(HttpStatusCode.Unauthorized, afterReuse.StatusCode);

        var me = await _f.NewClient(ip).Bearer(newAccess).GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task Refresh_rejects_an_unknown_token()
    {
        var response = await _f.NewClient().PostAsJsonAsync("/api/auth/refresh",
            new { refreshToken = "este-token-no-existe-en-ninguna-sesion-1234567890" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Logout_takes_effect_immediately()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        var session = await client.LoginOk(user);
        var authed = _f.NewClient(ip).Bearer(session.Token);

        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await authed.PostAsync("/api/auth/logout", null)).StatusCode);

        // El token de acceso todavia no vencio, pero la sesion ya esta cerrada
        Assert.Equal(HttpStatusCode.Unauthorized, (await authed.GetAsync("/api/auth/me")).StatusCode);

        var refresh = await client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = session.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task LogoutAll_closes_every_session()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        var first = await client.LoginOk(user);
        var second = await client.LoginOk(user);
        var a = _f.NewClient(ip).Bearer(first.Token);
        var b = _f.NewClient(ip).Bearer(second.Token);

        Assert.Equal(HttpStatusCode.OK, (await a.PostAsync("/api/auth/logout-all", null)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await a.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await b.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task ChangePassword_closes_the_other_sessions_but_keeps_the_current_one()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        var first = await client.LoginOk(user);
        var second = await client.LoginOk(user);
        var a = _f.NewClient(ip).Bearer(first.Token);
        var b = _f.NewClient(ip).Bearer(second.Token);
        const string newPassword = "Otra-Clave-Larga-2032";

        var change = await a.PostAsJsonAsync("/api/auth/change-password",
            new { currentPassword = user.Password, newPassword });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await a.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await b.GetAsync("/api/auth/me")).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.Login(user)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.Login(user, password: newPassword)).StatusCode);
    }

    [Fact]
    public async Task ChangePassword_rejects_a_wrong_current_password_and_an_unchanged_one()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        var session = await client.LoginOk(user);
        var authed = _f.NewClient(ip).Bearer(session.Token);

        var wrongCurrent = await authed.PostAsJsonAsync("/api/auth/change-password",
            new { currentPassword = "Otra-Clave-Equivocada-1", newPassword = "Otra-Clave-Larga-2032" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCurrent.StatusCode);

        var same = await authed.PostAsJsonAsync("/api/auth/change-password",
            new { currentPassword = user.Password, newPassword = user.Password });
        Assert.Equal(HttpStatusCode.BadRequest, same.StatusCode);
    }

    [Fact]
    public async Task The_audit_log_records_events_but_never_the_password()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var client = _f.NewClient(ip);
        await client.Register(user);
        await client.Login(user, password: "Otra-Clave-Equivocada-1");
        var session = await client.LoginOk(user);

        var response = await _f.NewClient(ip).Bearer(session.Token).GetAsync("/api/auth/audit-log");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Register", body);
        Assert.Contains("LoginFailed", body);
        Assert.Contains("LoginSuccess", body);
        Assert.DoesNotContain(user.Password, body);
        Assert.DoesNotContain("Otra-Clave-Equivocada-1", body);
    }

    [Fact]
    public async Task Login_is_rate_limited_per_ip()
    {
        var client = _f.NewClient();
        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < 11; i++)
            statuses.Add((await client.Login(TestUser.New())).StatusCode);

        Assert.All(statuses.Take(10), s => Assert.Equal(HttpStatusCode.Unauthorized, s));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }

    [Fact]
    public async Task Responses_carry_the_security_headers()
    {
        var response = await _f.NewClient().GetAsync("/api/auth/me");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Theory]
    [InlineData("GET", "/api/auth/me")]
    [InlineData("GET", "/api/auth/audit-log")]
    [InlineData("POST", "/api/auth/logout")]
    [InlineData("POST", "/api/auth/logout-all")]
    [InlineData("POST", "/api/auth/change-password")]
    [InlineData("GET", "/api/2fa/status")]
    [InlineData("POST", "/api/2fa/setup")]
    [InlineData("POST", "/api/passwords/check")]
    [InlineData("GET", "/api/report")]
    [InlineData("GET", "/api/findings")]
    public async Task Protected_endpoints_require_a_token(string method, string url)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), url);

        var response = await _f.NewClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
