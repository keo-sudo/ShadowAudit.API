using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using ShadowAudit.API.Data;
using ShadowAudit.Tests.Support;

namespace ShadowAudit.Tests.Integration;

[Collection("api")]
public class TwoFactorTests
{
    private readonly TestApiFactory _f;

    public TwoFactorTests(ApiFixture fixture)
    {
        _f = fixture.Factory;
    }

    private static string CodeFor(string manualKey) =>
        new Totp(Base32Encoding.ToBytes(manualKey)).ComputeTotp();

    // Cuenta nueva con 2FA ya activado. Devuelve la clave, los codigos de recuperacion y un cliente con sesion.
    private async Task<(TestUser User, string Ip, string Key, List<string> Codes, HttpClient Authed)> EnabledAccount()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var anonymous = _f.NewClient(ip);
        await anonymous.Register(user);
        var session = await anonymous.LoginOk(user);
        var authed = _f.NewClient(ip).Bearer(session.Token);

        var setup = await authed.PostAsync("/api/2fa/setup", null);
        Assert.Equal(HttpStatusCode.OK, setup.StatusCode);
        var key = (await setup.Json()).GetProperty("manualKey").GetString()!;

        var enable = await authed.PostAsJsonAsync("/api/2fa/enable", new { code = CodeFor(key) });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
        var codes = (await enable.Json()).GetProperty("recoveryCodes")
            .EnumerateArray().Select(e => e.GetString()!).ToList();

        return (user, ip, key, codes, authed);
    }

    [Fact]
    public async Task Enabling_2fa_gives_ten_recovery_codes_and_login_then_requires_a_code()
    {
        var (user, ip, _, codes, authed) = await EnabledAccount();

        Assert.Equal(10, codes.Count);

        var status = await (await authed.GetAsync("/api/2fa/status")).Json();
        Assert.True(status.GetProperty("enabled").GetBoolean());
        Assert.Equal(10, status.GetProperty("recoveryCodesRemaining").GetInt32());

        var withoutCode = await _f.NewClient(ip).Login(user);
        Assert.Equal(HttpStatusCode.Unauthorized, withoutCode.StatusCode);
        Assert.True((await withoutCode.Json()).GetProperty("twoFactorRequired").GetBoolean());
    }

    [Fact]
    public async Task A_recovery_code_logs_in_once_and_then_stops_working()
    {
        var (user, ip, _, codes, _) = await EnabledAccount();
        var client = _f.NewClient(ip);

        Assert.Equal(HttpStatusCode.OK, (await client.Login(user, codes[0])).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.Login(user, codes[0])).StatusCode);

        var session = await client.LoginOk(user, codes[1]);
        var status = await (await _f.NewClient(ip).Bearer(session.Token).GetAsync("/api/2fa/status")).Json();
        Assert.Equal(8, status.GetProperty("recoveryCodesRemaining").GetInt32());
    }

    [Fact]
    public async Task Disabling_2fa_needs_the_password_and_a_valid_code()
    {
        var (user, _, _, codes, authed) = await EnabledAccount();

        var wrongPassword = await authed.PostAsJsonAsync("/api/2fa/disable",
            new { password = "Otra-Clave-Equivocada-1", code = codes[0] });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);

        var wrongCode = await authed.PostAsJsonAsync("/api/2fa/disable",
            new { password = user.Password, code = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCode.StatusCode);

        var ok = await authed.PostAsJsonAsync("/api/2fa/disable",
            new { password = user.Password, code = codes[0] });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var status = await (await authed.GetAsync("/api/2fa/status")).Json();
        Assert.False(status.GetProperty("enabled").GetBoolean());
        Assert.Equal(0, status.GetProperty("recoveryCodesRemaining").GetInt32());

        var again = await authed.PostAsJsonAsync("/api/2fa/disable",
            new { password = user.Password, code = codes[1] });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task Enabling_with_a_wrong_code_fails_and_leaves_2fa_off()
    {
        var user = TestUser.New();
        var ip = TestApiFactory.NextIp();
        var anonymous = _f.NewClient(ip);
        await anonymous.Register(user);
        var session = await anonymous.LoginOk(user);
        var authed = _f.NewClient(ip).Bearer(session.Token);

        Assert.Equal(HttpStatusCode.OK, (await authed.PostAsync("/api/2fa/setup", null)).StatusCode);

        var enable = await authed.PostAsJsonAsync("/api/2fa/enable", new { code = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, enable.StatusCode);

        var status = await (await authed.GetAsync("/api/2fa/status")).Json();
        Assert.False(status.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task Setup_is_rejected_when_2fa_is_already_enabled()
    {
        var (_, _, _, _, authed) = await EnabledAccount();

        var response = await authed.PostAsync("/api/2fa/setup", null);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task The_secret_and_the_recovery_codes_are_never_stored_in_plain_text()
    {
        var (user, _, key, codes, _) = await EnabledAccount();

        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();

        var stored = await db.Users.AsNoTracking()
            .Where(u => u.Email == user.Email)
            .Select(u => u.TwoFactorSecret)
            .SingleAsync();

        Assert.NotNull(stored);
        Assert.NotEqual(key, stored);
        Assert.DoesNotContain(key, stored);

        var userId = await db.Users.AsNoTracking()
            .Where(u => u.Email == user.Email)
            .Select(u => u.Id)
            .SingleAsync();

        var hashes = await db.RecoveryCodes.AsNoTracking()
            .Where(r => r.UserId == userId)
            .Select(r => r.CodeHash)
            .ToListAsync();

        Assert.Equal(10, hashes.Count);
        Assert.All(hashes, hash => Assert.DoesNotContain(hash, codes));
    }
}
