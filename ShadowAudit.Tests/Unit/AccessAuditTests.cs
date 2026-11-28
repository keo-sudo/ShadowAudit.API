using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class AccessAuditTests
{
    private static readonly DateTime Now = new(2026, 11, 28, 12, 0, 0, DateTimeKind.Utc);

    private static AccessEvent Ok(string ip, string agent, DateTime at) => new("LoginSuccess", ip, agent, at);

    private static AccessEvent Fail(DateTime at) => new("LoginFailed", "1.2.3.4", "ua", at);

    [Fact]
    public void Sin_historial_anterior_no_marca_ips_nuevas()
    {
        var r = AccessAudit.Analyze(new[] { Ok("1.1.1.1", "A", Now.AddHours(-1)) }, Now);

        Assert.False(r.HasBaseline);
        Assert.Equal(RiskLevels.Low, r.Risk);
        Assert.Empty(r.NewIps);
    }

    [Fact]
    public void Una_ip_nueva_con_historial_sube_a_medio_y_se_oculta()
    {
        var r = AccessAudit.Analyze(new[]
        {
            Ok("1.1.1.1", "A", Now.AddDays(-10)),
            Ok("9.9.9.9", "A", Now.AddDays(-1))
        }, Now);

        Assert.Equal(RiskLevels.Medium, r.Risk);
        Assert.Equal("9.9.9.x", Assert.Single(r.NewIps));
    }

    [Fact]
    public void Un_navegador_nuevo_con_historial_sube_a_medio()
    {
        var r = AccessAudit.Analyze(new[]
        {
            Ok("1.1.1.1", "Chrome", Now.AddDays(-10)),
            Ok("1.1.1.1", "Firefox", Now.AddDays(-1))
        }, Now);

        Assert.Equal(RiskLevels.Medium, r.Risk);
        Assert.Single(r.NewDevices);
    }

    [Fact]
    public void Cinco_fallos_en_24_horas_son_medio_y_diez_son_alto()
    {
        var cinco = Enumerable.Range(0, 5).Select(_ => Fail(Now.AddHours(-1))).ToArray();
        var diez = Enumerable.Range(0, 10).Select(_ => Fail(Now.AddHours(-1))).ToArray();

        Assert.Equal(RiskLevels.Medium, AccessAudit.Analyze(cinco, Now).Risk);
        Assert.Equal("alto", AccessAudit.Analyze(diez, Now).Risk);
    }

    [Fact]
    public void La_reutilizacion_de_token_es_riesgo_alto()
    {
        var r = AccessAudit.Analyze(new[] { new AccessEvent("RefreshTokenReuse", "1.1.1.1", "A", Now.AddDays(-1)) }, Now);

        Assert.Equal("alto", r.Risk);
    }

    [Fact]
    public void Tres_ips_en_una_hora_suben_a_medio()
    {
        var r = AccessAudit.Analyze(new[]
        {
            Ok("1.1.1.1", "A", Now.AddMinutes(-50)),
            Ok("2.2.2.2", "A", Now.AddMinutes(-40)),
            Ok("3.3.3.3", "A", Now.AddMinutes(-30))
        }, Now);

        Assert.Equal(RiskLevels.Medium, r.Risk);
    }
}