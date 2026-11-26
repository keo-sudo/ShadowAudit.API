using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class NetworkAuditTests
{
    [Theory]
    [InlineData("    Authentication         : WPA3-Personal", "bajo")]
    [InlineData("    Autenticación          : WPA2-Personal", "bajo")]
    [InlineData("    Authentication         : WPA-Personal", "medio")]
    [InlineData("    Authentication         : Open", "alto")]
    [InlineData("    Autenticación          : Abierta", "alto")]
    public void Evalua_el_cifrado_del_wifi(string linea, string esperado)
    {
        var audit = NetworkAudit.Wifi("    SSID : MiRed\n" + linea + "\n    Signal : 90%");

        Assert.NotNull(audit);
        Assert.Equal(esperado, audit!.Risk);
    }

    [Fact]
    public void Wifi_sin_linea_de_autenticacion_devuelve_null() =>
        Assert.Null(NetworkAudit.Wifi("texto cualquiera que no es de netsh"));

    [Fact]
    public void Un_puerto_riesgoso_abierto_a_toda_la_red_es_alto()
    {
        var audit = NetworkAudit.Ports("  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING\n  TCP    [::]:445               [::]:0                 LISTENING");

        Assert.Equal(RiskLevels.High, audit.Risk);
        Assert.Equal(new[] { 445, 3389 }, audit.RiskyPorts);
    }

    [Fact]
    public void Un_puerto_solo_local_no_cuenta()
    {
        var audit = NetworkAudit.Ports("  TCP    127.0.0.1:445          0.0.0.0:0              LISTENING");

        Assert.Equal(RiskLevels.Low, audit.Risk);
        Assert.Empty(audit.RiskyPorts);
    }

    [Fact]
    public void Solo_puertos_medios_dan_riesgo_medio()
    {
        var audit = NetworkAudit.Ports("  TCP    0.0.0.0:135            0.0.0.0:0              ESCUCHANDO");

        Assert.Equal(RiskLevels.Medium, audit.Risk);
    }
}