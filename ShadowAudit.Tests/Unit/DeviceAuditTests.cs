using ShadowAudit.API.Models;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Unit;

public class DeviceAuditTests
{
    private static string Arp(params (string Ip, string Mac)[] rows) =>
        "Interfaz: 192.168.1.5 --- 0x4\n  Dirección de Internet   Dirección física   Tipo\n" +
        string.Join("\n", rows.Select(r => $"  {r.Ip}   {r.Mac}   dinamico"));

    [Fact]
    public void Ignora_difusion_y_multicast_y_marca_la_mac_privada()
    {
        var r = DeviceAudit.Analyze(Arp(
            ("192.168.1.1", "aa-bb-cc-dd-ee-ff"),
            ("192.168.1.2", "a4-bb-cc-dd-ee-00"),
            ("192.168.1.20", "02-11-22-33-44-55"),
            ("192.168.1.255", "ff-ff-ff-ff-ff-ff"),
            ("224.0.0.22", "01-00-5e-00-00-16")), null);

        Assert.NotNull(r);
        Assert.Equal(3, r!.Total);
        Assert.False(r.Devices.Single(d => d.Ip == "192.168.1.2").PrivateMac);
        Assert.True(r.Devices.Single(d => d.Ip == "192.168.1.20").PrivateMac);
    }

    [Fact]
    public void Sin_lista_de_conocidos_el_riesgo_es_bajo()
    {
        var r = DeviceAudit.Analyze(Arp(("192.168.1.1", "aa-bb-cc-dd-ee-ff")), null);

        Assert.Equal(RiskLevels.Low, r!.Risk);
        Assert.Null(r.Devices[0].Known);
    }

    [Fact]
    public void Un_desconocido_sube_a_medio()
    {
        var r = DeviceAudit.Analyze(
            Arp(("192.168.1.1", "aa-bb-cc-dd-ee-ff"), ("192.168.1.30", "10-20-30-40-50-60")),
            new[] { "AA:BB:CC:DD:EE:FF" });

        Assert.Equal(RiskLevels.Medium, r!.Risk);
        Assert.Equal(1, r.Unknown);
    }

    [Fact]
    public void Tres_desconocidos_son_riesgo_alto()
    {
        var r = DeviceAudit.Analyze(
            Arp(("192.168.1.1", "aa-bb-cc-dd-ee-ff"), ("192.168.1.30", "10-20-30-40-50-60"),
                ("192.168.1.31", "10-20-30-40-50-61"), ("192.168.1.32", "10-20-30-40-50-62")),
            new[] { "aa-bb-cc-dd-ee-ff" });

        Assert.Equal("alto", r!.Risk);
    }

    [Fact]
    public void La_misma_mac_en_dos_ips_sube_a_medio()
    {
        var r = DeviceAudit.Analyze(
            Arp(("192.168.1.1", "aa-bb-cc-dd-ee-ff"), ("192.168.1.40", "aa-bb-cc-dd-ee-ff")), null);

        Assert.Equal(RiskLevels.Medium, r!.Risk);
        Assert.Single(r.SharedMacs);
    }

    [Fact]
    public void Un_texto_sin_dispositivos_devuelve_null()
    {
        Assert.Null(DeviceAudit.Analyze("esto no es la salida de arp -a", null));
    }
}