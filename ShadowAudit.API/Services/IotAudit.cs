using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record IotPort(int Port, string Name, string Risk);

public record IotResult(string Risk, List<IotPort> Findings);

// Lee texto pegado (salida de nmap de TU dispositivo) y marca puertos riesgosos de IoT.
public static class IotAudit
{
    private static readonly Dictionary<int, (string Name, string Risk)> Known = new()
    {
        [21] = ("FTP (sin cifrado)", RiskLevels.High),
        [23] = ("Telnet (sin cifrado)", RiskLevels.High),
        [5555] = ("Android Debug Bridge", RiskLevels.High),
        [37777] = ("Dahua (cámaras)", RiskLevels.High),
        [554] = ("RTSP (video de cámaras)", RiskLevels.Medium),
        [1883] = ("MQTT sin cifrado", RiskLevels.Medium),
        [8000] = ("Hikvision (cámaras)", RiskLevels.Medium)
    };

    public static IotResult Analyze(string text)
    {
        var found = new SortedDictionary<int, IotPort>();
        var matches = Regex.Matches(text, @"^\s*(\d{1,5})/tcp\s+open", RegexOptions.IgnoreCase | RegexOptions.Multiline);

        foreach (Match m in matches)
            if (int.TryParse(m.Groups[1].Value, out var port) && Known.TryGetValue(port, out var k))
                found[port] = new IotPort(port, k.Name, k.Risk);

        var list = found.Values.ToList();
        var risk = list.Any(f => f.Risk == RiskLevels.High) ? RiskLevels.High
                 : list.Count > 0 ? RiskLevels.Medium
                 : RiskLevels.Low;

        return new IotResult(risk, list);
    }
}