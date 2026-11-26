using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record WifiAudit(string Risk, string Security, string Advice);

public record PortsAudit(string Risk, List<int> RiskyPorts, string Advice);

// Analiza texto que el usuario pega de SU propio equipo. No ejecuta nada ni guarda el texto.
public static class NetworkAudit
{
    private static readonly Dictionary<int, string> Risky = new()
    {
        [21] = RiskLevels.High, [23] = RiskLevels.High, [3389] = RiskLevels.High, [5900] = RiskLevels.High,
        [135] = RiskLevels.Medium, [139] = RiskLevels.Medium, [445] = RiskLevels.Medium
    };

    // Entrada: salida de "netsh wlan show interfaces". Devuelve null si no encuentra el cifrado.
    public static WifiAudit? Wifi(string text)
    {
        var m = Regex.Match(text, @"^\s*(Authentication|Autenticaci.n)\s*:\s*(.+?)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);
        if (!m.Success) return null;

        var value = m.Groups[2].Value;
        if (value.Contains("WPA3", StringComparison.OrdinalIgnoreCase))
            return new WifiAudit(RiskLevels.Low, value, "Buen cifrado.");
        if (value.Contains("WPA2", StringComparison.OrdinalIgnoreCase))
            return new WifiAudit(RiskLevels.Low, value, "Cifrado correcto. Si tu router lo permite, usa WPA3.");
        if (value.Contains("WEP", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Open", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Abiert", StringComparison.OrdinalIgnoreCase))
            return new WifiAudit(RiskLevels.High, value, "Sin cifrado o con WEP, que se rompe en minutos. Activa WPA2 o WPA3 en el router.");

        return new WifiAudit(RiskLevels.Medium, value, "Cifrado antiguo. Cambia a WPA2 o WPA3 en el router.");
    }

    // Entrada: salida de "netstat -an". Solo cuenta puertos en escucha abiertos a toda la red.
    public static PortsAudit Ports(string text)
    {
        var found = new SortedSet<int>();
        var matches = Regex.Matches(text,
            @"^\s*TCP\s+(0\.0\.0\.0|\[::\]):(\d+)\s+\S+\s+(LISTENING|ESCUCHANDO)",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        foreach (Match m in matches)
            if (int.TryParse(m.Groups[2].Value, out var port) && Risky.ContainsKey(port))
                found.Add(port);

        var risk = found.Any(p => Risky[p] == RiskLevels.High) ? RiskLevels.High
                 : found.Count > 0 ? RiskLevels.Medium
                 : RiskLevels.Low;

        var advice = found.Count == 0
            ? "No hay puertos riesgosos abiertos a la red."
            : "Cierra o bloquea con el firewall los puertos de la lista si no los necesitas.";

        return new PortsAudit(risk, found.ToList(), advice);
    }
}