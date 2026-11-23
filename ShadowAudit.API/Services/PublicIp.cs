using System.Net;
using System.Net.Sockets;

namespace ShadowAudit.API.Services;

public static class PublicIp
{
    // true solo si la IP es una dirección pública de internet.
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) ||
            ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None))
            return false;

        var b = ip.GetAddressBytes();

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 0 || b[0] == 10 || b[0] == 127) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;
            if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
            if (b[0] >= 224) return false;
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6Teredo) return false;
            if ((b[0] & 0xFE) == 0xFC) return false;
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false;
            if (b.Take(12).All(x => x == 0)) return false;
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
                b.Skip(4).Take(8).All(x => x == 0)) return false;
            return true;
        }

        return false;
    }
}