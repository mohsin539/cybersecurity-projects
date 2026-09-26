using System.Net;

namespace ProxyCore.Security;

/// <summary>
/// Blocks connections to loopback / link-local / site-local / cloud-metadata targets.
/// OWASP A10:2021 (SSRF), NIST SP 800-53 SC-7 (boundary protection).
/// Applied when security.denyPrivateTargets is enabled.
/// </summary>
public static class SsrfGuard
{
    public static bool IsForbidden(IPAddress ip)
    {
        if (IPAddress.IPv6Loopback.Equals(ip)) return true;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (IPAddress.Loopback.Equals(ip)) return true;
            var bytes = ip.GetAddressBytes();
            // 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (incl. metadata 169.254.169.254), 0.0.0.0/8
            if (bytes[0] == 127 || bytes[0] == 10 || bytes[0] == 0) return true;
            if (bytes[0] == 172 && (bytes[1] & 0xF0) == 16) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            return false;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
            var bytes = ip.GetAddressBytes();
            // Unique-local fc00::/7
            if ((bytes[0] & 0xFE) == 0xFC) return true;
            return false;
        }
        return false;
    }

    public static bool IsForbidden(string hostOrIp)
    {
        if (IPAddress.TryParse(hostOrIp, out var ip)) return IsForbidden(ip);
        return false;
    }
}
