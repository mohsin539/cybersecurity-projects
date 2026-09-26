using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

namespace ProxyCore.Net;

/// <summary>
/// Resolves the configured bind string to a concrete IPAddress for listeners.
/// Supported forms:
///   "127.0.0.1"      → that IP (default; loopback-only posture)
///   "localhost"      → 127.0.0.1
///   "auto"           → first site-local (LAN) IPv4, else loopback (fail closed to loopback)
///   "*" / "0.0.0.0"  → IPv6Any with DualMode (all interfaces, explicit user choice)
///   any IP/hostname  → parsed/resolved to a concrete address
/// Failure mode: throws ArgumentException — the service must not silently bind elsewhere.
/// </summary>
public static class BindResolver
{
    public static IPAddress Resolve(string? configured)
    {
        var raw = (configured ?? "").Trim();
        if (raw.Length == 0) raw = "127.0.0.1";

        if (raw is "*" or "0.0.0.0" or "::") return IPAddress.IPv6Any; // DualMode socket covers v4+v6

        if (raw.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return IPAddress.Loopback;

        if (raw.Equals("auto", StringComparison.OrdinalIgnoreCase))
            return DetectLanIp() ?? IPAddress.Loopback;

        // Literal IP first
        if (IPAddress.TryParse(raw, out var literal))
            return literal;

        // Hostname: resolve and prefer an IPv4 site-local address assigned to this machine
        try
        {
            var entry = Dns.GetHostEntry(raw);
            var candidate = entry.AddressList
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                .ThenByDescending(IsRfc1918)
                .FirstOrDefault();
            if (candidate is not null) return candidate;
            throw new ArgumentException($"bind '{raw}' resolved to no usable IPv4/IPv6 address.");
        }
        catch (ArgumentException) { throw; }
        catch (Exception ex)
        {
            throw new ArgumentException($"bind '{raw}' could not be resolved: {ex.Message}");
        }
    }

    /// <summary>True for RFC1918 private IPv4 addresses (10/8, 172.16/12, 192.168/16).</summary>
    public static bool IsRfc1918(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var s = ip.ToString();
        return s.StartsWith("10.")
            || s.StartsWith("192.168.")
            || IsPrivate172(s);
    }

    private static bool IsPrivate172(string s)
    {
        // 172.16.0.0 – 172.31.255.255
        var parts = s.Split('.');
        if (parts.Length < 2 || !int.TryParse(parts[1], out var second)) return false;
        return second >= 16 && second <= 31;
    }

    /// <summary>
    /// The IPv4 address the OS would use to reach the LAN (primary route), i.e. the "real"
    /// adapter rather than virtual ones. Falls back to enumerating live interfaces.
    /// </summary>
    public static IPAddress? DetectLanIp()
    {
        // Primary path: ask the routing table which source address a LAN-bound packet uses.
        // (UDP connect does not send packets; it just resolves the route.)
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(IPAddress.Parse("192.168.255.255"), 1));
            if (s.LocalEndPoint is IPEndPoint ep
                && ep.Address.AddressFamily == AddressFamily.InterNetwork
                && !IPAddress.IsLoopback(ep.Address)
                && IsRfc1918(ep.Address))
            {
                return ep.Address;
            }
        }
        catch { /* fall through to enumeration */ }

        // Fallback: enumerate live interfaces (may pick virtual adapters when several match).
        var candidates = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var info in nic.GetIPProperties().UnicastAddresses)
                {
                    var ip = info.Address;
                    if (ip.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(ip)) continue;
                    if (IsRfc1918(ip)) candidates.Add(ip);
                }
            }
        }
        catch { /* best effort */ }

        return candidates
            .OrderByDescending(a => a.ToString().StartsWith("192.168."))
            .ThenByDescending(a => a.ToString().StartsWith("10."))
            .FirstOrDefault();
    }
}
