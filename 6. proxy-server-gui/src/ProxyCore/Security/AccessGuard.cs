using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ProxyCore.Options;

namespace ProxyCore.Security;

/// <summary>
/// Guards a client connection before any proxying: rate limits, per-client caps, auth.
/// OWASP A04 (rate limits), A07 (authN); NIST SP 800-53 AC-7 (unsuccessful logon throttling), SC-5.
/// </summary>
public sealed class AccessGuard
{
    private readonly ProxyConfig _cfg;
    private readonly RateLimiter _connectLimiter;
    private readonly RateLimiter _httpLimiter;
    private readonly SecretVault? _vault;
    private readonly ConcurrentDictionary<IPAddress, int> _perClient = new();
    private readonly ConcurrentDictionary<string, int> _failedAuthByIp = new();
    private readonly ConcurrentDictionary<string, DateTime> _authLockedUntil = new();
    private readonly (IPAddress net, int prefix, AddressFamily fam)[] _allowNets;
    private readonly (IPAddress net, int prefix, AddressFamily fam)[] _denyNets;

    public AccessGuard(ProxyConfig cfg, SecretVault? vault)
    {
        _cfg = cfg;
        _vault = vault;
        _connectLimiter = new RateLimiter(cfg.Limits.ConnectRatePerMinute, cfg.Limits.RateBlockSeconds);
        _httpLimiter = new RateLimiter(cfg.Security.HttpRatePerMinute, cfg.Limits.RateBlockSeconds);
        _allowNets = ParseCidrs(cfg.Security.Clients?.Allow, "security.clients.allow");
        _denyNets = ParseCidrs(cfg.Security.Clients?.Deny, "security.clients.deny");
    }

    /// <summary>Client-IP allowlist enforcement (AC-3). Deny wins over allow. Empty allow = permit all.</summary>
    public bool IsClientAllowed(IPAddress client)
    {
        if (client.AddressFamily == AddressFamily.InterNetworkV6 && client.IsIPv4MappedToIPv6)
            client = client.MapToIPv4();

        foreach (var (net, prefix, fam) in _denyNets)
            if (fam == client.AddressFamily && InSubnet(client, net, prefix)) return false;

        if (_allowNets.Length == 0) return true;

        foreach (var (net, prefix, fam) in _allowNets)
            if (fam == client.AddressFamily && InSubnet(client, net, prefix)) return true;

        return false;
    }

    private static (IPAddress, int, AddressFamily)[] ParseCidrs(List<string>? entries, string what)
    {
        if (entries is null || entries.Count == 0) return Array.Empty<(IPAddress, int, AddressFamily)>();
        var list = new List<(IPAddress, int, AddressFamily)>();
        foreach (var e in entries)
        {
            var entry = (e ?? "").Trim();
            if (entry.Length == 0) continue;
            try
            {
                var ipn = IPNetwork.Parse(entry);   // accepts single IP or CIDR
                list.Add((ipn.BaseAddress, ipn.PrefixLength, ipn.BaseAddress.AddressFamily));
            }
            catch
            {
                // Fail closed for malformed allow entries is safest, but that could lock the
                // operator out on a typo — so log loudly at construction instead.
                Console.Error.WriteLine($"[config] WARNING: invalid CIDR '{entry}' in {what} (entry ignored)");
            }
        }
        return list.ToArray();
    }

    private static bool InSubnet(IPAddress ip, IPAddress net, int prefix)
    {
        var ipB = ip.GetAddressBytes();
        var netB = net.GetAddressBytes();
        if (ipB.Length != netB.Length) return false;
        int full = prefix / 8, rem = prefix % 8;
        for (int i = 0; i < full; i++)
            if (ipB[i] != netB[i]) return false;
        if (rem > 0 && full < ipB.Length)
        {
            int mask = 0xFF << (8 - rem);
            if ((ipB[full] & mask) != (netB[full] & mask)) return false;
        }
        return true;
    }

    public bool TryAdmitConnect(IPAddress client) => _connectLimiter.Allow(client);

    public bool TryAdmitHttpRequest(IPAddress client) => _httpLimiter.Allow(client);

    public bool TryReserveClientSlot(IPAddress client, out IDisposable release)
    {
        while (true)
        {
            var current = _perClient.GetOrAdd(client, 0);
            if (current >= _cfg.Limits.MaxConnectionsPerClient)
            {
                release = NullRelease.Instance;
                return false;
            }
            if (_perClient.TryUpdate(client, current + 1, current))
            {
                var cookie = new SlotRelease(this, client);
                release = cookie;
                return true;
            }
        }
    }

    private sealed class SlotRelease : IDisposable
    {
        private readonly AccessGuard _owner;
        private readonly IPAddress _ip;
        private bool _done;
        public SlotRelease(AccessGuard owner, IPAddress ip) { _owner = owner; _ip = ip; }
        public void Dispose()
        {
            if (_done) return;
            _done = true;
            while (true)
            {
                var cur = _owner._perClient.GetOrAdd(_ip, 0);
                if (_owner._perClient.TryUpdate(_ip, cur - 1, cur)) break;
            }
            if (_owner._perClient.TryGetValue(_ip, out var v) && v <= 0)
                _owner._perClient.TryRemove(_ip, out _);
        }
    }

    private sealed class NullRelease : IDisposable
    {
        public static readonly NullRelease Instance = new();
        public void Dispose() { }
    }

    // ---- Authentication (listener Basic / SOCKS5 userpass) ----

    public bool VerifyCredential(string username, string password)
    {
        if (!InputValidator.IsValidUsername(username)) return false;
        if (_vault is null) return false;
        if (!_vault.TryGet("user:" + username, out var stored)) return false;
        return FixedTimeEquals(stored, password);
    }

    public bool IsAuthLocked(IPAddress client) =>
        _authLockedUntil.TryGetValue(client.ToString(), out var until) && DateTime.UtcNow < until;

    public void RecordAuthFailure(IPAddress client)
    {
        var key = client.ToString();
        var n = _failedAuthByIp.AddOrUpdate(key, 1, (_, v) => v + 1);
        // AC-7: lock after 5 failures for 5 minutes
        if (n >= 5)
        {
            _authLockedUntil[key] = DateTime.UtcNow.AddMinutes(5);
            _failedAuthByIp[key] = 0;
        }
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    // ---- SSRF guard application ----

    public bool IsTargetAllowed(IPAddress target)
    {
        if (!_cfg.Security.DenyPrivateTargets) return true;
        return !SsrfGuard.IsForbidden(target);
    }
}
