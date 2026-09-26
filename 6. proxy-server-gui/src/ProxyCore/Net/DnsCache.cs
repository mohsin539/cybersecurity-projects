using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ProxyCore.Net;

/// <summary>Async DNS resolver with TTL cache (perf: avoids per-connection lookup stalls).</summary>
public sealed class DnsCache
{
    private sealed class Entry
    {
        public IPAddress[] Addresses { get; init; } = Array.Empty<IPAddress>();
        public DateTime Expires { get; init; }
    }

    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _ttl;

    public DnsCache(TimeSpan? ttl = null) => _ttl = ttl ?? TimeSpan.FromSeconds(30);

    public async Task<IPAddress[]> ResolveAsync(string host)
    {
        if (_cache.TryGetValue(host, out var hit) && hit.Expires > DateTime.UtcNow)
            return hit.Addresses;

        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            if (addrs.Length > 0)
            {
                _cache[host] = new Entry { Addresses = addrs, Expires = DateTime.UtcNow + _ttl };
                return addrs;
            }
        }
        catch
        {
            // resolution failure: fall through to throw
        }
        throw new SocketException((int)SocketError.HostNotFound);
    }

    public int Count => _cache.Count;
}
