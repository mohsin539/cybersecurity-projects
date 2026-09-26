using System.Collections.Concurrent;
using System.Net;

namespace ProxyCore.Security;

/// <summary>
/// Sliding-window rate limiter with temporary block, keyed per client IP.
/// OWASP A04:2021 (resource exhaustion), NIST SP 800-53 AC-4, SC-5 (DoS protection).
/// </summary>
public sealed class RateLimiter
{
    private sealed class Bucket
    {
        public Queue<long> Timestamps { get; } = new();
        public DateTime BlockedUntil { get; set; } = DateTime.MinValue;
    }

    private readonly ConcurrentDictionary<IPAddress, Bucket> _buckets = new();
    private readonly int _limitPerMinute;
    private readonly TimeSpan _blockDuration;
    private long _lastSweepTicks;

    public RateLimiter(int limitPerMinute, int blockSeconds)
    {
        _limitPerMinute = Math.Max(1, limitPerMinute);
        _blockDuration = TimeSpan.FromSeconds(Math.Max(1, blockSeconds));
    }

    /// <summary>Returns true if the request is allowed; false if rate-limited or blocked.</summary>
    public bool Allow(IPAddress client)
    {
        var nowTicks = Environment.TickCount64;
        var bucket = _buckets.GetOrAdd(client, _ => new Bucket());
        lock (bucket)
        {
            var nowMs = nowTicks;
            if (bucket.BlockedUntil.Ticks > 0 && DateTime.UtcNow < bucket.BlockedUntil) return false;

            // Evict entries older than 60s
            while (bucket.Timestamps.Count > 0 && nowMs - bucket.Timestamps.Peek() > 60_000)
            {
                bucket.Timestamps.Dequeue();
            }
            if (bucket.Timestamps.Count >= _limitPerMinute)
            {
                bucket.BlockedUntil = DateTime.UtcNow + _blockDuration;
                return false;
            }
            bucket.Timestamps.Enqueue(nowMs);
            if (Environment.TickCount64 - _lastSweepTicks > 300_000)
            {
                _lastSweepTicks = Environment.TickCount64;
                Sweep(nowTicks);
            }
            return true;
        }
    }

    private void Sweep(long nowMs)
    {
        foreach (var kv in _buckets)
        {
            var dead = false;
            lock (kv.Value)
            {
                if (kv.Value.Timestamps.Count == 0 &&
                    (kv.Value.BlockedUntil == DateTime.MinValue || DateTime.UtcNow > kv.Value.BlockedUntil))
                {
                    dead = true;
                }
            }
            if (dead) _buckets.TryRemove(kv.Key, out _);
        }
    }
}
