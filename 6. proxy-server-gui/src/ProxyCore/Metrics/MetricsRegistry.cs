using System.Collections.Concurrent;

namespace ProxyCore.Metrics;

/// <summary>Aggregated counters surfaced to the GUI dashboard and diagnostics.</summary>
public sealed class MetricsRegistry
{
    private long _sessionsTotal;
    private long _sessionsActive;
    private long _deniedTotal;
    private long _bytesUp;
    private long _bytesDown;
    private long _errorsTotal;
    private readonly ConcurrentDictionary<string, long> _byProto = new();

    public void SessionStarted() { Interlocked.Increment(ref _sessionsTotal); Interlocked.Increment(ref _sessionsActive); }
    public void SessionEnded() => Interlocked.Decrement(ref _sessionsActive);
    public void Denied() => Interlocked.Increment(ref _deniedTotal);
    public void Error() => Interlocked.Increment(ref _errorsTotal);
    public void Bytes(long up, long down)
    {
        if (up > 0) Interlocked.Add(ref _bytesUp, up);
        if (down > 0) Interlocked.Add(ref _bytesDown, down);
    }
    public void ProtoSession(string proto) => _byProto.AddOrUpdate(proto, 1, (_, v) => v + 1);

    public MetricsSnapshot Snapshot() => new()
    {
        SessionsTotal = Interlocked.Read(ref _sessionsTotal),
        SessionsActive = Interlocked.Read(ref _sessionsActive),
        DeniedTotal = Interlocked.Read(ref _deniedTotal),
        ErrorsTotal = Interlocked.Read(ref _errorsTotal),
        BytesUp = Interlocked.Read(ref _bytesUp),
        BytesDown = Interlocked.Read(ref _bytesDown),
        ByProto = new Dictionary<string, long>(_byProto)
    };
}

public sealed class MetricsSnapshot
{
    public long SessionsTotal { get; init; }
    public long SessionsActive { get; init; }
    public long DeniedTotal { get; init; }
    public long ErrorsTotal { get; init; }
    public long BytesUp { get; init; }
    public long BytesDown { get; init; }
    public Dictionary<string, long> ByProto { get; init; } = new();
}
