using System.Buffers;
using System.Net;
using System.Text;
using System.Net.Security;
using System.Net.Sockets;
using ProxyCore.Audit;
using ProxyCore.Metrics;
using ProxyCore.Options;
using ProxyCore.Rules;
using ProxyCore.Security;

namespace ProxyCore.Net;

/// <summary>Result of resolving and evaluating a client target before connecting upstream.</summary>
public sealed record UpstreamPlan(
    UpstreamOptions Upstream,
    string ConnectHost,   // hostname or IP to hand to upstream / connect to
    int ConnectPort,
    IPAddress? ResolvedIp,
    RuleDecision Decision);

/// <summary>
/// Chooses the upstream (rule-driven route, failover list, direct) and opens upstream connections,
/// applying SSRF guard + DNS cache. Also owns the zero-copy duplex relay.
/// </summary>
public sealed class UpstreamRouter
{
    private readonly ProxyConfig _cfg;
    private readonly RuleEngine _rules;
    private readonly AccessGuard _guard;
    private readonly DnsCache _dns;
    private readonly MetricsRegistry _metrics;
    private readonly AuditLogger _audit;

    public UpstreamRouter(ProxyConfig cfg, RuleEngine rules, AccessGuard guard,
        DnsCache dns, MetricsRegistry metrics, AuditLogger audit)
    {
        _cfg = cfg; _rules = rules; _guard = guard; _dns = dns; _metrics = metrics; _audit = audit;
    }

    public async Task<UpstreamPlan> PlanAsync(string host, int port, string proto,
        string? user, IPAddress clientIp)
    {
        var ctx = new RuleContext(host, port, proto, user, null, clientIp);
        var decision = _rules.Evaluate(ctx);

        if (decision.Action == RuleAction.Deny)
        {
            _metrics.Denied();
            _audit.Log(AuditSeverity.Security, "rule.deny", proto, clientIp?.ToString(), user,
                InputValidator.Safe(host), port, decision.Rule?.Id, "deny");
            throw new ProxyDenyException(decision.Rule?.Id);
        }

        // SSRF guard (A10): resolve + check when enabled
        IPAddress? resolved = null;
        if (_cfg.Security.DenyPrivateTargets && !IsIpLiteral(host))
        {
            var addrs = await _dns.ResolveAsync(host).ConfigureAwait(false);
            resolved = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                       ?? addrs.FirstOrDefault();
            if (resolved is not null && !_guard.IsTargetAllowed(resolved))
            {
                _metrics.Denied();
                _audit.Log(AuditSeverity.Security, "ssrf.block", proto, clientIp?.ToString(), user,
                    InputValidator.Safe(host), port, null, "deny", detail: "private target blocked");
                throw new ProxyDenyException(null, "Target address forbidden");
            }
        }
        else if (_cfg.Security.DenyPrivateTargets && IsIpLiteral(host))
        {
            if (!IPAddress.TryParse(host, out var lit) || !_guard.IsTargetAllowed(lit))
                throw new ProxyDenyException(null, "Target address forbidden");
            resolved = lit;
        }

        // Route selection: explicit rule route wins, else default/failover chain
        UpstreamOptions upstream;
        if (decision.Action == RuleAction.Route && decision.RouteTo is not null)
        {
            upstream = _cfg.Upstreams.FirstOrDefault(u => u.Name == decision.RouteTo)
                       ?? new UpstreamOptions { Name = "direct", Type = UpstreamType.Direct };
        }
        else
        {
            upstream = _cfg.Upstreams.FirstOrDefault(u => u.Name == _cfg.Routing.Default)
                       ?? new UpstreamOptions { Name = "direct", Type = UpstreamType.Direct };
        }

        return new UpstreamPlan(upstream, host, port, resolved, decision);
    }

    private static bool IsIpLiteral(string host) => IPAddress.TryParse(host, out _);

    public async Task<Stream> ConnectUpstreamAsync(UpstreamPlan plan)
    {
        var up = plan.Upstream;
        if (up.Type == UpstreamType.Direct)
        {
            return await ConnectDirectAsync(plan.ConnectHost, plan.ConnectPort, plan.ResolvedIp).ConfigureAwait(false);
        }
        if (up.Type == UpstreamType.Http)
        {
            var server = await ConnectDirectAsync(up.Host!, up.Port, null).ConfigureAwait(false);
            return server; // HTTP parent framing handled by HttpUpstream helper below
        }
        // SOCKS5 parent: handshake performed by ConnectViaSocks5ParentAsync in listener flows
        var s = await ConnectDirectAsync(up.Host!, up.Port, null).ConfigureAwait(false);
        return s;
    }

    public async Task<Stream> ConnectDirectAsync(string host, int port, IPAddress? resolvedIp)
    {
        var sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)
        { NoDelay = true };
        sock.DualMode = true;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_cfg.Limits.ConnectTimeoutSec));
        try
        {
            if (resolvedIp is not null)
            {
                await sock.ConnectAsync(new IPEndPoint(resolvedIp, port), cts.Token).ConfigureAwait(false);
            }
            else
            {
                await sock.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            }
        }
        catch
        {
            sock.Dispose();
            throw;
        }
        return new NetworkStream(sock, ownsSocket: true);
    }

    /// <summary>Connect through an HTTP parent proxy (absolute-URI or CONNECT handled by caller streams).</summary>
    public async Task<Stream> ConnectViaHttpParentAsync(UpstreamOptions parent, string host, int port, bool tlsTarget)
    {
        var server = await ConnectDirectAsync(parent.Host!, parent.Port, null).ConfigureAwait(false);
        if (tlsTarget)
        {
            // Issue CONNECT then hand the raw stream back for TLS-in-TLS passthrough
            var req = System.Text.Encoding.ASCII.GetBytes($"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
            await server.WriteAsync(req).ConfigureAwait(false);
            var resp = await ReadHttpResponseHeadAsync(server).ConfigureAwait(false);
            if (!resp.StartsWith("HTTP/1.1 2", StringComparison.Ordinal) &&
                !resp.StartsWith("HTTP/1.0 2", StringComparison.Ordinal))
            {
                await server.DisposeAsync();
                throw new IOException("Upstream CONNECT refused: " + InputValidator.Safe(resp.Split('\n').FirstOrDefault(), 80));
            }
            return server;
        }
        return server;
    }

    public async Task<Stream> ConnectViaSocks5ParentAsync(UpstreamOptions parent, string host, int port)
    {
        var s = await ConnectDirectAsync(parent.Host!, parent.Port, null).ConfigureAwait(false);
        var sock = ExtractSocket(s);
        if (sock is null) throw new InvalidOperationException("SOCKS5 parent requires socket stream");
        var buf = new byte[512];

        sock.Send(new byte[] { 0x05, 0x01, 0x00 });
        int n = sock.Receive(buf);
        if (n < 2 || buf[0] != 0x05 || buf[1] != 0x00) throw new IOException("SOCKS5 parent rejected no-auth");

        var target = Encoding.ASCII.GetBytes(host);
        var req = new byte[7 + target.Length];
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00;
        req[3] = 0x03; req[4] = (byte)target.Length;
        target.CopyTo(req, 5);
        req[^2] = (byte)(port >> 8); req[^1] = (byte)(port & 0xFF);
        sock.Send(req);
        n = sock.Receive(buf);
        if (n < 4 || buf[1] != 0x00) throw new IOException("SOCKS5 parent connect failed");

        return s;
    }

    private static Socket? ExtractSocket(Stream s) =>
        s is NetworkStream ns ? ns.Socket : null;

    /// <summary>Duplex relay with ArrayPool buffers and back-pressure.</summary>
    public async Task RelayAsync(Stream a, Stream b, long idleTimeoutSec)
    {
        var bufA = ArrayPool<byte>.Shared.Rent(64 * 1024);
        var bufB = ArrayPool<byte>.Shared.Rent(64 * 1024);
        long up = 0, down = 0;
        try
        {
            using var idleCts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(5, idleTimeoutSec)));
            var t1 = Pump(a, b, bufA, dirClientToUp: true, idleCts.Token, x => Interlocked.Add(ref up, x));
            var t2 = Pump(b, a, bufB, dirClientToUp: false, idleCts.Token, x => Interlocked.Add(ref down, x));
            await Task.WhenAll(t1, t2).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bufA);
            ArrayPool<byte>.Shared.Return(bufB);
            _metrics.Bytes(Interlocked.Read(ref up), Interlocked.Read(ref down));
        }
    }

    private static async Task Pump(Stream from, Stream to, byte[] buf, bool dirClientToUp,
        CancellationToken ct, Action<long> addBytes)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await from.ReadAsync(buf, ct).ConfigureAwait(false);
                if (n <= 0) return;
                await to.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                await to.FlushAsync(ct).ConfigureAwait(false);
                addBytes(n);
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
    }

    // Small helpers used by parent-proxy paths

    private static async Task<string> ReadHttpResponseHeadAsync(Stream s)
    {
        var head = new MemoryStream();
        var buf = new byte[1];
        var total = 0;
        while (total < 16 * 1024)
        {
            int n = await s.ReadAsync(buf).ConfigureAwait(false);
            if (n <= 0) break;
            head.WriteByte(buf[0]);
            total++;
            var all = head.ToArray();
            if (all.Length >= 4 && all[^4..].SequenceEqual("\r\n\r\n"u8.ToArray())) break;
            if (all.Length >= 2 && all[^2..].SequenceEqual("\n\n"u8.ToArray())) break;
        }
        return Encoding.Latin1.GetString(head.ToArray());
    }
}


