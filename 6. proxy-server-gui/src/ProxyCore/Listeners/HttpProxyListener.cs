using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyCore.Audit;
using ProxyCore.Metrics;
using ProxyCore.Net;
using ProxyCore.Options;
using ProxyCore.Rules;
using ProxyCore.Security;

namespace ProxyCore.Listeners;

/// <summary>
/// HTTP/1.1 proxy listener: absolute-URI forwarding + CONNECT tunneling.
/// Header size caps and CRLF validation enforced (OWASP A03/A04, request smuggling hygiene).
/// </summary>
public sealed class HttpProxyListener
{
    private readonly ProxyConfig _cfg;
    private readonly RuleEngine _rules;
    private readonly AccessGuard _guard;
    private readonly UpstreamRouter _router;
    private readonly MetricsRegistry _metrics;
    private readonly AuditLogger _audit;
    private readonly DnsCache _dns;
    private Socket? _listener;

    /// <summary>Concrete address the listener bound (resolved form of the config string).</summary>
    public string BoundAddress { get; private set; } = "";

    public HttpProxyListener(ProxyConfig cfg, RuleEngine rules, AccessGuard guard,
        UpstreamRouter router, MetricsRegistry metrics, AuditLogger audit, DnsCache dns)
    {
        _cfg = cfg; _rules = rules; _guard = guard; _router = router;
        _metrics = metrics; _audit = audit; _dns = dns;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        var opt = _cfg.Listeners.Http;
        var bindAddr = BindResolver.Resolve(opt.Bind);   // supports localhost/auto/*/hostname/IP
        _listener = new Socket(bindAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        // DualMode is ONLY valid on IPv6 (IPv6Any) sockets; setting it on an IPv4 socket throws.
        if (bindAddr.AddressFamily == AddressFamily.InterNetworkV6)
            _listener.DualMode = true;
        _listener.Bind(new IPEndPoint(bindAddr, opt.Port));
        BoundAddress = bindAddr.Equals(IPAddress.IPv6Any) ? "0.0.0.0" : bindAddr.ToString();
        _listener.Listen(_cfg.Limits.MaxConnections);
        if (bindAddr.Equals(IPAddress.IPv6Any))
            _audit.Log(AuditSeverity.Warn, "listener.wildcard_bind", "http", detail: $"0.0.0.0:{opt.Port} (all interfaces - restrict via security.clients.allow)");
        _audit.Log(AuditSeverity.Info, "listener.start", "http", detail: $"{opt.Bind} -> {bindAddr}:{opt.Port}");
        _ = AcceptLoopAsync(ct);
        await Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptAsync(ct).ConfigureAwait(false);
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { /* transient */ }
            catch (ObjectDisposedException) { break; }
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken ct)
    {
        var remote = (client.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        _metrics.ProtoSession("http");
        try
        {
            if (!_guard.IsClientAllowed(remote))
            {
                _audit.Log(AuditSeverity.Security, "client.denied", "http", remote.ToString(),
                    detail: "not in security.clients.allow");
                await WriteSimpleErrorAsync(client, 403, "Forbidden").ConfigureAwait(false);
                client.Dispose();
                return;
            }
            if (!_guard.TryReserveClientSlot(remote, out var release))
            {
                await WriteSimpleErrorAsync(client, 503, "Too many connections").ConfigureAwait(false);
                client.Dispose();
                release.Dispose();
                return;
            }
            using (release)
            using (client)
            {
                if (!_guard.TryAdmitConnect(remote))
                {
                    await WriteSimpleErrorAsync(client, 429, "Rate limited").ConfigureAwait(false);
                    return;
                }
                await ServeAsync(client, remote).ConfigureAwait(false);
            }
        }
        catch (Exception)
        {
            _metrics.Error();
            try { client.Dispose(); } catch { }
        }
    }

    private async Task ServeAsync(Socket client, IPAddress remote)
    {
        using var stream = new NetworkStream(client, ownsSocket: false);
        var head = await ReadHeadAsync(stream).ConfigureAwait(false);
        if (head is null)
        {
            await WriteSimpleErrorAsync(client, 400, "Bad request").ConfigureAwait(false);
            return;
        }

        var requestLine = head.Value.Line;
        var parts = requestLine.Split(' ');
        if (parts.Length != 3)
        {
            await WriteSimpleErrorAsync(client, 400, "Malformed request line").ConfigureAwait(false);
            return;
        }
        var (method, target, version) = (parts[0], parts[1], parts[2]);

        if (!version.StartsWith("HTTP/1.", StringComparison.Ordinal))
        {
            await WriteSimpleErrorAsync(client, 505, "HTTP version not supported").ConfigureAwait(false);
            return;
        }

        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            await HandleConnectAsync(client, stream, target, remote).ConfigureAwait(false);
        }
        else
        {
            await HandlePlainAsync(client, stream, method, target, version, head.Value.Headers, remote).ConfigureAwait(false);
        }
    }

    private async Task HandleConnectAsync(Socket client, NetworkStream stream,
        string authority, IPAddress remote)
    {
        var sep = authority.LastIndexOf(':');
        if (sep <= 0 || !int.TryParse(authority[(sep + 1)..], out var port) || port is < 1 or > 65535)
        {
            await WriteSimpleErrorAsync(client, 400, "Bad CONNECT authority").ConfigureAwait(false);
            return;
        }
        var host = authority[..sep];

        UpstreamPlan plan;
        try
        {
            if (!_guard.TryAdmitHttpRequest(remote)) { await WriteSimpleErrorAsync(client, 429, "Rate limited"); return; }
            plan = await _router.PlanAsync(host, port, "https", null, remote).ConfigureAwait(false);
        }
        catch (ProxyDenyException ex)
        {
            await WriteSimpleErrorAsync(client, 403, $"Forbidden{(ex.RuleId is int r ? $" (rule {r})" : "")}").ConfigureAwait(false);
            return;
        }

        Stream upstream;
        try
        {
            upstream = plan.Upstream.Type == UpstreamType.Http
                ? await _router.ConnectViaHttpParentAsync(plan.Upstream, host, port, tlsTarget: true).ConfigureAwait(false)
                : await _router.ConnectUpstreamAsync(plan).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _audit.Log(AuditSeverity.Warn, "upstream.fail", "https", remote.ToString(), null,
                InputValidator.Safe(host), port, detail: InputValidator.Safe(ex.Message));
            await WriteSimpleErrorAsync(client, 502, "Upstream unreachable").ConfigureAwait(false);
            return;
        }

        await using (upstream)
        {
            await WriteSimpleResponseAsync(client, "HTTP/1.1 200 Connection Established\r\n\r\n").ConfigureAwait(false);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await _router.RelayAsync(stream, upstream, _cfg.Limits.IdleTimeoutSec).ConfigureAwait(false);
            _audit.Log(AuditSeverity.Info, "session.end", "https", remote.ToString(), null,
                InputValidator.Safe(host), port, plan.Decision.Rule?.Id, "allow", durationMs: sw.ElapsedMilliseconds);
        }
    }

    private async Task HandlePlainAsync(Socket client, NetworkStream stream,
        string method, string target, string version, string headers, IPAddress remote)
    {
        // Parse absolute-URI or origin-form
        Uri? uri;
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            uri = Uri.TryCreate(target, UriKind.Absolute, out var u) ? u : null;
        }
        else if (target.StartsWith('/'))
        {
            await WriteSimpleErrorAsync(client, 400, "Origin-form not supported on proxy; use absolute URI").ConfigureAwait(false);
            return;
        }
        else uri = null;

        if (uri is null || (uri.Scheme != "http") || uri.HostNameType == UriHostNameType.Unknown)
        {
            await WriteSimpleErrorAsync(client, 400, "Unsupported target").ConfigureAwait(false);
            return;
        }
        var host = uri.Host;
        var port = uri.IsDefaultPort ? 80 : uri.Port;

        if (!InputValidator.IsValidHost(host))
        {
            await WriteSimpleErrorAsync(client, 400, "Invalid host").ConfigureAwait(false);
            return;
        }
        if (!_guard.TryAdmitHttpRequest(remote))
        {
            await WriteSimpleErrorAsync(client, 429, "Rate limited").ConfigureAwait(false);
            return;
        }

        UpstreamPlan plan;
        try { plan = await _router.PlanAsync(host, port, "http", null, remote).ConfigureAwait(false); }
        catch (ProxyDenyException ex)
        {
            await WriteSimpleErrorAsync(client, 403, $"Forbidden{(ex.RuleId is int r ? $" (rule {r})" : "")}").ConfigureAwait(false);
            return;
        }

        Stream upstream;
        try
        {
            upstream = plan.Upstream.Type == UpstreamType.Http
                ? await _router.ConnectViaHttpParentAsync(plan.Upstream, host, port, tlsTarget: false).ConfigureAwait(false)
                : await _router.ConnectUpstreamAsync(plan).ConfigureAwait(false);
        }
        catch
        {
            await WriteSimpleErrorAsync(client, 502, "Upstream unreachable").ConfigureAwait(false);
            return;
        }

        try
        {
            // Rebuild request with absolute URI, strip hop-by-hop + proxy headers (SP-800-53 SC-5, hygiene)
            var rewritten = RewriteRequestHead(method, uri, version, headers);
            await upstream.WriteAsync(Encoding.Latin1.GetBytes(rewritten)).ConfigureAwait(false);
            await _router.RelayAsync(stream, upstream, _cfg.Limits.IdleTimeoutSec).ConfigureAwait(false);
        }
        finally
        {
            await upstream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static string RewriteRequestHead(string method, Uri uri, string version, string headers)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
        var hopByHop = new[] { "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailers", "upgrade", "host" };
        foreach (var raw in headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var idx = raw.IndexOf(':');
            if (idx <= 0) continue;
            var name = raw[..idx].Trim();
            var value = raw[(idx + 1)..].Trim();
            if (hopByHop.Contains(name.ToLowerInvariant())) continue;
            // Header injection guard: reject CR/LF inside values (already excluded by head reader, belt+braces)
            if (value.Contains('\r') || value.Contains('\n')) continue;
            sb.Append(InputValidator.Safe(name, 128)).Append(": ").Append(InputValidator.Safe(value, 4096)).Append("\r\n");
        }
        sb.Append("Host: ").Append(uri.Authority).Append("\r\n");
        sb.Append("Connection: close\r\n\r\n");
        return sb.ToString();
    }

    private async Task<(string Line, string Headers)?> ReadHeadAsync(NetworkStream s)
    {
        var buf = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            var ms = new MemoryStream();
            var total = 0;
            while (total < _cfg.Limits.MaxHeaderBytes)
            {
                var n = await s.ReadAsync(buf.AsMemory(0, Math.Min(buf.Length, _cfg.Limits.MaxHeaderBytes - total))).ConfigureAwait(false);
                if (n <= 0) return null;
                ms.Write(buf, 0, n);
                total += n;
                var data = ms.GetBuffer();
                var len = (int)ms.Length;
                for (var i = 0; i < len - 3; i++)
                {
                    if (data[i] == 13 && data[i + 1] == 10 && data[i + 2] == 13 && data[i + 3] == 10)
                    {
                        var head = Encoding.Latin1.GetString(data, 0, i);
                        var lineEnd = head.IndexOf("\r\n", StringComparison.Ordinal);
                        var line = lineEnd < 0 ? head : head[..lineEnd];
                        var rest = lineEnd < 0 ? "" : head[(lineEnd + 2)..];
                        return (line, rest);
                    }
                }
            }
            return null; // header cap exceeded (A04)
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    private static async Task WriteSimpleErrorAsync(Socket client, int code, string msg)
    {
        var body = $"<html><body><h1>{code} {msg}</h1></body></html>";
        var resp = $"HTTP/1.1 {code} {msg}\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
        try { await client.SendAsync(Encoding.UTF8.GetBytes(resp), SocketFlags.None); } catch { }
        try { client.Shutdown(SocketShutdown.Both); } catch { }
    }

    private static async Task WriteSimpleResponseAsync(Socket client, string resp)
    {
        try { await client.SendAsync(Encoding.UTF8.GetBytes(resp), SocketFlags.None); } catch { }
    }
}
