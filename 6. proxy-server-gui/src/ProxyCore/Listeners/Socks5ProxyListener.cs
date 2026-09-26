using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyCore.Audit;
using ProxyCore.Metrics;
using ProxyCore.Net;
using ProxyCore.Options;
using ProxyCore.Security;

namespace ProxyCore.Listeners;

/// <summary>
/// SOCKS5 (RFC 1928) listener: no-auth and username/password subnegotiation (RFC 1929),
/// CONNECT command. UDP ASSOCIATE and BIND return not-supported in v1.
/// </summary>
public sealed class Socks5ProxyListener
{
    private readonly ProxyConfig _cfg;
    private readonly AccessGuard _guard;
    private readonly UpstreamRouter _router;
    private readonly MetricsRegistry _metrics;
    private readonly AuditLogger _audit;
    private Socket? _listener;

    /// <summary>Concrete address the listener bound (resolved form of the config string).</summary>
    public string BoundAddress { get; private set; } = "";

    public Socks5ProxyListener(ProxyConfig cfg, AccessGuard guard, UpstreamRouter router,
        MetricsRegistry metrics, AuditLogger audit)
    {
        _cfg = cfg; _guard = guard; _router = router; _metrics = metrics; _audit = audit;
    }

    public Task StartAsync(CancellationToken ct)
    {
        var opt = _cfg.Listeners.Socks5;
        var bindAddr = BindResolver.Resolve(opt.Bind);   // supports localhost/auto/*/hostname/IP
        _listener = new Socket(bindAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        // DualMode is ONLY valid on IPv6 (IPv6Any) sockets; setting it on an IPv4 socket throws.
        if (bindAddr.AddressFamily == AddressFamily.InterNetworkV6)
            _listener.DualMode = true;
        _listener.Bind(new IPEndPoint(bindAddr, opt.Port));
        BoundAddress = bindAddr.Equals(IPAddress.IPv6Any) ? "0.0.0.0" : bindAddr.ToString();
        _listener.Listen(_cfg.Limits.MaxConnections);
        if (bindAddr.Equals(IPAddress.IPv6Any))
            _audit.Log(AuditSeverity.Warn, "listener.wildcard_bind", "socks5", detail: $"0.0.0.0:{opt.Port} (all interfaces - restrict via security.clients.allow)");
        _audit.Log(AuditSeverity.Info, "listener.start", "socks5", detail: $"{opt.Bind} -> {bindAddr}:{opt.Port}");
        _ = AcceptLoopAsync(ct);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptAsync(ct).ConfigureAwait(false);
                _ = HandleClientAsync(client);
            }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { }
            catch (ObjectDisposedException) { break; }
        }
    }

    private async Task HandleClientAsync(Socket client)
    {
        var remote = (client.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        _metrics.ProtoSession("socks5");
        try
        {
            if (!_guard.IsClientAllowed(remote))
            { 
                _audit.Log(AuditSeverity.Security, "client.denied", "socks5", remote.ToString(),
                    detail: "not in security.clients.allow");
                Reply(client, 0x02); // connection not allowed by ruleset
                client.Dispose();
                return;
            }
            if (!_guard.TryReserveClientSlot(remote, out var release))
            {
                Reply(client, 0x01); // general failure
                client.Dispose(); release.Dispose();
                return;
            }
            using (release)
            using (client)
            {
                await NegotiateAndRelayAsync(client, remote).ConfigureAwait(false);
            }
        }
        catch
        {
            _metrics.Error();
            try { client.Dispose(); } catch { }
        }
    }

    private async Task NegotiateAndRelayAsync(Socket client, IPAddress remote)
    {
        var buf = new byte[256];

        // 1) Method selection
        if (!await ReadExactAsync(client, buf, 2).ConfigureAwait(false) || buf[0] != 0x05)
        {
            client.Dispose(); return;
        }
        var nMethods = buf[1];
        if (nMethods == 0 || nMethods > 32 || !await ReadExactAsync(client, buf, nMethods).ConfigureAwait(false))
        {
            client.Dispose(); return;
        }
        var methods = buf[..nMethods];
        var needAuth = _cfg.Listeners.Socks5.AuthMode == AuthMode.Basic;
        var chosen = needAuth
            ? (methods.Contains((byte)0x02) ? 0x02 : -1)
            : (methods.Contains((byte)0x00) ? 0x00 : -1);
        if (chosen < 0)
        {
            client.Send(new byte[] { 0x05, 0xFF });
            client.Dispose(); return;
        }
        client.Send(new byte[] { 0x05, (byte)chosen });

        // 2) Username/password subnegotiation
        string? user = null;
        if (chosen == 0x02)
        {
            if (_guard.IsAuthLocked(remote))
            {
                client.Send(new byte[] { 0x01, 0x01 });
                client.Dispose(); return;
            }
            if (!await ReadExactAsync(client, buf, 2).ConfigureAwait(false) || buf[0] != 0x01)
            {
                client.Dispose(); return;
            }
            var ulen = buf[1];
            if (ulen == 0 || ulen > 64 || !await ReadExactAsync(client, buf, ulen).ConfigureAwait(false))
            {
                client.Dispose(); return;
            }
            var username = Encoding.UTF8.GetString(buf, 0, ulen);
            if (!await ReadExactAsync(client, buf, 1).ConfigureAwait(false))
            {
                client.Dispose(); return;
            }
            var plen = buf[0];
            if (plen is 0 or > 64 || !await ReadExactAsync(client, buf, plen).ConfigureAwait(false))
            {
                client.Dispose(); return;
            }
            var password = Encoding.UTF8.GetString(buf, 0, plen);

            if (!_guard.VerifyCredential(username, password))
            {
                _audit.Log(AuditSeverity.Security, "auth.fail", "socks5", remote.ToString(), InputValidator.Safe(username, 32));
                _guard.RecordAuthFailure(remote);
                client.Send(new byte[] { 0x01, 0x01 });
                client.Dispose(); return;
            }
            _audit.Log(AuditSeverity.Info, "auth.ok", "socks5", remote.ToString(), InputValidator.Safe(username, 32));
            user = username;
            client.Send(new byte[] { 0x01, 0x00 });
        }

        // 3) Request
        if (!await ReadExactAsync(client, buf, 4).ConfigureAwait(false)) { client.Dispose(); return; }
        var cmd = buf[1];
        if (cmd != 0x01) // CONNECT only in v1
        {
            Reply(client, 0x07); // command not supported
            client.Dispose(); return;
        }
        string host;
        var atyp = buf[3];
        switch (atyp)
        {
            case 0x01:
                if (!await ReadExactAsync(client, buf, 4).ConfigureAwait(false)) { client.Dispose(); return; }
                host = new IPAddress(buf[..4]).ToString();
                break;
            case 0x03:
                if (!await ReadExactAsync(client, buf, 1).ConfigureAwait(false)) { client.Dispose(); return; }
                var dl = buf[0];
                if (dl is 0 or > 253 || !await ReadExactAsync(client, buf, dl).ConfigureAwait(false)) { client.Dispose(); return; }
                host = Encoding.UTF8.GetString(buf, 0, dl);
                break;
            case 0x04:
                if (!await ReadExactAsync(client, buf, 16).ConfigureAwait(false)) { client.Dispose(); return; }
                host = new IPAddress(buf[..16]).ToString();
                break;
            default:
                Reply(client, 0x08); // address type not supported
                client.Dispose(); return;
        }
        if (!await ReadExactAsync(client, buf, 2).ConfigureAwait(false)) { client.Dispose(); return; }
        var port = (buf[0] << 8) | buf[1];

        if (!InputValidator.IsValidHost(host))
        {
            Reply(client, 0x08);
            client.Dispose(); return;
        }

        // 4) Policy + connect
        UpstreamPlan plan;
        try
        {
            if (!_guard.TryAdmitConnect(remote)) { Reply(client, 0x02); return; }
            plan = await _router.PlanAsync(host, port, "socks", user, remote).ConfigureAwait(false);
        }
        catch (ProxyDenyException)
        {
            Reply(client, 0x02); // connection not allowed by ruleset
            return;
        }

        Stream upstream;
        try
        {
            upstream = plan.Upstream.Type switch
            {
                UpstreamType.Http => throw new IOException("HTTP parent unsupported for SOCKS5 CONNECT in v1"),
                UpstreamType.Socks5 => await _router.ConnectViaSocks5ParentAsync(plan.Upstream, host, port).ConfigureAwait(false),
                _ => await _router.ConnectUpstreamAsync(plan).ConfigureAwait(false)
            };
        }
        catch
        {
            Reply(client, 0x05); // connection refused
            _audit.Log(AuditSeverity.Warn, "upstream.fail", "socks5", remote.ToString(), user,
                InputValidator.Safe(host), port);
            return;
        }

        // 5) Success reply (BND.ADDR 0.0.0.0:0)
        client.Send(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

        await using (upstream)
        {
            var clientStream = new NetworkStream(client, ownsSocket: false);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await _router.RelayAsync(clientStream, upstream, _cfg.Limits.IdleTimeoutSec).ConfigureAwait(false);
            _audit.Log(AuditSeverity.Info, "session.end", "socks5", remote.ToString(), user,
                InputValidator.Safe(host), port, plan.Decision.Rule?.Id, "allow", durationMs: sw.ElapsedMilliseconds);
        }
    }

    private static void Reply(Socket client, byte code)
    {
        try { client.Send(new byte[] { 0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }); } catch { }
    }

    private static async Task<bool> ReadExactAsync(Socket s, byte[] buf, int count)
    {
        var off = 0;
        while (off < count)
        {
            var n = await s.ReceiveAsync(buf.AsMemory(off, count - off), SocketFlags.None).ConfigureAwait(false);
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }
}
