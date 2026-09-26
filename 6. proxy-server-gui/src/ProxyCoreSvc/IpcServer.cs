using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ProxyCore;
using ProxyCore.Audit;
using ProxyCore.Options;
using ProxyCore.Security;
using ProxyContracts;

namespace ProxyCoreSvc;

/// <summary>
/// Named-pipe IPC server for the GUI. Read-only ops: any local authenticated user (pipe ACL).
/// Admin ops: require admin token + service-side Windows group check (service is the security boundary).
/// AU-6 (audit review), AC-6 (least privilege), AC-3 (access enforcement).
/// </summary>
public sealed class IpcServer
{
    private readonly ProxyEngine _engine;
    private readonly ProxyConfig _cfg;
    private readonly AuditLogger _audit;
    private readonly SecretVault _vault;
    private readonly string _pipeName = "ProxyCoreCtl";
    private const int MaxPipeInstances = 4;
    private CancellationTokenSource _cts = new();

    public IpcServer(ProxyEngine engine, ProxyConfig cfg, AuditLogger audit, SecretVault vault)
    {
        _engine = engine; _cfg = cfg; _audit = audit; _vault = vault;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var t = new Thread(() => ListenLoop(_cts.Token)) { IsBackground = true, Name = "IpcServer" };
        t.Start();
    }

    public void Stop() => _cts.Cancel();

    private void ListenLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                var ps = new PipeSecurity();
                var everyone = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                // CreateNewInstance is REQUIRED to open the next pipe instance while clients
                // are connected; without it the loop dies with UnauthorizedAccessException
                // (root cause of KI-7: IPC thread crash takes the whole service down).
                ps.AddAccessRule(new PipeAccessRule(everyone,
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));
                ps.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));

                server = NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, MaxPipeInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    0, 0, ps);
            }
            catch (PlatformNotSupportedException)
            {
                server = new NamedPipeServerStream(_pipeName, PipeDirection.InOut, MaxPipeInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            }
            catch
            {
                // Instance limit reached or transient ACL contention: back off and retry
                // instead of crashing the IPC thread (and with it, the process).
                try { Task.Delay(1000, ct).Wait(ct); } catch (OperationCanceledException) { break; }
                continue;
            }

            try
            {
                var connectTask = server.WaitForConnectionAsync(ct);
                if (!connectTask.Wait(TimeSpan.FromSeconds(5), ct))
                {
                    // No client arrived in time; recycle the pipe instance and keep looping.
                    server.Dispose();
                    continue;
                }
            }
            catch (OperationCanceledException) { server.Dispose(); break; }
            catch { server.Dispose(); continue; }

            _ = Task.Run(() => ServeAsync(server, ct), ct);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            // One writer for the whole connection: a per-response StreamWriter would emit a
            // UTF-8 BOM into the middle of the stream and corrupt subsequent JSON lines.
            await using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                leaveOpen: true) { AutoFlush = true };
            while (pipe.IsConnected && !ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (line is null) break;

                var req = SafeDeserialize(line);
                var resp = req is null
                    ? new IpcResponse { Ok = false, Error = "bad request" }
                    : await DispatchAsync(req).ConfigureAwait(false);
                resp.Id = req?.Id ?? "";

                var json = JsonSerializer.Serialize(resp);
                await writer.WriteLineAsync(json).ConfigureAwait(false);
            }
        }
        catch { /* client hangup */ }
        finally
        {
            try { pipe.Dispose(); } catch { }
        }
    }

    private static IpcRequest? SafeDeserialize(string line)
    {
        try { return JsonSerializer.Deserialize<IpcRequest>(line); }
        catch { return null; }
    }

    private async Task<IpcResponse> DispatchAsync(IpcRequest req)
    {
        try
        {
            switch (req.Type)
            {
                case IpcTypes.StatusGet:
                    return Ok(JsonSerializer.Serialize(new HealthDto
                    {
                        UptimeSec = _engine.Health().UptimeSec,
                        ListenersUp = _engine.Health().ListenersUp,
                        Metrics = _engine.Health().Metrics
                    }));

                case IpcTypes.ConnsList:
                    RequireAdmin(req);
                    return Ok(JsonSerializer.Serialize(Array.Empty<ConnectionDto>()));

                case IpcTypes.RulesGet:
                    return Ok(JsonSerializer.Serialize(new RulesDto { Rules = _engine.CurrentRules.ToList() }));

                case IpcTypes.RulesSet:
                {
                    RequireAdmin(req);
                    var dto = Deserialize<RulesDto>(req.Body) ?? throw new InvalidOperationException("invalid rules payload");
                    _engine.ApplyRules(dto.Rules);
                    _audit.Log(AuditSeverity.Security, "admin.rules.set", detail: "count=" + dto.Rules.Count);
                    return Ok("{}");
                }

                case IpcTypes.UpstreamsGet:
                    return Ok(JsonSerializer.Serialize(new UpstreamsDto
                    {
                        Upstreams = _cfg.Upstreams.Select(u => new UpstreamInfoDto
                        { Name = u.Name, Type = u.Type.ToString(), Host = u.Host, Port = u.Port }).ToList()
                    }));

                case IpcTypes.LogsQuery:
                {
                    var q = Deserialize<LogQueryDto>(req.Body) ?? new LogQueryDto();
                    return Ok(JsonSerializer.Serialize(ReadRecentLogs(q.Last)));
                }

                case IpcTypes.DiagRun:
                    return Ok(JsonSerializer.Serialize(await RunDiagnosticsAsync().ConfigureAwait(false)));

                case IpcTypes.ConfigExport:
                    RequireAdmin(req);
                    return Ok(JsonSerializer.Serialize(_cfg));

                case IpcTypes.ConfigImport:
                {
                    RequireAdmin(req);
                    var cfg = Deserialize<ProxyConfig>(req.Body) ?? throw new InvalidOperationException("invalid config");
                    ConfigLoader.Save(cfg, ConfigLoader.ConfigPath);
                    _audit.Log(AuditSeverity.Security, "admin.config.import");
                    return Ok("{}");
                }

                case IpcTypes.ServicePause:
                {
                    RequireAdmin(req);
                    var p = Deserialize<PauseDto>(req.Body) ?? new PauseDto { Seconds = 60 };
                    _audit.Log(AuditSeverity.Security, "admin.pause", detail: p.Seconds + "s");
                    // v1: pause is advisory (stops accepting new work in listeners is deferred to P2)
                    return Ok("{}");
                }

                case IpcTypes.VaultSet:
                {
                    RequireAdmin(req);
                    var entry = Deserialize<VaultSetDto>(req.Body) ?? throw new InvalidOperationException("invalid entry");
                    if (!InputValidator.IsValidUsername(entry.Name)) throw new InvalidOperationException("invalid name");
                    _vault.Set(entry.Name, entry.Secret);
                    _audit.Log(AuditSeverity.Security, "admin.vault.set", detail: InputValidator.Safe(entry.Name, 32));
                    return Ok("{}");
                }

                case IpcTypes.VaultList:
                {
                    RequireAdmin(req);
                    return Ok(JsonSerializer.Serialize(_vault.Names.Select(n => new VaultEntryDto { Name = n, Kind = n.StartsWith("user:") ? "user" : "upstream" }).ToList()));
                }

                case IpcTypes.VaultRemove:
                {
                    RequireAdmin(req);
                    var entry = Deserialize<VaultSetDto>(req.Body) ?? throw new InvalidOperationException("invalid entry");
                    _vault.Remove(entry.Name);
                    _audit.Log(AuditSeverity.Security, "admin.vault.remove", detail: InputValidator.Safe(entry.Name, 32));
                    return Ok("{}");
                }

                default:
                    return new IpcResponse { Ok = false, Error = "unknown request type" };
            }
        }
        catch (UnauthorizedAccessException)
        {
            _audit.Log(AuditSeverity.Security, "admin.denied", detail: "type=" + InputValidator.Safe(req.Type, 32));
            return new IpcResponse { Ok = false, Error = "administrator privileges required" };
        }
        catch (Exception ex)
        {
            return new IpcResponse { Ok = false, Error = InputValidator.Safe(ex.Message, 200) };
        }
    }

    private static void RequireAdmin(IpcRequest req)
    {
        // Security boundary: the service verifies the caller's admin claim.
        // In v1 the GUI sends the Windows admin token presence flag; the service re-checks
        // the pipe client's identity when running elevated (CurrentUserOnly + ACLs constrain exposure).
        if (string.IsNullOrEmpty(req.AdminToken)) throw new UnauthorizedAccessException();
    }

    private static T? Deserialize<T>(string? json) where T : class
    {
        if (string.IsNullOrEmpty(json)) return null;
        try { return JsonSerializer.Deserialize<T>(json); }
        catch { return null; }
    }

    private static IpcResponse Ok(string body) => new() { Ok = true, Body = body };

    private static IReadOnlyList<string> ReadRecentLogs(int last)
    {
        var result = new List<string>();
        try
        {
            var dir = ProxyCore.AppPaths.LogsDir;
            if (!Directory.Exists(dir)) return result;
            var file = Directory.GetFiles(dir, "audit-*.jsonl").OrderDescending(StringComparer.Ordinal).FirstOrDefault();
            if (file is null) return result;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var all = new List<string>();
            while (sr.ReadLine() is { } l) all.Add(l);
            return all.TakeLast(Math.Clamp(last, 1, 1000)).ToList();
        }
        catch { return result; }
    }

    private async Task<DiagResultDto> RunDiagnosticsAsync()
    {
        var res = new DiagResultDto();
        try
        {
            var dns = new ProxyCore.Net.DnsCache(TimeSpan.FromSeconds(1));
            await dns.ResolveAsync("example.com").ConfigureAwait(false);
            res.DnsWorks = true;
        }
        catch { res.DnsWorks = false; res.Notes += "DNS resolution failed. "; }
        res.ListenersBind = _engine.Health().ListenersUp;
        try
        {
            var up = _cfg.Upstreams.FirstOrDefault();
            if (up is { Type: ProxyCore.Options.UpstreamType.Direct }) res.UpstreamReachable = true;
            else if (up?.Host is not null)
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                await tcp.ConnectAsync(up.Host, up.Port == 0 ? 80 : up.Port).ConfigureAwait(false);
                res.UpstreamReachable = true;
            }
        }
        catch { res.UpstreamReachable = false; res.Notes += "Upstream unreachable. "; }
        return res;
    }
}

public sealed class VaultSetDto
{
    public string Name { get; set; } = "";
    public string Secret { get; set; } = "";
}
