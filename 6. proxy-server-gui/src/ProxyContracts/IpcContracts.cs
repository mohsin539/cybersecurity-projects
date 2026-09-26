using ProxyCore.Audit;
using ProxyCore.Metrics;
using ProxyCore.Rules;

namespace ProxyContracts;

/// <summary>All IPC request types (JSON over named pipe).</summary>
public sealed class IpcRequest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Type { get; set; } = "";
    public string? Body { get; set; }        // JSON payload per request type
    public string? AdminToken { get; set; }  // required for admin ops
}

public sealed class IpcResponse
{
    public string Id { get; set; } = "";
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string? Body { get; set; }
}

// ---- Payload DTOs ----

public sealed class HealthDto
{
    public long UptimeSec { get; set; }
    public bool ListenersUp { get; set; }
    public MetricsSnapshot Metrics { get; set; } = new();
    public string Version { get; set; } = "1.0.0";
}

public sealed class ConnectionDto
{
    public string Id { get; set; } = "";
    public string Proto { get; set; } = "";
    public string Client { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string State { get; set; } = "";
    public long BytesUp { get; set; }
    public long BytesDown { get; set; }
    public int? Rule { get; set; }
}

public sealed class LogQueryDto
{
    public int Last { get; set; } = 100;
}

public sealed class RulesDto
{
    public List<RuleDefinition> Rules { get; set; } = new();
}

public sealed class UpstreamsDto
{
    public List<UpstreamInfoDto> Upstreams { get; set; } = new();
}

public sealed class UpstreamInfoDto
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string? Host { get; set; }
    public int Port { get; set; }
    public bool Healthy { get; set; } = true;
}

public sealed class DiagResultDto
{
    public bool ListenersBind { get; set; }
    public bool DnsWorks { get; set; }
    public bool UpstreamReachable { get; set; }
    public string Notes { get; set; } = "";
}

public sealed class PauseDto
{
    public int Seconds { get; set; }
}

public static class IpcTypes
{
    public const string StatusGet = "status.get";
    public const string ConnsList = "conns.list";
    public const string ConnsKill = "conns.kill";
    public const string RulesGet = "rules.get";
    public const string RulesSet = "rules.set";
    public const string UpstreamsGet = "upstreams.get";
    public const string LogsQuery = "logs.query";
    public const string LogsTail = "logs.tail";
    public const string DiagRun = "diag.run";
    public const string ConfigExport = "config.export";
    public const string ConfigImport = "config.import";
    public const string ServicePause = "service.pause";
    public const string ServiceResume = "service.resume";
    public const string VaultSet = "vault.set";
    public const string VaultList = "vault.list";
    public const string VaultRemove = "vault.remove";
}

public sealed class VaultEntryDto
{
    public string Name { get; set; } = "";
    public string Kind { get; set; } = ""; // user | upstream
}
