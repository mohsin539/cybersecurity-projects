using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyCore.Options;

namespace ProxyCore.Audit;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AuditSeverity
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Security = 4
}

/// <summary>One audit event. JSON-serialized one-per-line (JSONL) with a hash chain.</summary>
public sealed class AuditEvent
{
    [JsonPropertyName("ts")] public DateTime Ts { get; set; } = DateTime.UtcNow;
    [JsonPropertyName("sev")] public AuditSeverity Sev { get; set; } = AuditSeverity.Info;
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("proto")] public string? Proto { get; set; }
    [JsonPropertyName("client")] public string? Client { get; set; }
    [JsonPropertyName("user")] public string? User { get; set; }
    [JsonPropertyName("host")] public string? Host { get; set; }
    [JsonPropertyName("port")] public int? Port { get; set; }
    [JsonPropertyName("rule")] public int? Rule { get; set; }
    [JsonPropertyName("action")] public string? Action { get; set; }
    [JsonPropertyName("bytesUp")] public long? BytesUp { get; set; }
    [JsonPropertyName("bytesDown")] public long? BytesDown { get; set; }
    [JsonPropertyName("durationMs")] public long? DurationMs { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
    [JsonPropertyName("prev")] public string? PrevHash { get; set; }
    [JsonPropertyName("hash")] public string? Hash { get; set; }
}

/// <summary>
/// Tamper-evident audit log: each event embeds the hash of the previous event
/// (chain = SHA256(prevHash + canonical json)). Detects deletion/alteration of historical lines.
/// AU-2, AU-6, AU-9 (protection of audit information), AU-10 (non-repudiation), AU-11 (retention).
/// Sinks: rotating local file (JSONL, zstd-free for portability). SIEM forwarder hooks in service layer.
/// </summary>
public sealed class AuditLogger : IDisposable
{
    private readonly object _lock = new();
    private readonly string _dir;
    private readonly long _maxFileBytes;
    private readonly int _maxFiles;
    private readonly AuditSeverity _minSeverity;
    private string? _prevHash;
    private FileStream? _fs;
    private StreamWriter? _writer;
    private DateTime _currentFileDate;
    private long _currentFileSeq;

    public AuditLogger(LoggingOptions opts)
    {
        _dir = Path.GetFullPath(opts.Directory);
        Directory.CreateDirectory(_dir);
        _maxFileBytes = opts.MaxFileBytes;
        _maxFiles = Math.Max(1, opts.MaxFiles);
        _minSeverity = opts.Level?.ToLowerInvariant() switch
        {
            "debug" => AuditSeverity.Debug,
            "warn" => AuditSeverity.Warn,
            "error" => AuditSeverity.Error,
            _ => AuditSeverity.Info
        };
        RestoreChainTail();
    }

    /// <summary>Rebuild the chain hash from the newest existing file so rotation doesn't break the chain.</summary>
    private void RestoreChainTail()
    {
        try
        {
            var newest = Directory.GetFiles(_dir, "audit-*.jsonl")
                .OrderDescending(StringComparer.Ordinal).FirstOrDefault();
            if (newest is null) return;
            foreach (var line in File.ReadLines(newest))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var ev = JsonSerializer.Deserialize<AuditEvent>(line);
                    if (ev?.Hash is not null) _prevHash = ev.Hash;
                }
                catch { /* skip malformed */ }
            }
        }
        catch { /* fresh start */ }
    }

    public void Write(AuditEvent ev)
    {
        if (ev.Sev < _minSeverity) return;
        lock (_lock)
        {
            ev.PrevHash = _prevHash ?? Genesis;
            ev.Hash = ComputeHash(ev);
            _prevHash = ev.Hash;
            RollIfNeeded();
            if (_writer is null) OpenNewFile(DateTime.UtcNow);
            _writer!.WriteLine(JsonSerializer.Serialize(ev));
            _writer.Flush();
        }
    }

    private const string Genesis = "GENESIS";

    private static string ComputeHash(AuditEvent ev)
    {
        var canonical = $"{ev.PrevHash}|{ev.Ts:O}|{ev.Sev}|{ev.Type}|{ev.Proto}|{ev.Client}|{ev.User}|{ev.Host}|{ev.Port}|{ev.Rule}|{ev.Action}|{ev.BytesUp}|{ev.BytesDown}|{ev.DurationMs}|{ev.Detail}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private void RollIfNeeded()
    {
        if (_writer is null) return;
        var today = DateTime.UtcNow.Date;
        var oversized = _fs is not null && _fs.Length >= _maxFileBytes;
        if (today != _currentFileDate || oversized)
        {
            _writer.Dispose(); _fs!.Dispose();
            _writer = null; _fs = null;
            PruneOldFiles();
            OpenNewFile(today == _currentFileDate && oversized ? DateTime.UtcNow : DateTime.UtcNow);
        }
    }

    private void OpenNewFile(DateTime utcNow)
    {
        var seq = Interlocked.Increment(ref _currentFileSeq);
        var path = Path.Combine(_dir, $"audit-{utcNow:yyyyMMdd}-{seq:D6}.jsonl");
        _fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(_fs, new UTF8Encoding(false)) { AutoFlush = true };
        _currentFileDate = DateTime.UtcNow.Date;
    }

    private void PruneOldFiles()
    {
        try
        {
            var files = Directory.GetFiles(_dir, "audit-*.jsonl").OrderDescending(StringComparer.Ordinal).ToList();
            for (var i = _maxFiles; i < files.Count; i++) File.Delete(files[i]);
        }
        catch { /* best effort */ }
    }

    public void Dispose()
    {
        lock (_lock) { _writer?.Dispose(); _fs?.Dispose(); _writer = null; _fs = null; }
    }
}

public static class AuditExtensions
{
    public static void Log(this AuditLogger log, AuditSeverity sev, string type,
        string? proto = null, string? client = null, string? user = null,
        string? host = null, int? port = null, int? rule = null, string? action = null,
        long? bytesUp = null, long? bytesDown = null, long? durationMs = null, string? detail = null)
    {
        log.Write(new AuditEvent
        {
            Sev = sev, Type = type, Proto = proto, Client = client, User = user,
            Host = host, Port = port, Rule = rule, Action = action,
            BytesUp = bytesUp, BytesDown = bytesDown, DurationMs = durationMs, Detail = detail
        });
    }
}
