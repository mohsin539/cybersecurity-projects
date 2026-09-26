using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ProxyContracts;

namespace ProxyGui.Services;

/// <summary>
/// GUI-side named-pipe client. Carries admin token for elevated ops; the service
/// re-validates server-side (GUI is not the security boundary).
/// Every phase (connect, write, read) is bounded by a timeout so a wedged or
/// busy service can never leave the GUI waiting forever.
/// </summary>
public sealed class AgentClient
{
    private const string PipeName = "ProxyCoreCtl";
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);

    public async Task<IpcResponse> SendAsync(IpcRequest req)
    {
        // Single watchdog budget for the whole exchange (connect + write + read).
        using var cts = new CancellationTokenSource(RequestTimeout);
        var ct = cts.Token;

        await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

        try
        {
            await pipe.ConnectAsync(ConnectTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new IOException("Service pipe did not accept a connection (connect timeout).");
        }

        var json = JsonSerializer.Serialize(req);
        var bytes = Encoding.UTF8.GetBytes(json + "\n");

        var sw = Stopwatch.StartNew();
        await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);

        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (line is null) throw new IOException("No response from service");

        var resp = JsonSerializer.Deserialize<IpcResponse>(line);
        return resp ?? new IpcResponse { Ok = false, Error = "deserialization failed" };
    }

    public Task<IpcResponse> GetStatusAsync() =>
        SendAsync(new IpcRequest { Type = IpcTypes.StatusGet });

    public Task<IpcResponse> GetRulesAsync() =>
        SendAsync(new IpcRequest { Type = IpcTypes.RulesGet });

    public Task<IpcResponse> SetRulesAsync(List<ProxyCore.Rules.RuleDefinition> rules, bool isAdmin) =>
        SendAsync(new IpcRequest { Type = IpcTypes.RulesSet, Body = JsonSerializer.Serialize(new RulesDto { Rules = rules }), AdminToken = isAdmin ? Environment.UserName : null });

    public Task<IpcResponse> GetLogsAsync(int last = 100) =>
        SendAsync(new IpcRequest { Type = IpcTypes.LogsQuery, Body = JsonSerializer.Serialize(new LogQueryDto { Last = last }) });

    public Task<IpcResponse> RunDiagnosticsAsync() =>
        SendAsync(new IpcRequest { Type = IpcTypes.DiagRun });

    public Task<IpcResponse> GetUpstreamsAsync() =>
        SendAsync(new IpcRequest { Type = IpcTypes.UpstreamsGet });
}
