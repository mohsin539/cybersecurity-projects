using ProxyCore.Audit;
using ProxyCore.Options;
using ProxyCore.Security;
using ProxyCoreSvc;

// ProxyCoreSvc — console/service host.
// Production installs register this as a Windows Service (SC-2 / CM-7 hardening: minimal surface).
// Run interactively for development:  dotnet run --project src/ProxyCoreSvc

Console.WriteLine("ProxyCoreSvc starting...");
Console.WriteLine($"Portable home: {ProxyCore.AppPaths.Home}");

var cfg = ConfigLoader.Load();
cfg.Logging.Directory = ProxyCore.AppPaths.ResolveDir(cfg.Logging.Directory);
Directory.CreateDirectory(cfg.Logging.Directory);

var engine = new ProxyCore.ProxyEngine(cfg, ProxyCore.AppPaths.Home);
try
{
    await engine.StartAsync();
}
catch (Exception ex)
{
    // Bind failures (bad 'auto' resolution, port in use, typo'd hostname) must be loud.
    Console.Error.WriteLine($"FATAL: failed to start proxy listeners:");
    Console.Error.WriteLine(ex.ToString());
    Environment.Exit(1);
}

var vault = new SecretVault(ProxyCore.AppPaths.VaultFile(cfg.Security.SecretVaultPath));
var audit = new AuditLogger(cfg.Logging);
var ipc = new IpcServer(engine, cfg, audit, vault);
ipc.Start();

Console.WriteLine($"HTTP  proxy listening on {cfg.Listeners.Http.Bind} -> {engine.ResolvedHttpBind}:{cfg.Listeners.Http.Port}");
Console.WriteLine($"SOCKS5 proxy listening on {cfg.Listeners.Socks5.Bind} -> {engine.ResolvedSocksBind}:{cfg.Listeners.Socks5.Port}");
var allowList = cfg.Security.Clients?.Allow ?? new List<string>();
Console.WriteLine(allowList.Count > 0
    ? $"Client allowlist: {string.Join(", ", allowList)}"
    : "Client allowlist: (open - all clients allowed; set security.clients.allow for LAN exposure)");
Console.WriteLine("Press Ctrl+C to stop.");

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    ipc.Stop();
    engine.Stop();
    Environment.Exit(0);
};

// Keep the host alive
await Task.Delay(Timeout.Infinite);
