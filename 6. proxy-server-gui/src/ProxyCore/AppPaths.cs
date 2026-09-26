using System.Reflection;

namespace ProxyCore;

/// <summary>
/// Portable path resolution. Single-file published exes extract to a temp dir,
/// so AppContext.BaseDirectory is NOT portable. Environment.ProcessPath points at
/// the real .exe the user runs — all relative paths (config, vault, logs) anchor there.
/// Override everything with PROXYCORE_HOME for USB-stick or custom layouts.
/// </summary>
public static class AppPaths
{
    private static readonly string? _processDir =
        Path.GetDirectoryName(Environment.ProcessPath);

    /// <summary>Directory containing the running .exe (portable root).</summary>
    public static string ExeDir =>
        _processDir ?? AppContext.BaseDirectory;

    /// <summary>Portable home: exe dir unless PROXYCORE_HOME overrides.</summary>
    public static string Home
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("PROXYCORE_HOME");
            return string.IsNullOrWhiteSpace(env) ? ExeDir : env;
        }
    }

    public static string ConfigFile
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("PROXYCORE_CONFIG");
            return string.IsNullOrWhiteSpace(env)
                ? Path.Combine(Home, "config.json")
                : env;
        }
    }

    public static string LogsDir => Path.Combine(Home, "logs");
    public static string DataDir => Path.Combine(Home, "data");

    public static string VaultFile(string relativeName)
    {
        if (Path.IsPathRooted(relativeName)) return relativeName;
        return Path.Combine(DataDir, Path.GetFileName(relativeName));
    }

    /// <summary>Resolve a possibly-relative logging directory against the portable home.</summary>
    public static string ResolveDir(string dir)
    {
        if (Path.IsPathRooted(dir)) return dir;
        return Path.Combine(Home, dir);
    }
}
