using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using ProxyContracts;
using ProxyGui.Services;

namespace ProxyGui;

public partial class MainWindow : Window
{
    private readonly AgentClient _agent = new();
    private readonly DispatcherTimer _timer = new();
    private bool _isAdmin;
    private int _pollBusy; // 1 while a status poll is in flight; prevents overlapping requests

    public MainWindow()
    {
        InitializeComponent();
        _timer.Interval = TimeSpan.FromSeconds(2);
        _timer.Tick += async (_, _) => await RefreshStatusAsync();
        _timer.Start();
        Loaded += async (_, _) => { await RefreshStatusAsync(); LoadRules_Click(null!, null!); };
    }

    private async Task RefreshStatusAsync()
    {
        // Skip this tick if the previous poll hasn't completed yet (avoids request pile-up).
        if (System.Threading.Interlocked.CompareExchange(ref _pollBusy, 1, 0) != 0) return;
        try
        {
            var resp = await _agent.GetStatusAsync();
            if (resp.Ok && resp.Body is not null)
            {
                var dto = System.Text.Json.JsonSerializer.Deserialize<HealthDto>(resp.Body);
                if (dto is null) return;
                ServiceStateText.Text = "state: running";
                ServiceStateText.Foreground = System.Windows.Media.Brushes.LightGreen;
                StatActive.Text = dto.Metrics.SessionsActive.ToString("N0");
                StatTotal.Text = dto.Metrics.SessionsTotal.ToString("N0");
                StatBlocked.Text = dto.Metrics.DeniedTotal.ToString("N0");
                StatErrors.Text = dto.Metrics.ErrorsTotal.ToString("N0");
                UptimeText.Text = TimeSpan.FromSeconds(dto.UptimeSec).ToString(@"d\.hh\:mm\:ss");
                BytesUpText.Text = FormatBytes(dto.Metrics.BytesUp);
                BytesDownText.Text = FormatBytes(dto.Metrics.BytesDown);
            }
            else
            {
                SetServiceDown();
            }
        }
        catch
        {
            SetServiceDown();
        }
        finally
        {
            System.Threading.Interlocked.Exchange(ref _pollBusy, 0);
        }
    }

    private void SetServiceDown()
    {
        ServiceStateText.Text = "state: service not responding";
        ServiceStateText.Foreground = System.Windows.Media.Brushes.OrangeRed;
    }

    internal static string FormatBytes(long n) => n switch
    {
        >= 1 << 30 => $"{n / (double)(1 << 30):F2} GB",
        >= 1 << 20 => $"{n / (double)(1 << 20):F2} MB",
        >= 1 << 10 => $"{n / (double)(1 << 10):F2} KB",
        _ => $"{n} B"
    };

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button b) return;
        var name = b.Name["Nav".Length..];
        foreach (var child in ((Grid)b.Parent).Parent is Grid main ? FindPanels(main) : Enumerable.Empty<Grid>())
        {
            child.Visibility = child.Name == "Panel" + name ? Visibility.Visible : Visibility.Collapsed;
        }
        switch (name)
        {
            case "Dashboard": break;
            case "Connections": _ = LoadConnections_Click(); break;
            case "Rules": LoadRules_Click(null, null); break;
            case "Logs": LoadLogs_Click(null, null); break;
            case "Upstreams": _ = LoadUpstreams_Click(); break;
            case "Diagnostics": break;
            case "Settings": _ = LoadSettings_Click(); break;
        }
    }

    private static IEnumerable<Grid> FindPanels(Grid main) =>
        main.Children.OfType<Grid>().Where(g => g.Name?.StartsWith("Panel") == true);

    private async Task LoadConnections_Click()
    {
        // v1: live per-connection table is fed by the engine in P2; placeholder for now
        ConnectionsGrid.ItemsSource = Array.Empty<ConnectionDto>();
        await Task.CompletedTask;
    }

    private async void LoadRules_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var resp = await _agent.GetRulesAsync();
            if (resp.Ok && resp.Body is not null)
            {
                var dto = System.Text.Json.JsonSerializer.Deserialize<RulesDto>(resp.Body);
                RulesGrid.ItemsSource = dto?.Rules;
                _isAdmin = new System.Security.Principal.WindowsPrincipal(
                    System.Security.Principal.WindowsIdentity.GetCurrent())
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }
        catch { /* service down */ }
    }

    private async void SaveRules_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (RulesGrid.ItemsSource is not IEnumerable<ProxyCore.Rules.RuleDefinition> rules) return;
            var resp = await _agent.SetRulesAsync(rules.ToList(), _isAdmin);
            MessageBox.Show(this, resp.Ok ? "Rules applied (hot reload)." : "Failed: " + resp.Error,
                resp.Ok ? "Saved" : "Error", MessageBoxButton.OK,
                resp.Ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Service unreachable: " + ex.Message, "Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void LoadLogs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var resp = await _agent.GetLogsAsync(200);
            if (resp.Ok && resp.Body is not null)
            {
                var lines = System.Text.Json.JsonSerializer.Deserialize<List<string>>(resp.Body);
                LogsList.Items.Clear();
                foreach (var line in (lines ?? new()).AsEnumerable().Reverse())
                {
                    LogsList.Items.Add(line);
                }
            }
        }
        catch { /* service down */ }
    }

    private async Task LoadUpstreams_Click()
    {
        try
        {
            var resp = await _agent.GetUpstreamsAsync();
            if (resp.Ok && resp.Body is not null)
            {
                var dto = System.Text.Json.JsonSerializer.Deserialize<UpstreamsDto>(resp.Body);
                UpstreamsGrid.ItemsSource = dto?.Upstreams;
            }
        }
        catch { /* service down */ }
    }

    private async void RunDiag_Click(object sender, RoutedEventArgs e)
    {
        DiagResults.Text = "Running self-test…";
        try
        {
            var resp = await _agent.RunDiagnosticsAsync();
            if (resp.Ok && resp.Body is not null)
            {
                var d = System.Text.Json.JsonSerializer.Deserialize<DiagResultDto>(resp.Body);
                DiagResults.Text = $"Listeners bound: {(d?.ListenersBind == true ? "OK" : "FAIL")}\n" +
                                   $"DNS resolution:  {(d?.DnsWorks == true ? "OK" : "FAIL")}\n" +
                                   $"Upstream reach:  {(d?.UpstreamReachable == true ? "OK" : "FAIL")}\n" +
                                   (string.IsNullOrEmpty(d?.Notes) ? "" : "Notes: " + d?.Notes);
            }
            else DiagResults.Text = "Failed: " + resp.Error;
        }
        catch (Exception ex)
        {
            DiagResults.Text = "Service unreachable: " + ex.Message;
        }
    }

    private Task LoadSettings_Click()
    {
        SettingsInfo.Text = "config.json is loaded from the service base directory.\n" +
                            "Edit and use Config Import (admin) to apply, or restart the service after edits.";
        return Task.CompletedTask;
    }
}
