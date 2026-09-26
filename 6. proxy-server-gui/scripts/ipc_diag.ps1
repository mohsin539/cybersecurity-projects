# IPC diagnostic - dump raw bytes and connection state
$pipeName = "ProxyCoreCtl"
$p = new-object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
try { $p.Connect(3000) } catch { Write-Output "CONNECT FAILED: $_"; exit 1 }
Write-Output "connected: IsConnected=$($p.IsConnected) CanRead=$($p.CanRead) CanWrite=$($p.CanWrite)"

$req = '{"Id":"d1","Type":"status.get"}'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($req + "`n")
$p.Write($bytes, 0, $bytes.Length)
$p.Flush()
Write-Output "wrote $($bytes.Length) bytes: $req"

$buf = New-Object byte[] 4096
try {
    $n = $p.Read($buf, 0, $buf.Length)
    Write-Output "read returned: $n bytes"
    if ($n -gt 0) {
        $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        Write-Output ("RAW: " + $text)
    } else {
        Write-Output "server closed pipe (0 bytes) - IsConnected=$($p.IsConnected)"
    }
} catch {
    Write-Output "read error: $_"
}
$p.Dispose()
