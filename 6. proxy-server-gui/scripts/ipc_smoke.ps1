# IPC smoke test — same round-trip the GUI performs (status.get over named pipe)
$pipeName = "ProxyCoreCtl"
for ($i = 1; $i -le 3; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = new-object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $p.Connect(3000)
    $enc = [System.Text.Encoding]::UTF8
    $req = '{"Id":"smoke' + $i + '","Type":"status.get"}'
    $bytes = $enc.GetBytes($req + "`n")
    $p.Write($bytes, 0, $bytes.Length)
    $p.Flush()
    $buf = new-object System.IO.MemoryStream
    $b = $p.ReadByte()
    while ($b -ne 10 -and $b -ne -1) { $buf.WriteByte($b); $b = $p.ReadByte() }
    $p.Dispose()
    $sw.Stop()
    $resp = $enc.GetString($buf.ToArray())
    $ms = $sw.ElapsedMilliseconds
    if ($resp -match '"Ok":true') {
        Write-Output ("try {0}: OK in {1} ms - {2}" -f $i, $ms, $resp.Substring(0, [Math]::Min(120, $resp.Length)))
    } else {
        Write-Output ("try {0}: UNEXPECTED - {1}" -f $i, $resp)
        exit 1
    }
}
Write-Output "IPC SMOKE TEST PASSED (3/3, no hangs)"
