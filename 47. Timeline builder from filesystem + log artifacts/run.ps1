param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$env:PYTHONPATH = Join-Path $root "src"
$env:PYTHONUTF8 = "1"

python (Join-Path $root "run_app.py") @Args
