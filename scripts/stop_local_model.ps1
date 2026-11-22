param([ValidateRange(1, 65535)][int]$Port = 18089)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$binary = (Resolve-Path (Join-Path $repoRoot '.local\runtime\llama-b12414-cpu\llama-server.exe')).Path
$prefix = '"' + $binary + '"'
$stopped = 0
foreach ($process in Get-CimInstance Win32_Process -Filter "Name='llama-server.exe'") {
    if (-not $process.CommandLine) { continue }
    if (-not $process.CommandLine.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    if ($process.CommandLine -notmatch "(?:^|\s)--port\s+$Port(?:\s|$)") { continue }
    Stop-Process -Id $process.ProcessId -ErrorAction Stop
    $stopped++
}
Write-Output "Stopped $stopped UninstallerX model server process(es) on port $Port."
