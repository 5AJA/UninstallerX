param(
    [ValidateRange(1, 240)][int]$TimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'
# ProviderPath stays a plain file system path when the repository is on a network share such as WSL.
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$sandbox = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (-not (Test-Path -LiteralPath $sandbox)) {
    throw 'Windows Sandbox is not available. Enable the Containers-DisposableClientVM feature and restart Windows.'
}
$uv = (Get-Command uv.exe -ErrorAction SilentlyContinue).Source
if (-not $uv) { throw 'uv is required to provide Python inside the sandbox. Install uv, then rerun this script.' }

# The sandbox reads a copy of the repository and writes only to the output folder.
$stage = Join-Path $env:TEMP ('uninstallerx-sandbox-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
$inputRoot = Join-Path $stage 'in'
$outputRoot = Join-Path $stage 'out'
$copy = Join-Path $inputRoot 'repo'
New-Item -ItemType Directory -Path $copy, $outputRoot | Out-Null
& robocopy.exe $repoRoot $copy /E /XD .git .local __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying the repository failed with robocopy exit code $LASTEXITCODE." }
Copy-Item -LiteralPath $uv -Destination $inputRoot

# Tests create .local under the repository, so they run from a writable copy inside the sandbox.
@'
@echo off
echo started> C:\uninstallerx-out\started.txt
robocopy C:\uninstallerx-in\repo C:\uninstallerx /E /NFL /NDL /NJH /NJS /NP >nul
cd /d C:\uninstallerx
set PYTHONPATH=src
set PYTHONIOENCODING=utf-8
C:\uninstallerx-in\uv.exe run --no-project --python 3.13 python -m unittest discover -s tests -v > C:\uninstallerx-out\unittest.log 2>&1
>C:\uninstallerx-out\exit-code.txt echo %ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $inputRoot 'run.cmd') -Encoding Ascii

# The tests need no GPU. Software rendering avoids display session failures seen with vGPU sharing.
$config = Join-Path $stage 'tests.wsb'
@"
<Configuration>
  <vGPU>Disable</vGPU>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$inputRoot</HostFolder>
      <SandboxFolder>C:\uninstallerx-in</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$outputRoot</HostFolder>
      <SandboxFolder>C:\uninstallerx-out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\uninstallerx-in\run.cmd</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $config -Encoding UTF8

Start-Process -FilePath $sandbox -ArgumentList ('"' + $config + '"')
$exitFile = Join-Path $outputRoot 'exit-code.txt'
$log = Join-Path $outputRoot 'unittest.log'
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while (-not (Test-Path -LiteralPath $exitFile)) {
    if ((Get-Date) -gt $deadline) {
        $state = if (Test-Path -LiteralPath (Join-Path $outputRoot 'started.txt')) { 'The tests started but did not finish' } else { 'The sandbox never ran the logon command' }
        throw "$state within $TimeoutMinutes minutes. Output folder: $outputRoot"
    }
    Start-Sleep -Seconds 5
}
$code = [int](Get-Content -LiteralPath $exitFile -Raw).Trim()
Get-Content -LiteralPath $log -Encoding UTF8 -Tail 40
Write-Output "Full log: $log"
Write-Output 'Close the Windows Sandbox window to discard the test environment.'
exit $code
