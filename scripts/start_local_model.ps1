param(
    [ValidateRange(1, 65535)][int]$Port = 18089,
    [ValidateRange(1, 64)][int]$Threads = 4
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$binary = Join-Path $repoRoot '.local\runtime\llama-b12414-cpu\llama-server.exe'
$model = Join-Path $repoRoot '.local\models\granite-4.2-3b-Q4_K_M\granite-4.2-3b-Q4_K_M.gguf'
$keyFile = Join-Path $repoRoot '.local\runtime\api-key.txt'
if (-not (Test-Path -LiteralPath $binary) -or -not (Test-Path -LiteralPath $model) -or -not (Test-Path -LiteralPath $keyFile)) {
    throw 'Local runtime or model missing. Run scripts/setup_local_model.ps1 first.'
}
$expectedModelHash = 'e0406663965846ae22a403456eb826ccce5f450840491f71952f18a7cb78e7d5'
$actualModelHash = (Get-FileHash -LiteralPath $model -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualModelHash -ne $expectedModelHash) { throw "Model SHA-256 mismatch: $actualModelHash" }
$freeRamGiB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB / 1GB
if ($freeRamGiB -lt 8) { throw ('At least 8 GiB of free RAM is required before starting the model; available: {0:N2} GiB' -f $freeRamGiB) }

& $binary -m $model --host 127.0.0.1 --port $Port --api-key-file $keyFile --cors-origins "http://127.0.0.1:$Port" -c 4096 -t $Threads --parallel 1 --reasoning off --no-warmup
if ($LASTEXITCODE -ne 0) { throw "Model server exited with code $LASTEXITCODE" }
