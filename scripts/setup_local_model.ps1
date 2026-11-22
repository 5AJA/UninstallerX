param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$localRoot = Join-Path $repoRoot '.local'
$runtimeRoot = Join-Path $localRoot 'runtime'
$modelRoot = Join-Path $localRoot 'models\granite-4.2-3b-Q4_K_M'
$archive = Join-Path $runtimeRoot 'llama-b12414-bin-win-cpu-x64.zip'
$binary = Join-Path $runtimeRoot 'llama-b12414-cpu\llama-server.exe'
$model = Join-Path $modelRoot 'granite-4.2-3b-Q4_K_M.gguf'
$keyFile = Join-Path $runtimeRoot 'api-key.txt'

New-Item -ItemType Directory -Force -Path $runtimeRoot, $modelRoot | Out-Null

if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://github.com/ggml-org/llama.cpp/releases/download/b12414/llama-b12414-bin-win-cpu-x64.zip' -OutFile $archive
}
$expectedRuntimeHash = 'bbd666b4fe357053f4105b69b815a26f8223cfdbf7b2b4a9042b2fee979575a3'
$actualRuntimeHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualRuntimeHash -ne $expectedRuntimeHash) { throw "llama.cpp archive SHA-256 mismatch: $actualRuntimeHash" }
if (-not (Test-Path -LiteralPath $binary)) {
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $runtimeRoot 'llama-b12414-cpu') -Force
}

if (-not (Test-Path -LiteralPath $model)) {
    if (-not (Get-Command uvx -ErrorAction SilentlyContinue)) { throw 'uvx is required to download the model. Install uv, then rerun this script.' }
    & uvx --from huggingface_hub hf download ibm-granite/granite-4.2-3b-GGUF granite-4.2-3b-Q4_K_M.gguf --revision c40945d71cd90f249a56985e8155551a9188dc30 --local-dir $modelRoot --format quiet
    if ($LASTEXITCODE -ne 0) { throw "Model download failed with exit code $LASTEXITCODE" }
}
$expectedModelHash = 'e0406663965846ae22a403456eb826ccce5f450840491f71952f18a7cb78e7d5'
$actualModelHash = (Get-FileHash -LiteralPath $model -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualModelHash -ne $expectedModelHash) { throw "Model SHA-256 mismatch: $actualModelHash" }

if (-not (Test-Path -LiteralPath $keyFile)) {
    $randomBytes = New-Object byte[] 32
    $randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $randomGenerator.GetBytes($randomBytes) } finally { $randomGenerator.Dispose() }
    $key = [Convert]::ToBase64String($randomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Set-Content -LiteralPath $keyFile -Value $key -Encoding Ascii -NoNewline
}

Write-Output "Runtime ready: $binary"
Write-Output "Model ready: $model"
