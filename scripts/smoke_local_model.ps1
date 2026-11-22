param([ValidateRange(1, 65535)][int]$Port = 18089)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$keyFile = Join-Path $repoRoot '.local\runtime\api-key.txt'
if (-not (Test-Path -LiteralPath $keyFile)) { throw 'Local API key missing. Run scripts/setup_local_model.ps1 first.' }
$key = (Get-Content -LiteralPath $keyFile -Raw).Trim()
$body = @{
    model = 'granite-4.2-3b-Q4_K_M'
    messages = @(
        @{ role = 'system'; content = 'Return exactly one JSON object.' },
        @{ role = 'user'; content = 'Return a JSON object with status equal to ready.' }
    )
    temperature = 1.0
    top_p = 0.95
    max_tokens = 80
    stream = $false
} | ConvertTo-Json -Depth 5

$timer = [Diagnostics.Stopwatch]::StartNew()
$response = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/v1/chat/completions" -Method Post -ContentType 'application/json' -Headers @{ Authorization = "Bearer $key" } -Body $body
$timer.Stop()
$content = $response.choices[0].message.content
$parsed = $content | ConvertFrom-Json
if ($parsed.status -ne 'ready') { throw "Unexpected model answer: $content" }
Write-Output "Model response: $content"
Write-Output ('Elapsed seconds: {0:N2}' -f $timer.Elapsed.TotalSeconds)
