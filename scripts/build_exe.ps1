param(
    [string]$Python = 'python',
    [string]$DistDirectory = 'dist',
    [string]$VcRuntimeDirectory = (Join-Path $env:SystemRoot 'System32')
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not [IO.Path]::IsPathRooted($DistDirectory)) { $DistDirectory = Join-Path $repo $DistDirectory }
$dist = [IO.Path]::GetFullPath($DistDirectory)
$bundle = Join-Path $dist 'UninstallerX'
if (Test-Path -LiteralPath $bundle) {
    throw "Output already exists: $bundle. Choose another -DistDirectory."
}

$manifestPath = Join-Path $repo 'docs\model-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$logo = Join-Path $repo 'img\logo.ico'
$runtime = Join-Path $repo '.local\runtime'
$modelName = [IO.Path]::GetFileNameWithoutExtension($manifest.model.file)
$modelPath = Join-Path $repo ".local\models\$modelName\$($manifest.model.file)"
$archive = Join-Path $runtime $manifest.runtime.archive
if (-not (Test-Path -LiteralPath $archive -PathType Leaf) -or -not (Test-Path -LiteralPath $modelPath -PathType Leaf)) {
    throw 'Run scripts/setup_local_model.ps1 to download the pinned model and runtime before building.'
}
# llama.cpp imports the Visual C++ runtime, which a clean Windows installation does not have.
$vcRuntime = 'vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll' | ForEach-Object { Join-Path $VcRuntimeDirectory $_ }
foreach ($library in $vcRuntime) {
    if (-not (Test-Path -LiteralPath $library -PathType Leaf)) {
        throw "Missing $library. Install the Microsoft Visual C++ Redistributable (x64) on the build machine or pass -VcRuntimeDirectory."
    }
}
if ((Get-FileHash -LiteralPath $archive).Hash -ine $manifest.runtime.sha256 -or
    (Get-FileHash -LiteralPath $modelPath).Hash -ine $manifest.model.sha256) {
    throw 'The local runtime archive or model failed SHA-256 verification.'
}

$build = Join-Path $repo '.local\pyinstaller'
New-Item -ItemType Directory -Force -Path $build | Out-Null
$runtimeLicense = Join-Path $build 'llama.cpp-MIT.txt'
$modelLicense = Join-Path $build 'Granite-Apache-2.0.txt'
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/ggml-org/llama.cpp/$($manifest.runtime.release)/LICENSE" -OutFile $runtimeLicense
Invoke-WebRequest -UseBasicParsing -Uri 'https://www.apache.org/licenses/LICENSE-2.0.txt' -OutFile $modelLicense
$pythonBase = & $Python -c 'import sys; print(sys.base_prefix)'
if ($LASTEXITCODE -ne 0) { throw "Cannot locate the Python build environment: $Python" }
$pythonLicense = Join-Path $pythonBase 'LICENSE.txt'

# PyInstaller refuses to run from System32, where an elevated prompt starts.
Push-Location -LiteralPath $repo
try {
    & $Python -m PyInstaller --onedir --windowed --noupx --uac-admin --name UninstallerX --icon $logo `
        --paths (Join-Path $repo 'src') --workpath (Join-Path $build 'work') --specpath $build --distpath $dist `
        (Join-Path $PSScriptRoot 'windows_app.py')
} finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE." }

$modelTarget = Join-Path $bundle ".local\models\$modelName"
$runtimeTarget = Join-Path $bundle ".local\runtime\llama-$($manifest.runtime.release)-cpu"
$docsTarget = Join-Path $bundle 'docs'
$iconTarget = Join-Path $bundle 'img'
$licenseTarget = Join-Path $bundle 'licenses'
New-Item -ItemType Directory -Path $modelTarget, $runtimeTarget, $docsTarget, $iconTarget, $licenseTarget -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $runtimeTarget
Copy-Item -LiteralPath $vcRuntime -Destination $runtimeTarget
Copy-Item -LiteralPath $modelPath -Destination $modelTarget
Copy-Item -LiteralPath $manifestPath -Destination $docsTarget
Copy-Item -LiteralPath $logo -Destination $iconTarget
Copy-Item -LiteralPath $runtimeLicense, $modelLicense -Destination $licenseTarget
if (Test-Path -LiteralPath $pythonLicense -PathType Leaf) {
    Copy-Item -LiteralPath $pythonLicense -Destination (Join-Path $licenseTarget 'Python-LICENSE.txt')
}
Write-Output (Join-Path $bundle 'UninstallerX.exe')
