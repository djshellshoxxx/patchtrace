[CmdletBinding()]
param(
    [string]$Archive = "dist/PatchTrace-0.1.0-windows-x64.zip"
)

$ErrorActionPreference = "Stop"
$archivePath = (Resolve-Path $Archive).Path
$checksumPath = "$archivePath.sha256"
if (-not (Test-Path $checksumPath -PathType Leaf)) {
    throw "Missing portable ZIP SHA-256 sidecar: $checksumPath"
}
$expected = ((Get-Content -LiteralPath $checksumPath -TotalCount 1) -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    throw "Portable ZIP SHA-256 mismatch: $actual versus $expected"
}

$extraction = Join-Path $env:RUNNER_TEMP "PatchTrace Portable 研究 With Spaces"
if (Test-Path $extraction) {
    Remove-Item -LiteralPath $extraction -Recurse -Force
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $extraction -Force
$directory = Join-Path $extraction "PatchTrace"
$exe = Join-Path $directory "PatchTrace.exe"
if (-not (Test-Path $exe -PathType Leaf)) {
    throw "Portable archive did not contain PatchTrace.exe"
}
if (-not (Get-ChildItem -LiteralPath $directory -Recurse -File -Filter "qwindows.dll")) {
    throw "Portable archive is missing the Qt Windows platform plugin"
}
if (-not (Test-Path (Join-Path $directory "dependency-versions.json"))) {
    throw "Portable archive is missing the dependency manifest"
}
if (-not (Test-Path (Join-Path $directory "licenses"))) {
    throw "Portable archive is missing third-party notices"
}

$priorQpa = $env:QT_QPA_PLATFORM
$priorPythonHome = $env:PYTHONHOME
$priorPythonPath = $env:PYTHONPATH
try {
    $env:QT_QPA_PLATFORM = "offscreen"
    $env:PYTHONHOME = ""
    $env:PYTHONPATH = ""
    $selfTest = Start-Process -FilePath $exe -ArgumentList "--self-test" -WorkingDirectory $directory -Wait -PassThru
    if ($selfTest.ExitCode -ne 0) {
        throw "Extracted portable executable failed self-test: $($selfTest.ExitCode)"
    }
    $cli = Start-Process -FilePath $exe -ArgumentList @("rank", "--help") -WorkingDirectory $directory -Wait -PassThru
    if ($cli.ExitCode -ne 0) {
        throw "Extracted portable executable failed CLI smoke: $($cli.ExitCode)"
    }
}
finally {
    $env:QT_QPA_PLATFORM = $priorQpa
    $env:PYTHONHOME = $priorPythonHome
    $env:PYTHONPATH = $priorPythonPath
    Remove-Item -LiteralPath $extraction -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "Portable checksum, clean extraction, Qt plugin, dependencies, and frozen executable smoke passed."
