[CmdletBinding()]
param(
    [string]$Installer = "dist/PatchTrace-Windows-x64-Setup.exe"
)

$ErrorActionPreference = "Stop"
$installerPath = (Resolve-Path $Installer).Path
$installDir = Join-Path $env:RUNNER_TEMP "PatchTrace Installer Smoke 研究"
$shortcutPath = Join-Path $env:APPDATA "Microsoft/Windows/Start Menu/Programs/PatchTrace.lnk"

if (Test-Path $installDir) {
    Remove-Item -LiteralPath $installDir -Recurse -Force
}

$installArgs = @(
    "/VERYSILENT",
    "/SUPPRESSMSGBOXES",
    "/NORESTART",
    "/CURRENTUSER",
    "/DIR=`"$installDir`""
)
$install = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
if ($install.ExitCode -ne 0) {
    throw "Installer exited with code $($install.ExitCode)."
}

$exe = Join-Path $installDir "PatchTrace.exe"
if (-not (Test-Path $exe -PathType Leaf)) {
    throw "Installed PatchTrace.exe was not found at $exe."
}
if (-not (Test-Path $shortcutPath -PathType Leaf)) {
    throw "Start Menu shortcut was not created at $shortcutPath."
}
$qtCore = Get-ChildItem -LiteralPath $installDir -Filter "Qt6Core.dll" -File -Recurse
$qtWindows = Get-ChildItem -LiteralPath $installDir -Filter "qwindows.dll" -File -Recurse
if (-not $qtCore -or -not $qtWindows) {
    throw "The installed app is missing required Qt runtime files or the Windows platform plugin."
}

$previousQpa = $env:QT_QPA_PLATFORM
try {
    $env:QT_QPA_PLATFORM = "offscreen"
    $smoke = Start-Process -FilePath $exe -ArgumentList @("--self-test") -WorkingDirectory $installDir -Wait -PassThru
    if ($smoke.ExitCode -ne 0) {
        throw "Installed frozen application self-test exited with code $($smoke.ExitCode)."
    }
}
finally {
    $env:QT_QPA_PLATFORM = $previousQpa
}

$uninstaller = Join-Path $installDir "unins000.exe"
if (-not (Test-Path $uninstaller -PathType Leaf)) {
    throw "Inno Setup uninstaller was not installed."
}
$remove = Start-Process -FilePath $uninstaller -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
) -Wait -PassThru
if ($remove.ExitCode -ne 0) {
    throw "Uninstaller exited with code $($remove.ExitCode)."
}
if (Test-Path $installDir) {
    throw "Uninstall left application files in $installDir."
}
if (Test-Path $shortcutPath) {
    throw "Uninstall left the Start Menu shortcut behind."
}
Write-Host "Installer install, Qt/runtime checks, frozen self-test, and uninstall passed."
