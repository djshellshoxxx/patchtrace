[CmdletBinding()]
param(
    [string]$Installer = "dist/PatchTrace-Windows-x64-Setup.exe"
)

$ErrorActionPreference = "Stop"
$installerPath = (Resolve-Path $Installer).Path
$installDir = Join-Path $env:RUNNER_TEMP "PatchTrace Installer Smoke 研究"
$shortcutPath = Join-Path $env:APPDATA "Microsoft/Windows/Start Menu/Programs/PatchTrace/PatchTrace.lnk"
$projectDataDir = Join-Path $env:RUNNER_TEMP "PatchTrace User Project Data"
$projectData = Join-Path $projectDataDir "keep-this-project.txt"
New-Item -ItemType Directory -Path $projectDataDir -Force | Out-Null
Set-Content -LiteralPath $projectData -Value "user project data sentinel"

if (Test-Path $installDir) {
    Remove-Item -LiteralPath $installDir -Recurse -Force
}
# NSIS requires /D= to be the final unquoted argument, including when the path has spaces.
$installArgs = "/S /D=$installDir"
$install = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
if ($install.ExitCode -ne 0) {
    throw "Installer exited with code $($install.ExitCode)."
}

$exe = Join-Path $installDir "PatchTrace.exe"
if (-not (Test-Path $exe -PathType Leaf)) {
    throw "Installed PatchTrace.exe was not found at $exe."
}
# A project created inside the chosen install directory must survive uninstallation.
$insideProject = Join-Path $installDir "projects/keep-inside-project.txt"
New-Item -ItemType Directory -Path (Split-Path $insideProject -Parent) -Force | Out-Null
Set-Content -LiteralPath $insideProject -Value "in-place user project sentinel"
$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PatchTrace"
if (-not (Test-Path $uninstallKey)) {
    throw "Installer did not register with per-user Windows Apps/Uninstall."
}
if (-not (Test-Path $shortcutPath -PathType Leaf)) {
    throw "Start Menu shortcut was not created at $shortcutPath."
}
$qtCore = Get-ChildItem -LiteralPath $installDir -Filter "Qt6Core.dll" -File -Recurse
$qtWindows = Get-ChildItem -LiteralPath $installDir -Filter "qwindows.dll" -File -Recurse
if (-not $qtCore -or -not $qtWindows) {
    throw "The installed app is missing required Qt runtime files or the Windows platform plugin."
}
$nsisNotice = Join-Path $installDir "licenses/installer/COPYING"
if (-not (Test-Path $nsisNotice -PathType Leaf)) {
    throw "The NSIS redistribution notice is missing from the installed app."
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

$uninstaller = Join-Path $installDir "Uninstall.exe"
if (-not (Test-Path $uninstaller -PathType Leaf)) {
    throw "NSIS uninstaller was not installed."
}
$remove = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
if ($remove.ExitCode -ne 0) {
    throw "Uninstaller exited with code $($remove.ExitCode)."
}
if (Test-Path $exe -PathType Leaf) {
    throw "Uninstall left PatchTrace.exe in $installDir."
}
if (-not (Test-Path $insideProject -PathType Leaf)) {
    throw "Uninstall deleted user-created data inside the install directory."
}
if (Test-Path $uninstallKey) {
    throw "Uninstall left the per-user Windows Apps entry behind."
}
if (Test-Path $shortcutPath) {
    throw "Uninstall left the Start Menu shortcut behind."
}
if (-not (Test-Path $projectData -PathType Leaf)) {
    throw "Uninstall removed user project data outside the application directory."
}
Remove-Item -LiteralPath $installDir -Recurse -Force
Write-Host "Installer registration, Qt/runtime checks, frozen self-test, non-destructive uninstall passed."
