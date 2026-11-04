# Open PatchTrace on Windows

Download one Windows x64 package and its accompanying SHA-256 file from the newest prerelease on the project’s release page: the per-user Setup `PatchTrace-Windows-x64-Setup.exe`, or the portable ZIP `PatchTrace-0.1.0-windows-x64.zip` (also attached as `PatchTrace-Windows-x64-Portable.zip`, the same bytes). Setup installs for your account under `%LOCALAPPDATA%\Programs\PatchTrace`, adds a Start Menu shortcut and does not ask for administrator rights. For the ZIP, extract the entire archive into a directory your account can write to.

Keep `PatchTrace.exe,` `_internal,` documentation, and licenses together. Run the extracted executable, or start PatchTrace from the Start Menu after Setup. Launching it inside the ZIP or copying only the executable leaves required files unavailable.

You do not need a separate Python installation to open the packaged desktop application. Python used by the external comparison backend is a different installation.

To inspect a download’s hash in PowerShell, substitute its actual filename:

```
Get-FileHash '.\PatchTrace-Windows-x64-Setup.exe' -Algorithm SHA256
Get-Content '.\PatchTrace-Windows-x64-Setup.exe.sha256'
Get-FileHash '.\PatchTrace-0.1.0-windows-x64.zip' -Algorithm SHA256
Get-Content '.\PatchTrace-0.1.0-windows-x64.zip.sha256'
```

Compare the hexadecimal values. A matching value establishes agreement with that checksum file; it does not independently establish who published either file.

Choose `Sample` for an initial check. It should create a separate project and display authored comparison data without requiring Ghidra or an AI provider.

Store your projects outside the extracted application directory. When updating, extract the replacement application separately and reopen your existing project.

The cited packaging documentation describes unsigned prereleases, a per-user Setup and a portable ZIP, neither requiring elevation. Because the packages are unsigned, Windows SmartScreen and antivirus software may warn; if SmartScreen shows “Windows protected your PC”, choose **More info** then **Run anyway** only after checking the SHA-256.

> UNVERIFIED: successful launch on your Windows build, display configuration, and security software requires a local check. Automated startup tests do not establish screen-reader behavior or complete desktop compatibility.

Sources: `README.md,` “Download and first launch”; `docs/windows.md;` `docs/install.md;` `docs/specs/windows-release-signing-policy.md;` `docs/qa.md.`
