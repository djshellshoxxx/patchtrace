Open PatchTrace on Windows
Download the Windows x64 distribution ZIP and its accompanying SHA-256 file from the project’s release page. Extract the entire archive into a directory your account can write to.
Keep PatchTrace.exe, _internal, documentation, and licenses together. Run the extracted executable. Launching it inside the ZIP or copying only the executable leaves required files unavailable.
You do not need a separate Python installation to open the packaged desktop application. Python used by the external comparison backend is a different installation.
To inspect a downloaded archive’s hash in PowerShell, substitute its actual filename:
Get-FileHash '.\PatchTrace-0.1.0-windows-x64.zip' -Algorithm SHA256
Get-Content '.\PatchTrace-0.1.0-windows-x64.zip.sha256'

Compare the hexadecimal values. A matching value establishes agreement with that checksum file; it does not independently establish who published either file.
Choose Sample for an initial check. It should create a separate project and display authored comparison data without requiring Ghidra or an AI provider.
Store your projects outside the extracted application directory. When updating, extract the replacement application separately and reopen your existing project.
The cited packaging documentation describes an unsigned portable beta without an installer or elevation requirement.
UNVERIFIED: successful launch on your Windows build, display configuration, and security software requires a local check. Automated startup tests do not establish screen-reader behavior or complete desktop compatibility.
Sources: README.md, “Download and first launch”; docs/windows.md; docs/qa.md.
