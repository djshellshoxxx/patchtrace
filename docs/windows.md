# Windows setup and standalone packaging

Desktop target: Windows 11 x64. Extract the complete distribution ZIP into a user-writable location and run PatchTrace.exe. The package includes Python/Qt; it does not include Ghidra, Java, Ghidriff or local LLM weights. The app opens its sample and imports supported diff files without an analysis runtime.

For native comparison install a supported JDK per Ghidra release requirements, unpack Ghidra, and create a separate Python 3.12+ virtual environment:
```powershell
py -3.12 -m venv "$env:LOCALAPPDATA\PatchTrace-backend"
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m pip install "ghidriff @ git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d"
$env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.0.4_PUBLIC'
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m ghidriff --help
```
Setup now discovers an existing dedicated backend environment at `%LOCALAPPDATA%\\PatchTrace-backend\\Scripts\\python.exe` and common Ghidra extraction locations through bounded read-only scans. Unique candidates prefill empty fields; manually configured paths are retained. The **Find existing installations** button rescans. Multiple candidates require selecting an explicit path using Browse. Discovery does not install dependencies or execute Python/Ghidra. Settings must point at that backend python.exe, not PatchTrace.exe, and the unpacked Ghidra directory. Ghidriff symbol-server lookup is disabled by default (the backend supplies `--no-symbols`); enable it in Setup only if intended. Ghidra and extensions are separate processes: use actual OS network controls to enforce an air gap. Research documents the inspected Ghidra target; use setup diagnostics to verify the installed combination. The pinned combination passed the native known-patch workflow; other installed combinations need setup diagnostics and verification. Static PE drivers can be inspected but are never installed or loaded.

Build on Windows from source:
```powershell
py -3.12 -m pip install -e '.[dev]'
py -3.12 -m pytest -q
py -3.12 tools/build_windows.py
```
The build creates an onedir distribution, copies licenses/help/specs, archives it and computes SHA-256. Unsigned beta package; no installer/elevation needed. Keep Qt DLLs replaceable in onedir distribution. Update by unpacking a new version separately; projects are never overwritten by updater. Back up projects before future schema migration.

Clean-machine QA procedure: open Sample; compare the expected ordinary bounds check; save/reopen; export all three formats; configure native dependencies; compare source-built known-patch fixtures; cancel analysis and check Task Manager for residual backend/Java processes; configure local/remote model with exact context preview; verify cited evidence navigation; resize, tab through controls and change font. Record actual Windows version/dependency versions and outcomes in docs/qa.md. User hands-on QA begins only when a real Windows package is available.
