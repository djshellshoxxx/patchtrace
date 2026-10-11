# Windows setup and standalone packaging

Desktop target: Windows 11 x64. Extract the complete distribution ZIP into a user-writable location and run PatchTrace.exe. The package includes Python/Qt; it does not include Ghidra, Java, Ghidriff or local LLM weights. The app opens its sample and imports supported diff files without an analysis runtime.

For native comparison install a supported JDK per Ghidra release requirements, unpack Ghidra, and create a separate Python 3.12+ virtual environment:
```powershell
py -3.12 -m venv "$env:LOCALAPPDATA\PatchTrace-backend"
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m pip install "ghidriff @ git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d"
$env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.0.4_PUBLIC'
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m ghidriff --help
```
Settings must point at that backend python.exe, not PatchTrace.exe, and the unpacked Ghidra directory. Research documents the inspected Ghidra target; use setup diagnostics to verify the installed combination. The pinned combination passed the native known-patch workflow; other installed combinations need setup diagnostics and verification. Static PE drivers can be inspected but are never installed or loaded.

Build on Windows from source:
```powershell
py -3.12 -m pip install -e '.[dev]'
py -3.12 -m pytest -q
py -3.12 tools/build_windows.py
```
The build creates an onedir distribution, copies licenses/help/specs, archives it and computes SHA-256.

The build refuses to run when `git status --porcelain` is non-empty or `HEAD` is not a commit. `py -3.12 tools/build_windows.py --allow-dirty` is for local experiments only: the package is then marked `dirty: true`, and the release workflow rejects it. PyInstaller writes its `.spec` file under `build/` so that repeated builds keep the tree clean.

## Console behavior

`PatchTrace.exe` is a console-subsystem executable built with `--console --hide-console hide-early` (SPEC-05 §3.2). One executable serves both the desktop and the command line:

- Double-click or Start menu: the GUI opens. The bootloader hides the console it owns, so at most a brief console flash is visible.
- From `cmd.exe`, PowerShell or Windows Terminal: the console is inherited and stays attached. The shell waits for PatchTrace to finish, output appears in that console, and the exit code is available as `%ERRORLEVEL%` / `$LASTEXITCODE`.
- `PatchTrace.exe` with no arguments in a terminal opens the GUI and the terminal waits until the window closes. Use `start PatchTrace.exe` (cmd) or `Start-Process .\PatchTrace.exe` (PowerShell) to detach.

## Build provenance and source

Every package records where it came from:

- `_internal/patchtrace/build-info.json` holds `version`, `git_commit`, `git_describe`, `dirty`, `source_sha256`, `python`, `pyinstaller`, `pyside6` and `built_utc`. `source_sha256` is the SHA-256 over the sorted lines `<relative path>\t<file SHA-256>` of `src/patchtrace/**/*.py` (paths relative to `src`, `__pycache__` excluded), so it can be recomputed from a checkout with `python -c "from pathlib import Path; from patchtrace.buildinfo import source_sha256; print(source_sha256(Path('src')))"`.
- `PatchTrace.exe version --json` prints that provenance (from source, `python -m patchtrace version --json` computes it live). The build script runs it after packaging and fails if `git_commit` differs from `HEAD`; until the `version` command exists in the entry point, the build only prints a warning. CI additionally checks `build-info.json` against `$GITHUB_SHA`.
- `SOURCE.txt` in the package (and next to the ZIP) names the repository (https://github.com/djshellshoxxx/patchtrace), the commit and the three build commands above.
- `PatchTrace-<version>-source.zip` is a `git archive` of the built commit, published with its `.sha256` next to the binary ZIP and its `.sha256`.

PatchTrace's own modules are stored only as bytecode inside the frozen PyInstaller archive. This is by design: searching the extracted package or a build venv for PatchTrace `.py` files finds none. The editable source is `src/patchtrace` in the repository (or in the source ZIP). Every fix starts there; hand-patching `.pyc` files or the PYZ is prohibited (SRC-7). Unsigned beta package; no installer/elevation needed. Keep Qt DLLs replaceable in onedir distribution. Update by unpacking a new version separately; projects are never overwritten by updater. Back up projects before future schema migration.

Clean-machine QA procedure: open Sample; compare the expected ordinary bounds check; save/reopen; export all three formats; configure native dependencies; compare source-built known-patch fixtures; cancel analysis and check Task Manager for residual backend/Java processes; configure local/remote model with exact context preview; verify cited evidence navigation; resize, tab through controls and change font. Record actual Windows version/dependency versions and outcomes in docs/qa.md. User hands-on QA begins only when a real Windows package is available.
