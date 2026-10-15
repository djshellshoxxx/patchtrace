# 10. Getting started

This chapter takes you from a download to a first project. It covers the Windows zip, the Linux tar.gz, what runs without any extra tool, what the "offline bundle" is (and is not yet), and how PatchTrace finds Ghidra, Java and Ghidriff.

Status labels used throughout this guide: **built** (code exists on `main` and was checked), **planned** (specified, not built), **unverified** (built, but no native or hands-on acceptance is recorded). Back to the [index](00-index.md).

## What you need

| You want to | You need |
|---|---|
| Open the synthetic sample, import a Ghidriff JSON, review, export | Only the PatchTrace package (Python and Qt are inside) |
| Run a comparison yourself | A backend: Ghidra 12.0.4, a JDK, Python 3.12 with the pinned Ghidriff, **or** a prepared offline backend (see below) |
| Second opinions (optional) | `rz-diff` (rizin), BinDiff 8 plus `.BinExport` files |
| Static tool evidence (optional) | `capa`, `FLOSS`, `diec` (Detect It Easy) |
| YARA-X rule workflow (optional) | the `rules` extra (`yara-x`) in a source install |

Supported input: PE AMD64 (`.exe`, `.dll`, `.sys`), validated by header, not by extension. ELF, Mach-O, ARM64 and 32-bit x86 are outside the supported contract (`docs/specs/non-goals.md`, NG-R3). PatchTrace never executes a target and never loads or installs a driver.

## Install the Windows zip

1. Download `PatchTrace-0.1.0-windows-x64.zip` and its `.sha256` from the GitHub Releases page. Every release so far is a prerelease tagged `v0.1.0-beta.N` ([release process](../release-process.md), [version history](../version-history.md)). There is no final release and the package is unsigned.
2. Verify the hash (PowerShell):
   ```powershell
   Get-FileHash .\PatchTrace-0.1.0-windows-x64.zip -Algorithm SHA256
   Get-Content .\PatchTrace-0.1.0-windows-x64.zip.sha256
   ```
   A matching checksum detects corruption. It does not prove who built the file, because there is no code signature yet (SPEC-52, `docs/specs/windows-release-signing-policy.md`).
3. If Windows marked the zip as downloaded, tick **Unblock** in its Properties (or run `Unblock-File`) before extracting.
4. Extract the **whole** zip into a user-writable folder. Keep `PatchTrace.exe`, `_internal`, documentation and licences together. Running the exe from inside the zip, or copying only the exe, does not work.
5. Run `PatchTrace.exe`. SmartScreen may warn about an unsigned package.
6. Keep your projects outside the application folder so replacing the application never touches them.

Target platform: Windows 11 x64. To update, unpack a new version into a separate folder; projects and settings are not overwritten.

## Install the Linux tar.gz

```bash
sha256sum -c PatchTrace-0.1.0-linux-x86_64.tar.gz.sha256
tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz
./PatchTrace/PatchTrace
QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test   # headless smoke test
```

Qt's host libraries are not bundled. On Debian or Ubuntu you need `libegl1 libgl1 libfontconfig1 libdbus-1-3 libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxcb-xfixes0`, or a Wayland session. If startup aborts with `Could not load the Qt platform plugin "xcb"`, run `ldd PatchTrace/_internal/PySide6/Qt/lib/libQt6XcbQpa.so.6 | grep 'not found'` (see [18](18-troubleshooting.md)). Source: `docs/linux.md`.

The Linux build is smoke-tested offscreen and under Xvfb on Ubuntu 22.04 and 24.04 in CI. **Unverified:** live Ghidriff analysis from the frozen Linux build (`tasks/todo.md`, `docs/linux.md`).

## First run: the sample

The sample needs no Ghidra and no AI provider.

1. Click **Sample** and choose a parent folder. PatchTrace writes a new `patchtrace-sample-<timestamp>` project (`MainWindow.open_sample`).
2. Select the modified function in **FUNCTION MATCHES**, read both code panes, press **Next diff** (Alt+Down).
3. Select the sample finding, open an evidence entry, add a note, then **Export** a Markdown, HTML or JSON report.

The sample is an authored, synthetic bounds-check example (`src/patchtrace/sample.py`). No model and no analysis engine ran. See [11](11-workflow-compare.md) for the full workflow.

`PatchTrace.exe --self-test` (used by CI on the frozen build) opens the sample in an offscreen window, checks that matches display, and runs `PanelHost.self_check()` (every manifest module imports, every panel builds once). It prints the optional-dependency summary line first (`src/patchtrace/__main__.py`).

## External tools and how PatchTrace finds them

Ghidra, Java and Ghidriff are **not** bundled in the normal package and are never downloaded by the app. Ghidriff (GPL-3.0) stays a separate, unmodified process. The tested combination is Python 3.12.10, Ghidra 12.0.4, Temurin Java 25 and Ghidriff revision `4f5d895fcbb1eacd65efd81145922c15bb7e741d` (README, `docs/windows.md`). Other combinations may work but are not claimed.

**Setup dialog** (toolbar **Setup**, tab "Backend and desktop"). Fields: external Python executable (the backend's `python.exe`, never `PatchTrace.exe`), Ghidra install directory (the unpacked root containing `Ghidra/application.properties`), optional private Java home, comparison timeout (default 3600 s, range 10 to 86400), code font size (8 to 28), interpretation context budget, synchronized scrolling, and the symbol-server opt-in (off by default). Buttons: **Find existing installations**, **Install offline backend ZIP...**, **Diagnose dependencies**, **Save setup**. Diagnosis checks paths, versions and Java presence; it is not proof that a full comparison works.

**Discovery** (`src/patchtrace/runtime_discovery.py`) is read-only and bounded. It never executes Python, Ghidra, Java or pip, never downloads, and does not follow symlinks. Precedence, highest first: explicit hint, the bundle next to the executable, a per-user installed runtime, anything else found.

| Source | Candidate |
|---|---|
| `PATCHTRACE_BACKEND_PYTHON` | backend Python (explicit tier) |
| `GHIDRA_INSTALL_DIR` | Ghidra root (explicit tier) |
| `<exe dir>/backend` (or `PATCHTRACE_BUNDLE_DIR`) | bundled Python and Ghidra |
| `%LOCALAPPDATA%\PatchTrace-backend\Scripts\python.exe` | per-user backend venv |
| `%LOCALAPPDATA%\PatchTrace\runtimes\<id>\...` | imported offline runtimes |
| `~/.local/share/patchtrace/runtimes/<id>/payload/...` (POSIX) | imported runtimes |
| `Downloads`, `Program Files`, `C:\Tools` (one level, `ghidra_*` names, at most 64 entries per root) | Ghidra roots |
| `PATCHTRACE_BINDIFF`, `%PROGRAMFILES%\BinDiff\bin\bindiff.exe`, `/opt/bindiff/bin/bindiff` | BinDiff (pre-fill only; the probe decides) |

A single unique candidate pre-fills an empty field; several candidates require you to choose with **Browse**. A manually configured path is kept. Optional tools take explicit paths: `--rz-diff`, `--bindiff` / `PATCHTRACE_BINDIFF`, and for intel-tools `--capa`/`PATCHTRACE_CAPA`, `--floss`/`PATCHTRACE_FLOSS`, `--diec`/`PATCHTRACE_DIEC` (plus `PATCHTRACE_DIEC_DB`, `PATCHTRACE_DIEC_LIB`, `PATCHTRACE_CAPA_RULES`, `PATCHTRACE_CAPA_SIGS`). BinDiff is never found through `PATH` and never bundled. See [12](12-evidence-and-engines.md).

Manual backend install (Windows), condensed from `docs/windows.md`:

```powershell
py -3.12 -m venv "$env:LOCALAPPDATA\PatchTrace-backend"
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m pip install "ghidriff @ git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d"
$env:GHIDRA_INSTALL_DIR = 'C:\Tools\ghidra_12.0.4_PUBLIC'
& "$env:LOCALAPPDATA\PatchTrace-backend\Scripts\python.exe" -m ghidriff --help
```

Restart PatchTrace after changing Java settings so it inherits the environment.

## What "the offline bundle" is

Two separate things share the word "offline", and neither is a finished product yet.

1. **Offline backend ZIP importer (built).** **Setup > Install offline backend ZIP...** consumes a prepared archive (`manifest.json` plus `payload/`), verifies the ZIP and every file SHA-256 without running anything or contacting a site, and installs atomically under `%LOCALAPPDATA%\PatchTrace\runtimes\<runtime-id>\payload\`. It works on synthetic fixtures. **No official runtime archive has been produced or accepted.** Paste an independently trusted ZIP SHA-256 first; the manifest's own hashes detect corruption but are not a signature. Guide: [offline backend](../offline-backend.md), spec SPEC-06.
2. **Zero-download "full" package (builder merged, not published).** A `-full` archive would carry `backend/` (private Python 3.12, JDK, Ghidra 12.0.4, pinned Ghidriff) next to the executable, described by `backend/manifest.json`. `tools/build_backend_bundle.py`, `.github/workflows/backend-bundle.yml` and `tools/bundle_acceptance.py` exist. As of this guide, `tools/backend_pin.json` still has a `placeholder` entry for `python-windows` (the other components are pinned), and the disconnected-machine acceptance run has not passed. Do not treat any package as air-gap verified until a release note links that run. See [26](../internals/26-packaging-and-bundle.md).

If a `backend/` folder is present, these CLI checks exist today (see [16](16-cli-reference.md)): `backend status` (fast file check, starts no process), `backend verify [--full]`, `backend selftest --older A --newer B --expect-function NAME`, `backend diagnose`. Without a bundle `backend status` exits 4.

For a true air gap, enforce it with operating-system firewall rules. PatchTrace settings do not isolate Ghidra or Java ([17](17-privacy-and-network.md)).

## Where PatchTrace keeps things

| Item | Windows | Linux |
|---|---|---|
| Settings | registry `HKCU\Software\PatchTrace\PatchTrace` | `~/.config/PatchTrace/PatchTrace.conf` |
| Analysis profiles | `%APPDATA%\PatchTrace\profiles\` | `$XDG_CONFIG_HOME/PatchTrace/profiles/` |
| Imported runtimes | `%LOCALAPPDATA%\PatchTrace\runtimes\` | `~/.local/share/patchtrace/runtimes/` |
| Bundled-runtime scratch | `%LOCALAPPDATA%\PatchTrace\work` | `~/.local/state/patchtrace/work` |
| Projects | wherever you created them | same |

Source: [install](../install.md) (uninstall table) and `runtime_discovery.bundle_work_dir`. Next: [11 Compare workflow](11-workflow-compare.md).
