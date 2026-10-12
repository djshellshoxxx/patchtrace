# SPEC-06: Verified offline backend bundle and installer
Status: implementation contract, 2026-10-11. Scope: PatchTrace Windows x64 beta.

## 1. Outcome and exclusions

A user with an air-gapped Windows 11 x64 computer, the portable PatchTrace desktop ZIP and a previously assembled, trustworthy PatchTrace offline backend ZIP shall install **without Python, pip, Git, Internet access, machine-wide PATH edits, environment settings, elevation or Docker**. The installed bundle contains a ready-to-run private Python interpreter with ghidriff/pyghidra/JPype and dependencies, an extracted compatible Ghidra tree, and a private JDK. Existing projects stay untouched. The desktop remains usable without a backend. The user explicitly chooses a local archive and the runtime installs under a dedicated per-user versioned directory.

**Important phase boundary:** this task delivers the secure offline *bundle consumer/installer*, initial desktop integration, and a **producer tool** for a preassembled runtime. No official prebuilt full runtime is being advertised until a real relocatable Python/Java/Ghidra/Ghidriff payload has been built, license-audited, hashed and tested on a clean Windows machine with network disabled. A copied venv is NOT presumed portable.

## 2. Version/dependency contract and supply chain

Tested comparison stack in existing CI: CPython 3.12.10, Ghidra 12.0.4, Temurin JDK 25, ghidriff git SHA `4f5d895fcbb1eacd65efd81145922c15bb7e741d`. Record all exact versions/build revisions and wheel/tree licenses in shipped provenance. The Ghidriff dependency's GPL-3.0 license and notices must accompany redistribution. Ghidra is Apache-2.0; Java distributors have their own licensing. Do not bundle source-built executables until legal and security notices are reviewed. A PyInstaller Qt Python interpreter is not pip-installable and must never be selected as the analysis runtime.

For producer: stage relocatable private CPython (the official Windows embeddable runtime may be used with app-vendored compatible site-packages and explicit `._pth` configuration, **never pip install at user runtime**), Ghidra and JDK into payload; include the exact package wheels/extensions/runtime DLLs, all relevant third-party notices, provenance, and tested hash inventory. Do not copy a Windows `venv` verbatim and assume it relocates. Producer must not download or execute binaries, and must not invent compatibility; native packaging acceptance is separate.

The archive SHA-256 supplied via a release checksum or trusted out-of-band channel establishes **authenticity only when that digest itself is trusted**. Internal manifest digests establish accidental corruption/tampering relative to the manifest, not the bundle's origin. The user supplies optional expected SHA-256 at install; Setup warns that a self-consistent archive without a trusted external digest cannot prove origin. There is no silent remote fetch or auto-update.

## 3. Archive format and schema

ZIP (stored or deflated) with **one** UTF-8 `manifest.json` at archive root and file-only entries beneath `payload/`. No directory/empty-name entries. Manifest version exactly 1:

```json
{
  "format": "patchtrace-offline-runtime",
  "schema_version": 1,
  "runtime_id": "ghidra-12.0.4-ghidriff-4f5d895-windows-amd64",
  "platform": "windows",
  "architecture": "amd64",
  "python": "python/python.exe",
  "ghidra": "ghidra",
  "java": "jdk",
  "versions": {
    "python": "3.12.10",
    "ghidra": "12.0.4",
    "jdk": "25",
    "ghidriff_revision": "4f5d895fcbb1eacd65efd81145922c15bb7e741d"
  },
  "files": [
    {"path": "python/python.exe", "size": 123, "sha256": "<64-lowercase-hex>"},
    {"path": "ghidra/Ghidra/application.properties", "size": 123, "sha256": "<64-lowercase-hex>"},
    {"path": "jdk/bin/java.exe", "size": 123, "sha256": "<64-lowercase-hex>"},
    {"path": "LICENSES/NOTICE.txt", "size": 123, "sha256": "<64-lowercase-hex>"}
  ]
}
```

Each `files[].path` is **relative to payload**, not to archive root. Required markers are `python` executable, Ghidra properties, JDK Java executable, and `LICENSES/NOTICE.txt`; markers must be inventoried like all other files. No wildcard, scripts, hooks, remote URLs, post-install commands, interpreter `venv` recreation or implicit downloads. Exact key sets; wrong schema, extra unexpected file, duplicate key or path, duplicate ZIP name, malformed hash/size/version/platform/arch are rejected. Manifest itself at most 4 MiB, runtime total at most 8 GiB uncompressed, any single member at most 2 GiB, at most 60,000 file members; manifest file count exact, sum size exact, no integer bools, no nonfinite JSON, no partial whitelist. Detect path collisions with Windows `casefold()` and Unicode NFC. Reject `..`, `.`, empty segments, backslashes, NUL/control characters, drive/absolute/UNC paths, colons/ADS, Windows device filenames including extensions (CON, PRN, AUX, NUL, COM1–9, LPT1–9), trailing spaces/dots, and ZIP symlink/special-file modes. Reject ZIP compression types other than stored/deflated, and unreasonable compression inflation (>200x for compressed nonempty members >1 KiB). Do not trust ZIP metadata size alone: count actual decompressed bytes and stream-SHA-256 to verify every entry.

The installed directory will contain `manifest.json`, `payload/python/...`, `payload/ghidra/...`, `payload/jdk/...`. This prevents collision with an existing manually configured Python backend; runtime discovery will learn this layout.

## 4. Public pure-Python modules and contracts

`offline_bundle.py` (no Qt) provides frozen data classes:
- `OfflineBundlePlan`: archive path and archive digest, strict manifest, runtime ID, expected file bytes, file count, installed Python/Ghidra/JDK relative paths; no methods execute software.
- `InstalledRuntime`: runtime root, absolute Python exe, Ghidra root, JDK root, manifest and archive SHA.
- `OfflineBundleError(ValueError)`: stable error taxonomy `PT-OFFLINE: ...`.
- `inspect_offline_bundle(path, *, expected_sha256=None, cancel=None) -> OfflineBundlePlan`: bounded, read-only ZIP parser, digest and complete-file verification. No download/execution.
- `install_offline_bundle(plan, runtimes_root, *, cancel=None, event=None) -> InstalledRuntime`: verify archive again to close path/replace race; stage privately next to destination; perform the same strict byte/hash verification while streaming extraction; atomic publish; report progress; on failure/cancel leave previous installs intact; no overwrite of an existing runtime ID.
- `build_offline_bundle(source_payload, manifest_metadata, destination)` producer (separate `tools/make_offline_bundle.py`): deterministic sorted inventory ZIP, source validated using same path policy, stages output and atomic publishes only after complete; never executes/downloads. Producer is a packager, not a dependency resolver.

`runtime_discovery.py` remains independent and discovers `runtimes/<runtime_id>/payload/python/python.exe`, `payload/ghidra` in addition to manual/current candidates. Limit depth to this exact known layout; no recursive search. Detection alone is never considered compatibility acceptance.

`backend.BackendConfig` grows `java_home: str = ''` with default preserving existing callers. If set, validate absolute JDK root and `bin/java.exe` on Windows (or `bin/java` on POSIX); inject **child-only** `JAVA_HOME` and JDK `bin` prepended to `PATH`. Never modify parent process, global PATH, registry, or machine environment. Existing configured Java still works when field is empty.

## 5. UI transaction

Setup dialog includes **Install offline backend ZIP…**. Only a user click opens a local file picker. Show filename, warning that manifest checksums are not an independent publisher signature, optional external expected SHA-256, version/runtime ID, size/space, license/notice summary. Explicit confirmation before writing. Installer runs in an existing cancellable `Worker(QThread)` with text/progress updates (no GUI freeze). A running installation disables editing/closing and the Install action; Cancel stops between bounded I/O chunks and cleans staging. On success fill Python/Ghidra/JDK fields, display `Installed; run Diagnose dependencies, then Save setup`; on Setup Save persist only nonsecret paths. On rejected, failed or cancelled installs do not change configured paths. No automatic remote requests or post-install launch; optional user-click `Diagnose dependencies` probes installed runtime separately.

`MainWindow.backend_config` forwards the saved JDK root; source GUI uses same BackendConfig. Keep advanced manual controls and prior settings keys backwards compatible.

**Do not change user projects, raw run histories, manual symbol lookup policy or provider credentials**.

## 6. Install-state and security invariants

Destination default per-user `%LOCALAPPDATA%/PatchTrace/runtimes`; explicitly reject root/system directories, relative destinations, installed target symlinks and symlinked ancestor directories. For test injection allow absolute temporary roots. Use `mkdir(exist_ok=True)` only on the validated runtimes container, never create a partially published target. Re-check `plan` identity/digest/size before extraction (no trust in a potentially swapped ZIP). Use an exclusive per-target publish lock with O_EXCL or mkdir; fail clearly if concurrent/stale lock and never steal/delete another process's lock. Stage under the same parent/volume with unpredictable UUID, `os.replace` to new absent final destination. If final target exists: return clear `already installed` rather than overwriting files. Stage cleanup in finally; if antivirus locks files, report incomplete cleanup with exact staging directory. Cancellation propagated as PT-CANCEL and does not publish partially installed runtimes. No shell, subprocess, pip, network APIs, registry writes or elevation in installer. Delete only the freshly created stage for current invocation. Never trust paths/links inside archives. Avoid race of manifest mutation by comparing SHA during initial and extraction phases. Validate free space preflight conservatively; retry failed archives manually, no silent automatic retry.

Power loss may strand a staging directory; document manual recovery and avoid auto-removing unknown stages.

## 7. Acceptance matrix

A) unit: manifest valid/invalid variants, casefold/Unicode alias, traversal/backslash/drive/ADS/device names, symlinks/special modes, forged hashes, missing/extraneous file, duplicate entries, ZIP bombs/limits, non-Windows labels, UTF-8 JSON duplicates, blank/truncated/malformed archives.

B) filesystems: atomic commit; partial cleanup on hash mismatch, storage failure, cancel, pre-existing destination, repeated install, concurrent lock, symlink root, source ZIP changed after inspection. Existing installs unchanged on failure. No reads/writes outside intended locations (except reading selected archive). Install with spaces/unicode.

C) Qt: preview and explicit confirm; import success auto-prefill; cancelling/close while Worker active; manual settings retained on failure; Java setting persisted in Setup and injected only into subprocess environment. GUI responsive.

D) CI: Linux and Windows pytest, Ruff, frozen Windows self-test and package build, native Windows Ghidriff fixture, offline smoke test **on actual complete portable bundle** in fresh Windows machine with networking denied. The final offline end-to-end gate remains unverified until real runtime bundle artifact exists. Test must verify `python -m ghidriff --help`, correct JDK and known patch analysis from extracted package, no outbound connections, and preserved logs/case; CI fixtures with stub .exe files prove only installer plumbing.

E) release: place full bundle ZIP, standalone PatchTrace ZIP, SHA-256 sidecar and license/source notices in GitHub Releases, only after supply-chain/legal review. No auto-ship or claims of verified complete offline release before gate D.

## 8. Staged delivery

M1 detailed contract, schema example, threat model and builder spec checked into docs (this file). M2 pure ZIP validator + tests. M3 atomic installer + tests. M4 GUI and backend/JDK injection, discovery and tests. M5 offline packager and fake bundle acceptance. M6 real Windows full offline bundle creation and clean air-gapped QA (blocked until real dependency payload is assembled). Maintain separate PR and merge only after standard CI checks; do not overwrite other contributors.
