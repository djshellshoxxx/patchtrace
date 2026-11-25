# 26. Packaging, release gate and the offline bundle

How a PatchTrace package is built (PyInstaller), checked (frozen smoke), published (release gate) and how the zero-download backend bundle is designed, verified and accepted. User view: [10](../guide/10-getting-started.md). Procedures: `docs/windows.md`, `docs/linux.md`, `docs/release-process.md`, `docs/offline-backend.md`. Spec: `docs/specs/windows-acceptance-and-milestone-builds.md`, SPEC-06 `offline-backend-installer.md`, `docs/specs/program-e/BUNDLE-integration-plan.md`. Previous: [25](25-intelligence-kb-kev-yara-capa.md). Next: [27](27-testing-and-ci.md).

## Constraints that shape the build

- **PyInstaller cannot cross-compile**: the Windows package is built on Windows (CI `windows-latest`), the Linux package on Linux (CI `ubuntu-22.04`, older glibc baseline). `AGENTS.md`: "Windows packaging must run on Windows."
- Standalone includes Python and Qt (PySide6 6.12.0). **Ghidra, Java and Ghidriff are external**, and so are all optional tools (BinDiff, rizin, capa, FLOSS, diec), unless a *full* bundle is attached.
- **Keep Qt DLLs replaceable**: one-folder (`onedir`) distribution, never one-file; LGPL notices ship (`qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt`).
- Windows users can extract the unsigned portable ZIP or install the unsigned NSIS package under their own account. Both work without elevation. See [Windows setup and packaging](../windows.md).
- The desktop pins `PySide6==6.12.0`, `shiboken6==6.12.0`, `pydantic==2.14.2` and `protobuf==7.36.2`. The build requires the upb protobuf implementation and uses `pyinstaller==6.22.3`. The `search` extra pins `rapidfuzz==3.14.6`. The `rules` extra pins `yara-x==1.21.0` and `iced-x86==1.21.0`. The `calibration-dev` extra is for development. The desktop QA job installs dependencies with `--only-binary=:all:`. See [project dependencies](../../pyproject.toml).

## The build scripts

| Script | Output |
|---|---|
| `tools/build_windows.py` | `dist/PatchTrace/` and `dist/PatchTrace-0.1.0-windows-x64.zip` + `.sha256` (LF-only sidecar bytes) |
| `tools/package_windows_installer.py` | Wraps the desktop build using NSIS 3.13 and produces `PatchTrace-Windows-x64-Setup.exe` and its SHA-256 sidecar. |
| `tools/build_linux.py` | `dist/PatchTrace-0.1.0-linux-x86_64.tar.gz` + `.sha256` (preserves the executable bit; tar filter normalises modes) |
| `tools/desktop_entry.py` | the PyInstaller entry: calls `patchtrace.__main__.main` |
| `tools/pyinstaller_hooks/` | hooks for `PySide6.QtGui`, `patchtrace.cli_commands`, `patchtrace.optional_deps`, `patchtrace.secondary.binexport_proto`, `patchtrace.unified`, `patchtrace.unified.extract` |

What a build does (Windows and Linux share helpers from `build_linux.py`): refuses to proceed without the pinned protobuf on upb; excludes `QtWebEngine*` and `QtPdf*`; collects submodules so guarded optional imports and the discovered `cli_commands/*.py` verbs are frozen (`optional_deps.py` writes explicit top-level guarded imports because PyInstaller's static scan must see them); copies licences, docs, specs and the required notices (`REQUIRED_NOTICES`: Qt LGPL, protobuf, BinExport2 licence/proto/provenance, BinDiff v8 notice for the MD index) and **refuses to publish without them**; ships the Ghidra extractor script `patchtrace/unified/extract/ghidra_script.py` as a data file because it runs in the user's external Python; writes `dependency-versions.json`; archives and hashes. `tools/` itself is dev-only and not packaged.

The version string is the literal `0.1.0` in `pyproject.toml`, the build scripts and the archive names; the release tag `v0.1.0-beta.N` uses the CI run counter, so N rises by more than one between tags ([version history](../version-history.md)).

## Frozen smoke (`tools/frozen_smoke.py`)

Run by the Windows CI step against `dist/PatchTrace/PatchTrace.exe` (and by `tests/test_acceptance_smoke.py` with `python -m patchtrace` as the launcher, which proves the logic everywhere but nothing about the frozen package). Checks (each PASS/FAIL, any FAIL exits 1): A1 every command answers `--help` with `usage:`; A2 unknown command exits 2 without a traceback; A3 missing project exits 2, no Qt; A4 `--self-test` exits 0 and removes its temp directory (frozen only); A5 `rank <sample> --json --dry-run` exit 0 or 4 with exactly one JSON document; A10 path cases (spaces, Unicode, OneDrive-style, long) give the same ranking or an actionable exit-2/3 message; A6s a three-build series via the CLI with *imported synthetic* Ghidriff results; B1/B2 `secondary binexport-check` through the real worker route with the Job Object memory cap, and rejection of JSON lookalikes; C1-C4 `intelligence import`/`explain` on a synthetic CSAF fixture; U1 the Ghidra extractor script is in the frozen package exactly once and byte-identical to source, with the BinDiff notice; U2 `unified --help` and `unified _worker --self-check` read the packaged script through `importlib.resources`. The self-test (`PanelHost.self_check`) proves every panel manifest module imports in the frozen process. Linux has `linux-smoke` on Ubuntu 22.04 and 24.04 (offscreen and Xvfb/xcb) plus a report of unresolved shared libraries of the bundled Qt platform plugins.

## Release gate and publication

The desktop QA workflow builds and tests on Ubuntu and Windows, repeats the Qt tests, validates the downloaded Windows packages in `windows-validate`, and exercises the downloaded Linux archive on Ubuntu 22.04 and 24.04. See [release process](../release-process.md) for the job dependencies and publication conditions.

`tools/release_gate.py` calculates the prerelease cadence. A successful gate job can still leave publication disabled. On a main-branch push, `[no release]` in the actual head commit message suppresses publication while the build and test jobs run. `[no deploy]` separately suppresses Pages deployment on that push. Pull requests and manual desktop QA runs do not publish. See [integration without publication](../release-process.md#integrate-without-publishing).

## The offline bundle: two mechanisms

**1. Importable runtime ZIP** (`offline_bundle.py`, SPEC-06; built, no official archive exists). Layout: top-level `manifest.json` (strict inventory with per-file SHA-256) and `payload/{python, ghidra, jdk, LICENSES}`. The importer inspects the ZIP with checksum-bounded reads, verifies every file hash without executing anything, rejects traversal/links/unexpected files, and extracts transactionally into `%LOCALAPPDATA%\PatchTrace\runtimes\<runtime-id>\payload\` (staging directory, lock, atomic rename; cancellation and power loss leave earlier installs untouched). Producer: `tools/make_offline_bundle.py`. A self-consistent manifest proves integrity, not authenticity.

**2. Zero-download "full" package** (`backend_bundle.py`, `runtime_discovery.py`, `tools/build_backend_bundle.py`; builder and verifier built, nothing published). The package gains `backend/manifest.json` and `backend/payload/{python,ghidra,jdk,LICENSES,SOURCES}` next to the executable (or `PATCHTRACE_BUNDLE_DIR`).
- *Pins.* The [backend pin file](../../tools/backend_pin.json) records CPython 3.12.10, Ghidra 12.0.4, Temurin 21.0.12.1+1 and the Ghidriff revision. Windows CPython has status `pinned` and digest source `sigstore-verified`. Run `python tools/check_backend_pin.py --release` to check the pin metadata and recorded license policy before building.
- *Build* (`build_backend_bundle.py build`): fetch and verify each component (downloads happen only in the builder, never in the app), assemble `backend/payload`, install hash-locked wheels with `pip install --target` (wheels only, `--no-index`), build Ghidriff from the exact source tarball and byte-compare, apply strip rules, precompile, write notices and `THIRD-PARTY.json`, check path length (`MAX_BACKEND_PATH` 150), mode and size gates (`FULL_SIZE_LIMIT` 1.9 GiB, release assets cap 2 GiB), and split when asked. Archive names are exact: `PatchTrace-<v>-windows-x64-full.zip`, `PatchTrace-<v>-linux-x86_64-full.tar.gz` (tar.gz because ZIP loses Unix mode bits).
- *Runtime* (`backend_bundle.py`): `find_bundled_runtime`, `verify_bundle(mode='fast'|'full')` returning `PT-BUNDLE-*` problems (`MISSING`, `MANIFEST`, `PLATFORM`, `SIZE`, `EXTRA`, `HASH`, `LINK`, `WORKDIR`, `PIN-MISMATCH`, `LICENSE`, `SIZE-LIMIT`), a verified-cache record, never executing anything. `bundle_config` switches `BackendConfig` to isolated bundle mode when the settings are empty or already equal the bundle's paths; an explicit different path always wins. In bundle mode the child runs with `-I`, a forced restricted environment, a private `JAVA_HOME`, and scratch under the per-user work directory (`bundle_work_dir`), never inside the install tree.
- *Acceptance* (`tools/bundle_acceptance.py`, workflow `backend-bundle.yml`): scrub the environment, digest `backend/`, make it read-only, positive-control a socket probe, block the network (Linux `unshare --net`; Windows per-program outbound firewall rules), require the same probe now to fail, run `backend verify --full`, `backend selftest` and a real Ghidriff comparison under the block while sampling connections, then re-digest and require equality. The OS-level steps run for real only in CI on a release artifact; locally only the pure helpers and a dry-run are covered.
- *Release evidence.* Tag pushes can build and test without publishing. Attaching full assets requires an accepted build and explicit prerelease publication. The pin file records owner approval for Ghidriff and the Temurin JDK under the project’s distribution policy. Preserve the notices, component inventory and source offers from the actual package. Record the exact archive digest and disconnected acceptance results on each supported platform before claiming an air-gapped installation. See the [offline guide](../offline-backend.md) for the separate importable ZIP.

## GitHub Pages site

`site/` plus `tools/site/` and `pages.yml` build a static site (dev tooling, never shipped). `pages.yml` was invalid YAML until PR #50; `tests/test_workflows.py` now guards every workflow for plain scalars containing `: `. The first Pages deployment awaits owner inputs (logo, donation address, Settings > Pages source).

## Build sequence (what `build_linux.py` and `build_windows.py` do, in order)

1. Refuse to run on the wrong platform (`PyInstaller does not cross-compile`).
2. `require_upb_protobuf()`: protobuf must be exactly 7.36.2 with the upb backend, otherwise stop.
3. Run PyInstaller `--onedir --name PatchTrace` with the project hooks, `--paths src`, and the `QtWebEngine*`/`QtPdf*` modules excluded. Windows adds `--console --hide-console hide-early` so headless commands return output and exit codes to the invoking shell while a double-click hides the console.
4. Copy `LICENSE` (as `LICENSE.txt`), `README.md` and `docs/` into the package.
5. Verify that every required third-party notice exists under `third_party/notices/` (Qt and PySide LGPL/GPL texts, OpenSSL 3.0.16 and 3.5.5, PyInstaller `COPYING`, protobuf, BinExport2, BinDiff v8) and copy them to `licenses/upstream/`; **missing notice means no distribution**.
6. Write `dependency-versions.json` and copy each bundled distribution’s license files. The optional distribution inventory includes `rapidfuzz`, `yara-x` and `iced-x86` when installed.
7. Inventory the package (`file-inventory.json`) and fail if unused WebEngine/PDF/Quick/QML libraries were collected, if `google/_upb/_message` is missing (silent pure-Python protobuf fallback, 85x memory), or if the packaged extractor script differs from the source copy.
8. Run the frozen executable: `--self-test`, then `rank --help`; fail on any non-zero exit.
9. Archive: Windows zip, Linux `write_tar_gz` (executable bits normalised), write the `.sha256` sidecar as bytes (LF only; a CRLF sidecar was an audit finding).
10. With `--full --backend-payload DIR`: `attach_backend` copies the verified backend payload into the package, writes build provenance, checks path length, Windows name rules, executable bits (`EXEC_PATTERNS`), writes `SHA256SUMS`, builds the `-full` archive, and `check_archive_size` enforces the size limit.

## Package contents (onedir)

```
PatchTrace/
  PatchTrace(.exe)           launcher; no args opens the GUI, any other first arg is a CLI verb
  _internal/                 Python runtime, PySide6/Qt (replaceable DLLs), pydantic, protobuf (upb), patchtrace
  LICENSE.txt  README.md  docs/
  licenses/                  Python-LICENSE.txt, per-distribution notices, upstream/ (Qt, OpenSSL, BinExport2, BinDiff v8, ...)
  dependency-versions.json   file-inventory.json
  backend/                   only in a full package: manifest.json + payload/{python,ghidra,jdk,LICENSES,SOURCES}
```

## Environment variables read by packaging and runtime discovery

| Variable | Used by | Meaning |
|---|---|---|
| `PATCHTRACE_BUNDLE_DIR` | `backend_bundle` | directory that contains `backend/` instead of the executable's directory |
| `PATCHTRACE_BACKEND_PYTHON` | `runtime_discovery` | explicit backend Python (highest precedence tier) |
| `GHIDRA_INSTALL_DIR` | `runtime_discovery`, Ghidriff | explicit Ghidra root |
| `PATCHTRACE_BINDIFF`, `PATCHTRACE_BINDIFF_EXPECTED_VERSION` | `secondary/`, `runtime_discovery` | BinDiff executable and expected version |
| `PATCHTRACE_CAPA`, `_FLOSS`, `_DIEC`, `_DIEC_DB`, `_DIEC_LIB`, `_CAPA_RULES`, `_CAPA_SIGS` | `intelligence/tools/cli.py` | tool executables and data |
| `PATCHTRACE_LIVE_STATUS_DIR`, `PATCHTRACE_REQUIRE_LIVE_BINDIFF` | tests | live-lane status files |
| `PATCHTRACE_CHILD_ENV=inherit` | `backend.py` | overrides the restricted child environment when `restrict_env` is on (never in bundle mode) |
| `QT_QPA_PLATFORM` | Qt | `offscreen` for headless self-test and tests |

## Checking a package by hand

```bash
sha256sum -c PatchTrace-0.1.0-linux-x86_64.tar.gz.sha256
tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz
QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test      # prints the optional-dependency summary, exits 0
./PatchTrace/PatchTrace rank --help                                 # CLI inside the frozen process
./PatchTrace/PatchTrace backend status                              # exit 4 on a lite package
python tools/frozen_smoke.py ./PatchTrace/PatchTrace                # full frozen checks (the Windows CI step uses PatchTrace.exe)
```

On Windows replace the paths with `dist\PatchTrace\PatchTrace.exe`; `Get-FileHash` verifies the zip.
