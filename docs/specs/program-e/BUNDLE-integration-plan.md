# BUNDLE: one-download full build (app + private Python/JDK/Ghidra/Ghidriff payload)

Status: plan for build, written 2026-10-14 (Program E, owner priority). Documents only. Extends SPEC-06 (`docs/specs/offline-backend-installer.md`), whose phase boundary ("no full runtime advertised until built, audited, hashed, tested offline") this plan closes. Independent of GHR (symbol launcher); compatible with it (section 4).

Source-access note (2026-10-14): `www.python.org`, `docs.python.org`, `api.adoptium.net` were unreachable (DNS/proxy 403); the GitHub API for non-attached repositories was refused by policy, so release asset lists (sizes, digests) of Adoptium and python-build-standalone could not be read. Those facts are `[unverified]`; the builder resolves them in slice B1 and records them in `tools/backend_pin.json`.

## 1. Verdict and scope

Build: `PatchTrace-<ver>-windows-x64-full.zip` and `PatchTrace-<ver>-linux-x86_64-full.tar.gz`. Each is the existing lite one-folder app plus a `backend/` directory shaped exactly like an installed SPEC-06 runtime (`backend/manifest.json` + `backend/payload/{python,ghidra,jdk,LICENSES,SOURCES}`), so one validator, one hash inventory and one discovery rule serve the full download, the importer ZIP and the per-user install. The importer ZIP is the same payload re-packed (updates, air-gap); the lite build stays on every merge; the full build runs on tags, `workflow_dispatch` and a weekly pin-drift schedule (no release on the schedule).

Decisions: JDK **21** (Ghidra's documented requirement), Python 3.12.10 (Windows: official embeddable zip + hash-locked wheels-only site-packages; Linux: python-build-standalone), pyghidra **3.0.2** (the version in the Ghidra 12.0.4 tag, satisfies ghidriff `>=3.0.0,<4`), JPype1 1.5.2, Ghidriff built as an unmodified wheel from the pinned git SHA's exact source tarball, run only as a separate process (`python -I -m ghidriff`). Isolation: child env allowlist + `JAVA_HOME_OVERRIDE` + per-user writable dirs; acceptance on a **read-only install tree** with scrubbed PATH and network denied.

Not built: runtime downloads or `pip` at the user's machine; auto-update; a signed installer (WIN policy track); macOS; jlink-trimmed JDK or processor stripping in v1; splitting assets (only if a measured zip exceeds 1.9 GiB); any claim of "air-gapped" without a linked CI run.

## 2. Sources and facts

| claim | source | retrieved | confidence |
|---|---|---|---|
| Ghidra needs "Java 21 64-bit Runtime and Development Kit (JDK)"; Temurin and Corretto named as free LTS; PyGhidra supports Python 3.9 to 3.13; Windows 10 1809+ and Linux supported | https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/GhidraDocs/GettingStarted.md | 2026-10-14 | high |
| Ghidra_12.0.4_build release, PUBLIC 20260303, zip digest `c3b45866...a120` (already pinned in live-backend.yml); asset list and size not loadable | https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.4_build | 2026-10-14 | digest high, size [unverified] (history: ~0.4-0.5 GB zip, ~1.2 GB extracted) |
| Ghidra licence Apache-2.0 (LICENSE file); NOTICE and `licenses/` presence in the distribution not confirmed | https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE | 2026-10-14 | licence high, layout [unverified] |
| pyghidra in the 12.0.4 tag is `3.0.2`; `MINIMUM_GHIDRA_VERSION = "12.0"`; deps `Jpype1==1.5.2`, `packaging`; requires Python `>=3.9` | https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/__init__.py and `.../pyproject.toml` | 2026-10-14 | high |
| pyghidra launcher: `JAVA_HOME_OVERRIDE` env wins; otherwise it runs the literal command `java -cp <launch_support> LaunchSupport <install> -jdk_home -save` (so `java` must resolve through PATH), then sets `JAVA_HOME` and calls `jpype.startJVM(None, ...)`; install dir = arg, `GHIDRA_INSTALL_DIR`, else `lastrun` file under `XDG_CONFIG_HOME`/`%APPDATA%`/`~/.config`; compiles its Java plugin with `javac` when the jar is missing (needs a JDK, not a JRE) into the user settings dir `Extensions`; lock file in system temp | https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/launcher.py (fetch tool summarised; re-read in B1) | 2026-10-14 | medium |
| PyPI pyghidra: 3.1.0 (2026-05-14), 3.0.2 (2026-01-15), pure wheel `pyghidra-3.1.0-py3-none-any.whl` sha256 `62d76e4c...ac94` | https://pypi.org/pypi/pyghidra/json | 2026-10-14 | high |
| PyPI jpype1 1.5.2 wheels: `cp312-cp312-win_amd64` sha256 `c7b1c2d7...ff2d`, `manylinux_2_17_x86_64` sha256 `b5b1fb2b...6f`; Apache-2.0 | https://pypi.org/pypi/jpype1/1.5.2/json | 2026-10-14 | high |
| **No PyPI release contains the pinned Ghidriff**: PyPI latest is 1.0.0 (2025-07-04, requires `pyghidra>=2.0.0`, GPL-3.0, wheel + sdist). The pinned commit `4f5d895` (merge of PR #141 "ghidra12-dev-refresh", 2026-05-11) also reports `__version__ = '1.0.0'` but requires `pyghidra>=3.0.0,<4`, `mdutils==1.6.0`, Python `>=3.10`, entry `ghidriff = ghidriff.__main__:main`, `license = GPL-3.0 license` | https://pypi.org/pypi/ghidriff/json ; https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/setup.cfg ; `.../ghidriff/__init__.py` ; https://github.com/clearbluejar/ghidriff/commits/4f5d895fcbb1eacd65efd81145922c15bb7e741d | 2026-10-14 | high; whether PyPI 1.0.0 works with Ghidra 12 [unverified], not used |
| Ghidriff pure Python: build with setuptools from the source tarball into a `py3-none-any` wheel; mdutils 1.6.0 wheel tag and licence | PyPI mdutils JSON (not fetched) | - | [unverified], resolve in B1 |
| Python 3.12.10 is the last 3.12 release with official Windows binaries; embeddable zip `python-3.12.10-embed-amd64.zip` (~10 MB) has `python312._pth`, `python312.zip`, `vcruntime140*.dll`, no pip, no venv/ensurepip; with a `._pth` file the interpreter ignores `PYTHONPATH`, `PYTHONHOME`, registry and user site; paths in `._pth` are relative to the file | https://docs.python.org/3.12/using/windows.html#windows-embeddable ; https://www.python.org/downloads/release/python-31210/ | blocked | [unverified] (SPEC-06 already prescribes this approach) |
| python-build-standalone release `20250409` lists "CPython 3.12.10"; asset names, sizes, glibc baseline, licence files not loadable | https://github.com/astral-sh/python-build-standalone/releases/tag/20250409 | 2026-10-14 | version high, assets [unverified] |
| Temurin 21 latest on the binaries repo page: `jdk-21.0.12.1+1` (published 19 Aug, year not shown); 315 assets; sizes not loadable. Licence GPL-2.0-with-classpath-exception (SPDX `GPL-2.0-only WITH Classpath-exception-2.0`) | https://github.com/adoptium/temurin21-binaries/releases/latest | 2026-10-14 | tag medium, sizes [unverified] (history: ~190 MB zip / ~320 MB extracted on Windows) |
| Ghidra 12.0.4 reads the settings dir from `application.settingsdir` then `XDG_CONFIG_HOME` on every OS (per-run scratch already fixes a persisted-symbol-store failure) | `docs/qa.md` line 40 (this repo, native CI) | 2026-10-14 | high |
| Current CI stack: Python 3.12 (setup-python, 3.12.10 in the recorded run), Temurin 25, Ghidra 12.0.4, Ghidriff by git SHA with **floating** pyghidra/JPype/mdutils (`pip install -e . 'ghidriff @ git+...'`) | `.github/workflows/live-backend.yml`, `docs/qa.md` line 83 | 2026-10-14 | high; resolved wheel versions of that run [unverified] |
| Consumer today: manifest keys exact, `platform=='windows' and architecture=='amd64'`, `python=='python/python.exe'`, required markers 4 files, `versions` exactly 4 keys, ZIP entries 0o100644, limits 60,000 members / 8 GiB / 2 GiB per file, reserved-name and casefold collision rejection | `src/patchtrace/offline_bundle.py` lines 24-45, 146-190, 426-500 | 2026-10-14 | high |
| Discovery today finds `runtimes/<id>/payload/python/python.exe` (Windows only), `payload/ghidra`; never looks next to the executable; `restrict_env` defaults off "until validated natively" | `src/patchtrace/runtime_discovery.py`, `backend.py` lines 63-70, 136-175 | 2026-10-14 | high |

## 3. Standalone baseline versus PatchTrace value

Standalone Ghidriff needs: install JDK 21+, unpack Ghidra, create a venv, `pip install git+...`, set `GHIDRA_INSTALL_DIR`/`JAVA_HOME`, hope the global Ghidra settings are clean. PatchTrace-full adds: nothing to install (extract and run), a **verified** inventory (every file SHA-256, size-checked on each start, fully hashed on first run and on demand), per-run isolated Ghidra settings, a read-only install tree, recorded provenance (versions, hashes, licences, source offer) in every run's settings, and one tested combination instead of a floating one.

Workflows: (1) analyst downloads one file on a locked-down laptop, extracts, compares two builds with no setup; (2) later updates via the existing two-ZIP importer or a new full ZIP; (3) auditor reads `backend/payload/LICENSES/THIRD-PARTY.json` and `backend/manifest.json` and re-verifies with `patchtrace backend verify`.

## 4. Cross-feature links

| Anchor | Direction | Counterpart | Use |
|---|---|---|---|
| runtime id + component versions + manifest SHA-256 in run `settings` (`bundle_id`, `bundle_manifest_sha256`) | emit | RPT2 report export, enrichment `RuntimeFingerprint` (`ghidriff_revision` already present) | A run states exactly which payload produced it; cache key unchanged (versions already keyed) |
| `THIRD-PARTY.json` components + SPDX | emit | WIN release-signing/notice policy, `docs/legal` | Single source for notices; build refuses if a component lacks licence files |
| bundle root next to exe | consume | SPEC-06 installer, GHR launcher | GHR's `ptlaunch.py` is launched by the same bundled interpreter with the same env; `local`/`off` symbol modes work unchanged. `restrict_env` becomes default-on only in bundle mode |
| BinDiff/rz-diff provisioning | none | `tools/provision_bindiff.py` | Separate payloads; not part of this bundle (non-goal) |

## 5. Synergy test

Scenario `full-bundle-offline-known-patch` (synthetic, self-made): the committed `tests/fixtures/old.c`/`new.c` pair (bounds-check in `read_item`). Windows: MSVC-built `old.dll`/`new.dll` as in live-backend.yml. Linux: `gcc -shared -fPIC -O0 -g0 "-D__declspec(x)=" -o old.so old.c` (and new). Using **only** the extracted full artifact: `PatchTrace backend selftest --older old --newer new --expect-function read_item --json` exits 0, reports `modified` match containing `read_item`, `if` in the new decompilation, `bundle.verified=true`, `servers=[]` (no symbol lookups, `--no-symbols`), and no file under `backend/` changed (tree digest before == after, install tree read-only). Combined claim: the lite app alone cannot analyse; plain Ghidriff alone has no verified inventory or isolation; only the bundle gives analysis + provenance with zero external dependency. Test ids: `bundle_acceptance_windows`, `bundle_acceptance_linux`, unit `test_bundle_fast_verify_detects_extra_file`.

## 6. Traps and guards

| Trap | Guard |
|---|---|
| `pyghidra` runs bare `java` from PATH | Child env sets `JAVA_HOME_OVERRIDE` and prepends `jdk/bin`; acceptance PATH contains no java; test asserts `where java` fails before run |
| JDK 25 was the CI-tested JDK; 21 is documented but unexercised here | Acceptance runs on 21; if it fails, B1 flips the pin to 25 (pre-tested in live-backend) and records it; decision never silent |
| Floating pyghidra/JPype/mdutils today | `backend_pin.json` pins every wheel with sha256; install with `--require-hashes --no-deps --only-binary=:all: --target`; B1 cross-checks pyghidra 3.0.2 against the wheel inside Ghidra's `pypkg/dist` if present |
| Windows path rules reject Ghidra/Python/JDK file names (reserved device names with extension, trailing dot, casefold collisions) | B2 adds `--check` inventory dry-run that lists offending paths; strip or rename only after review; **first spike of the whole plan** |
| Path length: Explorer extraction limit 260 | Builder asserts longest relative path under `backend/` <= 150 chars; fail otherwise |
| Mark-of-the-Web / SmartScreen / Defender slowdowns on 40k files | README step "right-click ZIP > Properties > Unblock before extracting" plus `Unblock-File`; `docs/windows.md`; first-run hash pass runs in the existing cancellable Worker |
| Ghidra writes into its install dir or temp, JVM caches | Per-run `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TEMP/TMP/TMPDIR` under a per-user work dir (`%LOCALAPPDATA%\PatchTrace\work`, `~/.local/state/patchtrace/work`); acceptance makes `backend/` read-only (`icacls /deny`, `chmod -R a-w` as non-owner) and compares a before/after tree digest |
| `.pyc` written into site-packages | Precompile at build with `compileall --invalidation-mode unchecked-hash`, include in inventory; env `PYTHONDONTWRITEBYTECODE=1`; `python -I` |
| ZIP extraction loses Unix mode bits (Ghidra natives, `support/*`) on Linux | Linux uses tar.gz; builder applies modes from the Ghidra zip `external_attr` and asserts `+x` on `decompile`, `sleigh*`, `demangler_gnu*`, `support/*`, JDK `bin/*`, python `bin/*` |
| GPL-3.0 Ghidriff in a MIT-licensed distribution | Unmodified, separate process, no import, no linking; aggregate notice in `NOTICE.txt`; exact source tarball in-bundle and as a release asset; wheel's package files byte-compared with the tarball; owner/legal read stays open question 1 |
| JDK GPL-2.0+CE source obligation | Ship `legal/` and a written offer (URL + sha256 of the matching Adoptium source tarball); not bundled for size; legal confirmation open question 2 |
| Stripping docs/OS-natives breaks Ghidra | Only listed safe removals (section 7.4); each removal is gated by the acceptance run; no processor stripping |
| Network "denial" that is not enforced | Positive control: the same socket probe succeeds before the block and fails after; evidence wording "passed with OS network block" only with run link |
| Self-consistent bundle is not authentic | Release sidecar `.sha256`; installer already warns; signing is WIN track |
| Release asset limit 2 GiB | Builder prints size; hard fail >1.9 GiB with "split or fall back to lite + backend ZIP pair" |

## 7. Contracts

### 7.1 `tools/backend_pin.json` (schema `patchtrace-backend-pin/1`; single source of pins)

```json
{"schema":"patchtrace-backend-pin/1","runtime_id_format":"ghidra-{ghidra}-ghidriff-{sha7}-{os}-amd64",
 "components":{
  "python-windows":{"url":"https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip","sha256":"<64hex>","size":0,"spdx":"PSF-2.0","version":"3.12.10"},
  "python-linux":{"url":"https://github.com/astral-sh/python-build-standalone/releases/download/20250409/<asset>","sha256":"<64hex>","size":0,"spdx":"PSF-2.0","version":"3.12.10"},
  "ghidra":{"url":"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip","sha256":"c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120","size":0,"spdx":"Apache-2.0","version":"12.0.4"},
  "jdk-windows":{"url":"<adoptium zip>","sha256":"<64hex>","size":0,"spdx":"GPL-2.0-only WITH Classpath-exception-2.0","version":"21.0.x+y"},
  "jdk-linux":{"url":"<adoptium tar.gz>","sha256":"<64hex>","size":0,"spdx":"GPL-2.0-only WITH Classpath-exception-2.0","version":"21.0.x+y"}},
 "wheels":{"windows":[{"name":"jpype1-1.5.2-cp312-cp312-win_amd64.whl","sha256":"c7b1c2d76d211cab60be16505d32a6b3c9fffc51ce79c68e81a3d48e5effff2d","spdx":"Apache-2.0"}],
           "linux":[{"name":"jpype1-1.5.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl","sha256":"b5b1fb2b430a50f081ea0ee24d19232ae0d03dbfe3dd076ec5f8ae42b30a656f","spdx":"Apache-2.0"}],
           "any":[{"name":"pyghidra-3.0.2-py3-none-any.whl","sha256":"<64hex>"},{"name":"packaging-<v>-py3-none-any.whl","sha256":"<64hex>"},{"name":"mdutils-1.6.0-<tag>.whl","sha256":"<64hex>"}]},
 "ghidriff":{"repo":"https://github.com/clearbluejar/ghidriff","sha":"4f5d895fcbb1eacd65efd81145922c15bb7e741d","spdx":"GPL-3.0-only","spdx_note":"LICENSE file does not say only/or-later; record as GPL-3.0 (unqualified)"},
 "strip":{"ghidra":["docs/**","Extensions/Eclipse/**","**/os/{other-OS}/**"],"jdk":["lib/src.zip","jmods/**"]}}
```
Rules: every download verified by sha256 before use; a mismatch is a hard failure (`PT-BUNDLE-PIN-MISMATCH`). The test `test_pin_schema` rejects non-hex digests, missing SPDX, `http://` URLs, any unpinned wheel. Resolving the `<...>` digests is slice B1 (vendor `.sha256.txt` for Adoptium; python.org MD5 plus own sha256 recorded as trust-on-first-use, stated in the file).

### 7.2 Payload layout and manifest (SPEC-06 schema 1, additive)

Windows `backend/payload/`: `python/` (embeddable files; `python312._pth` = `python312.zip` / `.` / `Lib/site-packages` / `import site`), `python/Lib/site-packages/` (ghidriff, pyghidra, jpype, packaging, mdutils, dist-info), `ghidra/` (renamed from `ghidra_12.0.4_PUBLIC`), `jdk/`, `LICENSES/NOTICE.txt`, `LICENSES/GPL-3.0.txt`, `LICENSES/THIRD-PARTY.json`, `LICENSES/<component>/...`, `SOURCES/ghidriff-4f5d895.tar.gz`, `SOURCES/SOURCE-OFFER.txt`. Linux: `python/` = python-build-standalone `install_only_stripped` tree (`python/bin/python3`, `lib/python3.12/site-packages`), `jdk/bin/java`.

Manifest: the **schema stays exactly as today** (every payload file, including the licence files and source tarball, is in `files[]` with size and sha256; `versions` keeps its 4 keys). Additive changes, all in `offline_bundle.py` (slice B3): accept `platform=='linux'` with `python=='python/bin/python3'` and required markers `jdk/bin/java`, `python/bin/python3`; expose `validate_manifest(data)` publicly; allow the Linux manifest only through the new loader (the Windows importer UI still refuses non-Windows ZIPs). Licence and component data go in `LICENSES/THIRD-PARTY.json` (hashed by the manifest), so old readers of the manifest are unaffected and no key set changes.

### 7.3 `THIRD-PARTY.json` (`patchtrace-third-party/1`, Pydantic `ThirdPartyDoc`, extra=forbid)

`components[]`: `id`, `name`, `version`, `spdx` (string expression), `role` (`runtime|analysis-engine|library|tool`), `upstream_url`, `artifact` `{name, sha256, size, url}`, `license_files` (payload-relative paths, each must be in `files[]`), `source` `{kind: 'in-bundle'|'offer'|'upstream-public', path|url, sha256}`, `modified: false`, `process_boundary: 'separate-process'|'embedded-runtime'`. `generated_by` (`build_backend_bundle/1`), `pin_sha256`, `built_at` (UTC), `git_commit`. Rules: Ghidriff entry has `role analysis-engine`, `source.kind in-bundle`, `process_boundary separate-process`; builder fails if any component lacks a licence file or if `modified` is not false. Notice for each wheel copies `*.dist-info/LICENSE*`.

### 7.4 Size reduction (all gated by acceptance)

Safe in v1: Ghidra `docs/` (Javadoc/class material), Eclipse GhidraDev/Sleigh extension zips under `Extensions/`, native directories of the *other* OS (`os/linux_*`, `os/mac_*` on Windows; `os/win_*`, `os/mac_*` on Linux), JDK `lib/src.zip` and `jmods/`. Keep: Ghidra `LICENSE`, `licenses/`, `GPL/` (GPL-licensed decompiler/demangler sources), all `Processors`, `Debug`, `Features`; JDK `legal/`; `javac` (jdk.compiler) is required by pyghidra. Deferred: processor stripping, jlink. Expected: ~0.7-1.0 GB zip, 1.5-2.0 GB extracted `[unverified]`; gate: zip <= 1.2 GB else investigate before shipping.

### 7.5 Runtime contract (`src/patchtrace/backend_bundle.py`, pure, no Qt, no subprocess)

- `BundleRef(root, manifest_path, runtime_id, python, ghidra, java_home, platform, manifest_sha256)` frozen dataclass.
- `find_bundled_runtime(exe_dir: Path | None = None, environ=None) -> BundleRef | None`: exe dir = `Path(sys.executable).parent` when `sys.frozen`, else `PATCHTRACE_BUNDLE_DIR`; checks exactly `<exe_dir>/backend/manifest.json`; no recursion; refuses symlinks/junctions; no execution.
- `verify_bundle(ref, *, mode='fast'|'full', cancel=None, event=None) -> BundleReport(ok, checked, bytes, problems[])`: fast = `os.scandir` walk, exact path set equals `files[]` (missing/extra), sizes equal; full = streamed SHA-256 of all files (progress events, cancellable); results cached as `<work>/bundle-verified-<manifest_sha256>.json` (nonsecret, per-user).
- `bundle_backend_kwargs(ref, work_dir) -> dict` for `BackendConfig(python_executable, ghidra_dir, java_home, restrict_env=True, bundle=True, ...)`.
- `BundleError(ValueError)` codes: `PT-BUNDLE-MISSING`, `PT-BUNDLE-MANIFEST`, `PT-BUNDLE-PLATFORM`, `PT-BUNDLE-SIZE`, `PT-BUNDLE-EXTRA`, `PT-BUNDLE-HASH`, `PT-BUNDLE-LINK`, `PT-BUNDLE-WORKDIR` (work dir inside the install dir), `PT-BUNDLE-PIN-MISMATCH` (build only), `PT-BUNDLE-LICENSE` (build only), `PT-BUNDLE-SIZE-LIMIT` (build only, > 1.9 GiB), `PT-BUNDLE-PATH-LENGTH` (build only).
- Limits: fast check <= 3 s for 60,000 entries on an SSD (test with 60,000 tiny files, budget 10 s CI); full hash chunk 1 MiB; work dir must not be inside `backend/`.

### 7.6 `backend.py` / `runtime_discovery.py` edits (each <= 40 lines)

`BackendConfig`: add `bundle: bool = False`. When true: argv is `[python, '-I', '-X', 'utf8', '-m', 'ghidriff', ...]`; `restrict_env` forced true; child env adds `JAVA_HOME_OVERRIDE=<jdk>` (also valid for the existing `java_home` path, harmless), `PYTHONDONTWRITEBYTECODE=1`, `XDG_CACHE_HOME`, and `TEMP/TMP/TMPDIR` pointing to the per-run scratch; PATH = `<jdk>/bin` + the existing allowlisted system PATH; `_config_errors` rejects a bundle config whose scratch/work path is inside the ghidra dir's parent `backend/`; `diagnose` appends `Bundled runtime <id>: fast check ok` or the `PT-BUNDLE-*` problem. `runtime_discovery`: `RuntimeCandidates.bundle_roots: tuple[Path, ...] = ()` (default keeps callers), filled by `find_bundled_runtime`; per-user runtimes root on Linux `~/.local/share/patchtrace/runtimes` with `payload/python/bin/python3`; precedence documented: explicit user setting > bundle next to exe > per-user installed runtime > other discovered.

### 7.7 Release assets (names exact)

`PatchTrace-<ver>-windows-x64-full.zip(.sha256)`, `PatchTrace-<ver>-linux-x86_64-full.tar.gz(.sha256)`, `PatchTrace-<ver>-backend-windows-amd64.zip(.sha256)` (importer ZIP = same payload), `ghidriff-4f5d895-source.tar.gz(.sha256)`, `THIRD-PARTY.json`, existing lite assets unchanged. Release notes lead with the full downloads; `milestone_notes.py` preamble amended (B9).

## 8. CLI and GUI

CLI (new `src/patchtrace/backend_cli.py`, hooked from `cli.py` with <= 8 lines; envelope `enrichment-cli/1`, exit codes 0/2/3/4/5 as the other commands): `patchtrace backend status [--json]` (bundle found, fast check, versions, no process started); `patchtrace backend verify [--full] [--json]`; `patchtrace backend selftest --older P --newer P --expect-function NAME [--project-dir D] [--json]` (runs the real `run_comparison` with the bundle config; exit 0 pass, 3 backend failure, 4 expectation not met, 2 usage, 5 bundle verification failure). Never executes the targets.

GUI (existing Setup dialog; no new window): `_apply_discovery` fills empty Python/Ghidra/JDK fields from the bundle first and adds the line `Bundled analysis runtime found next to PatchTrace (<runtime id>). Run Diagnose dependencies to verify it.` A read-only label `setup.backend.bundle` shows `Bundled runtime: ok (fast check)` or `Bundled runtime problem: <PT-BUNDLE-code> - extract the complete ZIP again`. A button `Verify bundle files` (`setup.backend.verify`) runs the full hash in the existing `Worker`, with progress text `Verifying 41,230 files... 38%` and a Cancel. First launch with a bundle and empty settings: `MainWindow.backend_config` falls back to `bundle_backend_kwargs` (<= 12 lines, slice B7), saved paths remain untouched. Accessible names/tooltip ids use the `setup.backend.*` stem. Offscreen test: bundle fixture (tiny fake payload) present => fields prefilled, verify worker cancel leaves settings unchanged.

## 9. Slice plan

Waves: W1 = B1, B2, B3, B6, B8 in parallel (no shared files). W2 = B3b, B4, B5a after their inputs. W3 = B7, B5b. W4 = B9, B10.

| Slice | Scope | Exclusive files | Depends | Tier | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| B1 pins | Resolve all `<...>` digests and sizes; confirm pyghidra 3.0.2 vs Ghidra `pypkg/dist` wheel; confirm JDK 21 patch; record `pip freeze` of the current CI lane; list safe strips | `tools/backend_pin.json`, `tools/check_backend_pin.py`, `tests/test_backend_pin.py` | none | sonnet (network, careful vendor digests) | S | schema test green; every digest traceable to a vendor file or marked TOFU | JDK 25 pin |
| B2 payload spike | `--check` inventory dry-run of the real extracted Ghidra/JDK/Python trees against the SPEC-06 path policy; report offending names | `tools/build_backend_bundle.py` (create, `check` subcommand only), `tests/test_build_backend_bundle_check.py` | none | sonnet | S | report on real trees attached to PR; zero or listed offenders | rename/strip rules |
| B3 manifest | Linux platform + public `validate_manifest`; keep Windows behaviour byte-identical | `src/patchtrace/offline_bundle.py`, `tests/test_offline_bundle_linux.py` | none | sonnet (strict parser, security) | S | all existing offline tests unchanged; new platform cases; traversal/reserved-name suites unchanged | Windows-only manifest, Linux loader parses its own |
| B4 builder | Full pipeline: fetch+verify, assemble payload, hash-locked `pip install --target`, wheel from source tarball, byte-compare, strip, compileall, notices, `THIRD-PARTY.json`, source tarball, manifest via `build_offline_bundle`, modes on Linux, size/path-length gates; `make_offline_bundle.py` becomes a thin caller of the same module (CLI unchanged) | `tools/build_backend_bundle.py` (extends B2), `tools/make_offline_bundle.py`, `tests/test_build_backend_bundle.py` (tiny fake components, no network) | B1 pin schema, B2 | sonnet | L | fake-component build passes manifest inspect; mismatch/license/mode/size gates each have a red test | keep producer-only mode |
| B5a acceptance harness | Env scrub, network denial per OS, read-only tree, tree digest, positive control, runs `backend selftest` | `tools/bundle_acceptance.py`, `tests/test_bundle_acceptance_unit.py` (pure helpers) | none (calls CLI by contract) | sonnet | M | helpers unit-tested; dry run on this Linux box with a fake bundle | none |
| B6 backend | `bundle` flag, argv, env, diagnose line | `src/patchtrace/backend.py`, `tests/test_backend_bundle_env.py` | none | sonnet; opus only after two failed attempts on Windows env behaviour | S | existing backend/audit tests unchanged; new tests: `JAVA_HOME_OVERRIDE`, `-I`, scratch outside backend | env-only |
| B8 build variants | `--full --backend-payload DIR --version V`: copy `backend/`, `SHA256SUMS.txt`, `build-provenance.json`, archive names, tar modes, frozen smoke on lite parts unchanged | `tools/build_windows.py`, `tools/build_linux.py`, `tests/test_build_full_variants.py` (pure helpers) | none (consumes a payload dir) | sonnet | M | helper tests; real build runs only in CI | lite only |
| B3b module | Pure runtime module (7.5) | `src/patchtrace/backend_bundle.py`, `tests/test_backend_bundle.py` | B3 | sonnet | M | fast/full verify, symlink, extra/missing/size tests; 60k-entry timing | fast-only |
| B7 wiring | Discovery edit, Setup prefill/label/verify button, `backend_config` fallback, `backend_cli.py` | `src/patchtrace/runtime_discovery.py`, `src/patchtrace/backend_cli.py`, hunks in `cli.py` and `ui.py` (serialised through the integration owner) | B3b, B6 | sonnet | M | offscreen tests, CLI envelope tests with fake bundle | CLI first, UI later |
| B5b workflow | `backend-bundle.yml` (section 10.3) | `.github/workflows/backend-bundle.yml` | B4, B5a, B7, B8 | sonnet; own PR (workflow changes can block publishing) | M | dispatch run green on both OS, acceptance artifacts | matrix row `continue-on-error` only until first green |
| B9 docs/QA | `docs/qa.md` rows, `docs/windows.md`, `docs/linux.md`, `tasks/todo.md`, SPEC-06 amendment, notes preamble | those files, `tools/milestone_notes.py` | B5b | haiku (doc edits) | S | links valid; no claim without run link | none |
| B10 first live | Dispatch run, record digests and sizes, fix pins/strips, attach prerelease | `tools/backend_pin.json` only | all | sonnet; opus for demonstrated Ghidra/JPype headless failures | M | acceptance green both OS; prerelease carries both full assets | publish lite + backend ZIP pair |

Merge order that avoids conflicts: B3, B1, B6, B8, B2 first (any order), then B3b, B5a, B4, then B7, B5b, then B9, B10.

## 10. Amendments, tests, QA

### 10.1 Amendments (owner of each applies in the named slice)

- `docs/specs/offline-backend-installer.md` section 1/4/7 (B9): add "full download" layout `backend/` next to the exe, Linux platform, JDK 21 decision, THIRD-PARTY.json, Windows acceptance gate D now automated; section 3 manifest unchanged.
- `AGENTS.md` line "Ghidra/Java/Ghidriff remain external" (B9): "except in the full distribution". Needs owner approval (policy file).
- `docs/windows.md`, `docs/linux.md`: full download steps, Unblock-File, storage requirement, read-only install, where per-user data lives.
- `docs/qa.md`: rows in 10.3; `tasks/todo.md`: link this plan.
- `.github/workflows/qa-windows.yml` (not edited in this plan): release job keeps lite assets; the full workflow attaches its assets to the same tag with `gh release upload --clobber`, creating the prerelease if absent (idempotent, no race).
- `tools/frozen_smoke.py`: no change (lite smoke); full smoke lives in `bundle_acceptance.py`.

### 10.2 Network denial and scrubbing (B5a design)

Common: extract the **release artifact** (not `dist/`) to a path with a space and a non-ASCII character; assert `backend/` read-only; scrub env to a minimum (`HOME`/`USERPROFILE`, `TEMP` pointing to a writable temp, `PATH` without any java/python, no `JAVA_HOME`, `GHIDRA_INSTALL_DIR`, `PYTHON*`); assert `which java python python3` fail under that PATH; positive control socket probe to a public IP:443 (bundled python) must succeed **before** the block and fail after; tree digest before and after equal; run `backend verify --full` then `backend selftest`.

- **Linux** (ubuntu-22.04 and 24.04 runners): `sudo unshare --net -- setpriv --reuid=$(id -u) --regid=$(id -g) --clear-groups env -i HOME=... PATH=/nonexistent LANG=C.UTF-8 ... ./PatchTrace/PatchTrace backend selftest ...` (root-created namespace; unprivileged `unshare -rn` is restricted by AppArmor on 24.04 `[unverified]`); bring `lo` up inside; read-only via running as a different owner or `chmod -R a-w`. Alternative if needed: `docker run --network none ubuntu:22.04` (base image has no python/java) with the tree mounted read-only.
- **Windows** (windows-latest, admin): `New-NetFirewallRule -Direction Outbound -Action Block -Program <abs>` for `PatchTrace.exe`, `backend\payload\python\python.exe`, `jdk\bin\java.exe`, `javaw.exe`, Ghidra `decompile.exe`; a blanket block would cut the runner's own log stream, so program rules plus the positive/negative control are the evidence. PATH set to `%SystemRoot%\System32;%SystemRoot%`. Loopback exemption of Windows Firewall `[unverified]`; record it in the log by also probing 127.0.0.1.
- Extra evidence (cheap): sample established non-loopback connections of the process tree every 500 ms during the run (`/proc/net` + pid on Linux, `Get-NetTCPConnection -OwningProcess` on Windows) and require zero.

### 10.3 Workflow `backend-bundle.yml` (B5b)

Triggers: `push tags v*`, `workflow_dispatch` (input `publish_tag`), `schedule` weekly (build + acceptance, no release). Jobs: `payload-{windows,linux}` (cache keyed by `hashFiles('tools/backend_pin.json')`, run `build_backend_bundle.py`, upload payload dir as artifact only for the next job) -> `app-{windows,linux}` (lite build deps as in qa-windows, `build_*.py --full`) -> `accept-{windows,linux}` (download the produced archive, 10.2) -> `release` (tag runs: upload full archives, `.sha256`, importer ZIP, source tarball, THIRD-PARTY.json). Job names state the hypothesis (`accept-windows-no-network-readonly`). `permissions: contents: read` except `release`. Timeouts 60 min. Artifact retention 7 days.

QA rows added to `docs/qa.md`: `BUNDLE-1` inventory dry-run on real trees; `BUNDLE-2` pin resolution; `BUNDLE-3` Windows acceptance (run link); `BUNDLE-4` Linux acceptance (22.04 and 24.04); `BUNDLE-5` size; `BUNDLE-6` licence completeness; `BUNDLE-7` owner clean-machine test (BLOCKED external: fresh Windows 11 with network unplugged, SmartScreen, Defender, double-click launch, GUI comparison of owner's pair). Automated evidence and blocked external acceptance are reported separately.

### 10.4 Unit/property tests

Fake components (tiny zips with the same layout) under `tests/fixtures/bundle/`, no Microsoft binaries: pin schema; builder gates (digest mismatch, missing licence, wheel not byte-equal to the tarball, over-size, long path, reserved name); manifest round-trip through `inspect_offline_bundle` and `verify_bundle` (full and fast); property: any single-byte flip, extra file, missing file or size change is detected; `find_bundled_runtime` refuses symlinked `backend/`; env tests assert `JAVA_HOME_OVERRIDE`, `-I`, no `PYTHONPATH`. Windows pitfalls: LF line endings for `_pth`, `CRLF` in notices fine, junction detection, reserved names, 32,767-char test id, no `rglob` on 60k entries without bound.

## 11. Open questions (defaults, none blocking)

1. Does MIT PatchTrace shipping unmodified GPL-3.0 Ghidriff as a separate-process component with source offer meet the owner's legal view? Default: ship; keep notices and the in-bundle source tarball; owner confirms before the first non-draft release.
2. JDK GPL-2.0+CE: written offer instead of bundling the OpenJDK source tarball? Default: offer with URL and sha256; include the tarball only if legal asks (adds ~0.2 GB).
3. JDK 21 or 25? Default 21 (documented); 25 is the pre-tested fallback.
4. pyghidra 3.0.2 (Ghidra 12.0.4 tag) or 3.1.0 (floating CI)? Default 3.0.2; acceptance decides.
5. Ghidriff SPDX `GPL-3.0-only` vs `-or-later`? Default record "GPL-3.0" unqualified, ask upstream via issue later.
6. Linux support level? Default: tar.gz is built and accepted in CI on 22.04/24.04 but labelled "experimental" until an owner test.
7. Should fast verification block analysis on failure? Default: block with the PT-BUNDLE code and a "re-extract" message; full verify is advisory on demand and mandatory only once per manifest hash.
8. Is a weekly schedule acceptable cost? Default yes (one run; detects vanished upstream assets).
