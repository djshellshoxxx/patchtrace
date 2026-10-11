# Ghidra-safe workspace, command-line interface and shared configuration (SPEC-05)

Status: **specification, not implemented** (except where §2.2 says a part is already on `main`).
Baseline: commit `5667b75` ("Fix dot-prefixed Ghidra analysis paths").
Upstream baseline: ghidriff `4f5d895fcbb1eacd65efd81145922c15bb7e741d` (see `../research.md`); every ghidriff flag named below was checked against `ghidriff/parser.py`, `ghidriff/__main__.py` and `GhidraDiffEngine.add_ghidra_args_to_parser` in that revision.
Normative keywords: **MUST**, **MUST NOT**, **SHOULD**, **MAY**.

This spec changes contracts in SPEC-01 (`architecture.md`, `run_comparison`), SPEC-03 (`verification.md`, new R15–R18) and the module index (`../modules.md`). If this spec conflicts with an older sentence in those files, this spec wins. The implementer updates those sentences in the same change as the code.

---

## 1. Overview

PatchTrace is a Qt desktop app (PySide6, frozen with PyInstaller as `PatchTrace.exe`). It compares an older and a newer PE AMD64 binary by running the external GPL `ghidriff` CLI in a separately installed Python environment, then normalizes the PDiff JSON into a project for review. This spec covers three things:

| Part | Outcome |
|---|---|
| A. Bug fix | Ghidra never receives a path that it rejects. Today the known failure is a dot-prefixed path element (`runs\.quarantine-<uuid>\raw`). The same layer also handles long paths, OneDrive, UNC and reserved names. The fix lives in editable, versioned source, and every shipped exe can be traced to that source. |
| B. CLI | The same `PatchTrace.exe` runs headless when given a subcommand and starts the GUI otherwise. The CLI exposes every backend capability and every ghidriff option. It has distinct exit codes, machine-readable run metadata, `--dry-run`, `--print-command`, and a config file shared with the GUI. |
| C. Extension points | Ranking, CVE correlation, binary acquisition, result caching, BinDiff/capa interop and pluggable AI each have a reserved place in the config, CLI, artifact registry and exit-code space, so adding them later does not change these contracts. |

Invariants that still apply (from AGENTS.md / SPEC-01):

- Target binaries are never executed. Driver inputs are never installed. Model-suggested commands are never run.
- Only strict JSON is imported. Evidence, artifact and run ownership is validated.
- Every remote transmission is explicit and preceded by an exact preview. Credentials exist only for the session. The CLI has no flag that takes a credential value.
- When something fails, upstream raw data and previously committed results are preserved. A failed run never produces an empty "success".
- Backend, schema and provider logic stays outside the UI. The CLI path **MUST NOT** import PySide6.

---

## 2. Part A: Ghidra rejects dot-prefixed project paths

### 2.1 Root cause

Ghidra's project layer rejects a project location if any path element starts with `.`:

```
output_path: ...\runs\.quarantine-a6e3382d-...\raw
Setting Up Ghidra Project...
java.lang.IllegalArgumentException: Path element starting with '.' is not permitted
  ghidra_diff_engine.py, line 497, in setup_project:
  project = GhidraProject.openProject(project_location, project_name, True)
```

The pinned ghidriff source shows how this happens. `ghidriff/__main__.py` derives four paths from `--output-path` whenever the caller leaves them at their defaults:

| ghidriff option | Default | Effective path when left at default |
|---|---|---|
| `-p/--project-location` | `ghidra_projects` | `<output-path>/ghidra_projects` |
| `-s/--symbols-path` | `symbols` | `<output-path>/symbols` |
| `-g/--gzfs-path` | `gzfs` | `<output-path>/gzfs` |
| `--log-path` | `ghidriff.log` | `<output-path>/ghidriff.log` |

`setup_project` then creates `<project-location>/<project-name>` and calls `GhidraProject.openProject(...)`. The effective project name is `f'{project_name}-{old.name}-{new.name}'`.

PatchTrace passed only `--output-path <project>\runs\.quarantine-<uuid>\raw`. The Ghidra project location therefore inherited the `.quarantine-…` element, and Ghidra threw before analysis started. ghidriff exited with code 1, and PatchTrace reported `PT-BACKEND: ghidriff exited with code 1; inspect analysis.log`.

The isolation test confirmed the cause: the same engine and inputs succeed when the output path is `C:\tools\ghidriff-out`.

Two more latent defects come from the same code:

1. **Path length.** PatchTrace passes `artifacts/<64-hex sha256>.bin` as the input names. The Ghidra project name is then `ghidriff-<sha>.bin-<sha>.bin` (141 characters). That name appears twice in every project file path (`<loc>\<name>\<name>.rep\…`), so the paths exceed Windows `MAX_PATH` unless long paths are enabled. CI runners enable long paths, which is probably why the native acceptance test passed there.
2. **Unvalidated derived paths.** The project location, symbol store, GZF cache and engine log all depend on whatever directory the project lives in. A project under OneDrive, under a hidden ancestor (for example `C:\Users\me\.cases\…`), or on a UNC share puts Ghidra's project database there too.

### 2.2 Current state on `main` (baseline `5667b75`)

| Required item | State at baseline | Remaining work in this spec |
|---|---|---|
| A1. Run working directory has no dot prefix | **Done.** `runs/quarantine-<uuid>` (`backend.py`). Legacy `.quarantine-*` directories are left alone. | Move the Ghidra-facing workspace out of the project entirely (§2.3). Put the naming in one module. |
| A2. Validate every path element before invoking ghidriff | **Partial.** `_validated_ghidra_output_path` checks `--output-path` ancestors for a leading `.` and rejects ≥ 240 characters on Windows. | Validate *every* Ghidra-facing path, including user overrides. Predict the deepest Ghidra file path instead of checking the base length. Add UNC, reserved-name, trailing-dot/space and OneDrive rules. Shorten the staged input names. Map Ghidra failure signatures to remedies (§2.4–§2.6). |
| A3. Editable source and buildable app | Source exists at `src/patchtrace/*.py` in `djshellshoxxx/patchtrace`. The exe has **no build provenance**, so nobody can tell which commit produced a given `PatchTrace.exe`. | Build provenance, a source archive, and a refusal to build from a dirty tree (§2.7). |

The failing log contains `.quarantine-`, so the user's executable was built **before** `5667b75`. Rebuilding from current source fixes the specific symptom. The rest of Part A hardens against the same class of failure.

### 2.3 Fix design: a local Ghidra workspace, separate from the project

**Decision (supersedes the SPEC-01 sentence "Reject an unsafe path… rather than silently renaming or moving the analyst's project"):** Ghidra never works inside the PatchTrace project directory by default. Each run gets a short, validated, machine-local *workspace*. After a successful run, the outputs are **published** into the project's `runs/<run_id>/raw/`. After a failed run, bounded diagnostics are copied into `runs/quarantine-<run_id>/`. The analyst's project is never moved or renamed.

Rationale:
- The user's project location (OneDrive, hidden folder, deep path, network share) stops affecting Ghidra.
- Ghidra's project database (large, write-heavy and lock-file based) stays out of sync clients.
- Paths are short, and their length can be predicted.

**Rewrite vs reject policy (answers the "reject or rewrite" requirement):**
- Path elements that PatchTrace *generates* (run directory, staged input names, Ghidra project name, output filenames) are **made safe by construction**. They are sanitized and the result is checked.
- Paths the *user provides explicitly* for Ghidra (`--work-root`, `--ghidra-project-location`, `--symbols-path`, `--gzfs-path`, or `--workspace project`) are **never silently rewritten**. If they fail validation, the command stops with exit code 2 (`PT-BACKEND`) and an actionable message. Silently rewriting an explicit path would hide where data went, and the persistent symbol store or Ghidra project might then be lost.

#### 2.3.1 Workspace layout

```
<work_root>\<run_id[:8]>\                     W  (created 0700 / owner-only ACL)
    patchtrace-work.json                      marker: run_id, project root, pid, created (UTC), PatchTrace version
    in\older\<staged-old-name>                hard link to the project artifact if on the same volume, else a verified copy; read-only
    in\newer\<staged-new-name>
    out\                                      → ghidriff --output-path
    gp\                                       → ghidriff --project-location
    sym\                                      → ghidriff --symbols-path   (unless a persistent symbols path is configured)
    gzf\                                      → ghidriff --gzfs-path
    ghidriff.log                              → ghidriff --log-path
```

- Default `work_root`:
  - Windows: `%LOCALAPPDATA%\PatchTrace\work`
  - POSIX: `<tempfile.gettempdir()>/patchtrace-work-<uid>`. `~/.cache` is **not** usable because `.cache` is dot-prefixed.
- The default can be overridden with `--work-root`, `PATCHTRACE_WORK_ROOT` or `backend.work_root`. The resolved work root is validated (§2.4) before any directory is created. If the default itself is invalid (for example a profile path containing a dot-prefixed element), the command exits 2 and the message names `--work-root`.
- `<run_id[:8]>` is the first 8 hex characters of the run's canonical UUID. If a directory with that name already exists, PatchTrace uses the full 32-hex UUID.
- `--workspace project` (config `backend.workspace = "project"`) restores the legacy layout (`<project>/runs/quarantine-<uuid>/raw` as `W`) for analysts who need the Ghidra project inside the case directory. The same validation applies, and failures are rejected.

#### 2.3.2 Staged input names

`stage_name(side, artifact.name) -> str`:
1. Replace every character outside `[A-Za-z0-9._-]` with `_`. Collapse runs of `_`.
2. Strip leading `.`, `-` and `_`, and trailing `.` and space.
3. Split into stem and extension. Keep the extension only if it matches `\.[A-Za-z0-9]{1,8}`. Truncate the stem so that stem + extension ≤ 24 characters. If the stem is empty, use `bin`.
4. Prefix with `older_` or `newer_` (examples: `older_clfs.sys`, `newer_clfs.sys`). The prefix keeps same-named inputs distinct inside one Ghidra project. It also guarantees the name never starts with `.` or `-`.

Before launch, the staged file's SHA-256 **MUST** equal `Artifact.sha256`; otherwise the run fails with `PT-INPUT`. Normalization already checks identity by hash (`verify_diff_identity`), so renaming does not weaken provenance. The default `--md-title` is set to `"<original old name> → <original new name>"` so upstream Markdown shows the user's file names, not the staged names.

#### 2.3.3 Ghidra project name

PatchTrace passes `--project-name pt` by default (`backend.ghidra_project_name`; must match `[A-Za-z0-9_-]{1,32}`). ghidriff appends `-<old>-<new>`, so the effective name is at most `3 + 30 + 1 + 30 = 64` characters.

#### 2.3.4 Publish and quarantine

- **Completed run:**
  1. Validate `out/json/*.ghidriff.json` with the existing rules (exactly one PDiff, ≤ 100 MiB, no symlink escape).
  2. Copy `out/` (Markdown, JSON, matches JSON, `sxs_html/` when requested) and `ghidriff.log` (truncated to the last 50 MiB if larger) into `<project>/runs/quarantine-<run_id>/raw/`, preserving relative paths. Then rename to `runs/<run_id>/` using the existing atomic-rename flow. Cross-volume moves are copy + fsync + rename within the project volume.
  3. Delete `gp/`, `gzf/` and `sym/` unless `--keep-ghidra-project` is set (`gp/`, `gzf/`) or a persistent symbols path is configured (`sym/` is then not under `W`).
  4. Delete `W` unless `--keep-workspace` is set.
- **Failed, cancelled or timed-out run:** Copy `analysis.log` (redacted, 2 MiB tail), `ghidriff.log` (50 MiB tail), `failure.txt` and any partial `out/json/*.json` that passes the size limit into `runs/quarantine-<run_id>/`. Keep `W` for post-mortem only if `--keep-workspace` is set. Previous committed results are untouched.
- **Startup hygiene:** `cleanup_stale_workspaces(work_root, max_age=7 days)` deletes only directories that contain a valid `patchtrace-work.json` whose `pid` is not alive and whose `created` is older than `max_age`. It never deletes anything without the marker. It runs on GUI start and at the start of `diff`.
- **Legacy:** Existing `runs/.quarantine-*` directories and `raw_path` values that point into them **MUST** stay loadable and viewable. They are never passed to Ghidra.

### 2.4 Path validation layer

New module `workspace.py` (indexed as `workspace` in `../modules.md`). Pure functions with no Qt dependency. Callers include `backend.run_comparison`, `cli diff --dry-run`, `doctor` and the GUI Settings dialog.

```python
@dataclass(frozen=True)
class PathIssue:
    code: str            # see table below
    severity: Literal['error', 'warning']
    path: str            # the offending path as given
    element: str | None  # offending element, when applicable
    message: str         # PT-BACKEND: … actionable text
    hint: str            # remediation, may name a CLI flag / config key

@dataclass(frozen=True)
class GhidraPaths:
    workspace: Path
    output_path: Path
    project_location: Path
    project_name: str
    symbols_path: Path | None      # None when --no-symbols
    gzfs_path: Path
    log_path: Path
    staged_inputs: tuple[Path, ...]

def check_ghidra_path(path: Path, role: str, *, platform: str = sys.platform,
                      long_paths_enabled: bool | None = None) -> list[PathIssue]
def predict_deepest(paths: GhidraPaths) -> int     # character count of the longest path Ghidra is expected to create
def validate_ghidra_paths(paths: GhidraPaths) -> list[PathIssue]   # errors → caller fails with exit 2
def plan_workspace(config: EffectiveConfig, project: ComparisonProject, project_root: Path,
                   run_id: str) -> GhidraPaths                     # pure; creates nothing (used by --dry-run)
def create_workspace(paths: GhidraPaths, project: ComparisonProject, project_root: Path) -> None
def publish_outputs(paths: GhidraPaths, destination: Path) -> None
def cleanup_stale_workspaces(work_root: Path, max_age: timedelta) -> list[Path]
```

`check_ghidra_path` checks both the **literal** path and `Path.resolve(strict=False)`. This catches junctions and symlinks that point into dot-prefixed directories. A non-existent tail is checked lexically against the resolved nearest existing ancestor.

| Code | Severity | Rule | Applies to |
|---|---|---|---|
| `GP-DOT` | error | Any element (literal or resolved) starts with `.`. Drive anchors such as `C:\` and `/` are excluded. | all Ghidra-facing paths |
| `GP-RELATIVE` | error | Path is not absolute after config resolution | all |
| `GP-UNC` | error | Path is UNC (`\\server\share\…`) or a mapped network drive (`GetDriveTypeW == DRIVE_REMOTE`). Ghidra project lock files are unreliable on SMB. | `project_location`, `gzfs_path`, `workspace` |
| `GP-VERBATIM` | error | Path uses the `\\?\` or `\\.\` prefix | all |
| `GP-RESERVED` | error | Any element, compared case-insensitively without its extension, is `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9` or `LPT1`–`LPT9` | all (Windows) |
| `GP-TRAILING` | error | Any element ends with `.` or a space (Windows strips these silently) | all (Windows) |
| `GP-CHARS` | error | An element contains `<>:"|?*`, a control character, or `:` outside the drive anchor | all (Windows) |
| `GP-LENGTH` | error | `predict_deepest(paths) > 259` and long paths are not enabled | the plan as a whole (Windows) |
| `GP-LENGTH-WARN` | warning | `predict_deepest(paths) > 259` and long paths are enabled | plan (Windows) |
| `GP-ONEDRIVE` | warning (error with `--workspace project`) | The path is inside `%OneDrive%`, `%OneDriveCommercial%` or `%OneDriveConsumer%` (resolved), or an element starts with `OneDrive` | `workspace`, `project_location` |
| `GP-SPACE` | none (allowed) | Spaces are valid. Paths are passed as separate argv elements with `shell=False` and are never quoted by hand. | — |
| `GP-NONASCII` | warning | An element contains non-ASCII characters. Ghidra supports Unicode, but this is recorded so failures can be triaged. | all |

`predict_deepest` = `max(len(str(p)) for p in candidates)`, where `candidates` contains:
- `gp\<pn>\<pn>.rep\idata\00\~00000000.db`, with `<pn>` the effective project name;
- `gp\<pn>\<pn>.rep\versioned\~index.bak`;
- `out\json\<old>-<new>.ghidriff.matches.json`;
- `gzf\<staged>.gzf`;
- `sym\<staged-name>\<32-hex+age>\<staged-name>.pdb`, a representative symbol-store path with an 80-character allowance.

Add `GHIDRA_SUFFIX_RESERVE = 48` characters to every candidate to cover Ghidra-internal names that are not enumerated. The reserve value is an estimate that must be calibrated on Windows (§6.4, open item). `long_paths_enabled` is read from `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled`. Tests can inject the value.

`--sxs` writes one file per changed function (`out\sxs_html\<old>-<new>.<function>.md`), and C++ function names can be very long. When `--sxs` is requested and long paths are disabled, PatchTrace emits a `GP-LENGTH-WARN` naming `--sxs` because the length cannot be predicted.

### 2.5 Failure classifier (actionable errors)

`classify_engine_failure(log_tail: str) -> EngineFailure | None` maps known ghidriff/Ghidra/JVM signatures to a hint. It runs on the redacted log after a non-zero exit. The resulting message replaces the generic text `ghidriff exited with code N; inspect analysis.log` with:

```
PT-BACKEND: ghidriff exited with code 1 (GF-DOTPATH): Ghidra rejected a dot-prefixed project path element.
  hint: …
  log:  C:\…\runs\quarantine-<id>\analysis.log
```

| ID | Signature (regex on log) | Hint |
|---|---|---|
| `GF-DOTPATH` | `Path element starting with '\.' is not permitted` | Name the offending configured path and remove the leading-dot element. With default settings this indicates a PatchTrace defect, so report it with the run metadata. |
| `GF-OOM` | `java\.lang\.OutOfMemoryError` | Raise `--max-ram-percent` or pass `--jvm-arg=-Xmx<N>G`. Large binaries may need `--no-bsim`. |
| `GF-JDK` | `UnsupportedClassVersionError\|Unsupported class file major version\|requires Java` | Install the JDK version that the Ghidra release requires, and set `--java-home`. |
| `GF-NOGHIDRA` | `GHIDRA_INSTALL_DIR\|Ghidra installation not found` | Set `--ghidra-install-dir` to the extracted root that contains `Ghidra/application.properties`. |
| `GF-PYGHIDRA` | `Expected pyghidra 3\.x` | Install a ghidriff/pyghidra combination compatible with the installed Ghidra version. |
| `GF-MISMATCH` | `arch.*mismatch\|symbols mismatch\|--force-diff` | The inputs differ in architecture or symbols. Verify the pair, or pass `--force-diff`. |
| `GF-LOCK` | `LockException\|project is locked` | Another Ghidra process holds the project. Close it or use a fresh `--ghidra-project-location`. |
| `GF-PATHLEN` | `FileNotFoundException.*(name too long\|path.*too long)\|The filename or extension is too long` | Shorten `--work-root` or enable Windows long paths. |
| `GF-DECOMP` | `Decompiler.*time(d)? ?out` | Raise `--decompiler-timeout`. |

The classifier table is data (a tuple of `(id, compiled regex, hint)`), so new signatures are one-line additions with a fixture test each.

### 2.6 Changes to `backend.run_comparison`

- Signature becomes `run_comparison(config: EffectiveConfig, project, root, cancel, on_event, *, run_id: str | None = None, plan_only: bool = False) -> tuple[Path, AnalysisRun]`. `BackendConfig` stays as a thin compatibility constructor for one release.
- argv is built by the pure function `build_ghidriff_argv(options: GhidriffOptions, paths: GhidraPaths, capabilities: GhidriffCapabilities) -> list[str]` (§3.8).
- `_validated_ghidra_output_path` is replaced by `workspace.validate_ghidra_paths`. Validation errors fail **before** `_probe_backend` and before any Java start, with exit code 2 / run status `failed`.
- `AnalysisRun.settings` additionally records the following. No absolute user paths are recorded unless `--redact-paths` is off; it is off by default, because metadata is local, and it is always redacted in reports.
  - `engine`, `ghidriff_argv_digest` (SHA-256 of the canonical argv JSON), `workspace_mode`, `path_issues` (warnings), and the effective analysis options.
- The child environment adds `JAVA_HOME` and prepends `<JAVA_HOME>/bin` to `PATH` when `backend.java_home` is configured. PYTHONPATH and PYTHONHOME stay removed. Whether pyghidra's launcher honors `JAVA_HOME` on Windows is an open live check (§6.4).

### 2.7 A3: Editable source, provenance and buildability

Facts:
- The application source is `src/patchtrace/*.py` in `djshellshoxxx/patchtrace`. It is installable with `pip install -e .[dev]` and runnable from source with `python -m patchtrace`.
- PyInstaller stores application modules **only as bytecode** inside the frozen archive. A search of an installed distribution (or of a build venv's `site-packages`) therefore finds no `.py` for PatchTrace's own code. This is expected, but nothing currently links an exe back to its source.

Requirements:

| ID | Requirement |
|---|---|
| SRC-1 | Run-directory naming, staged-name sanitization and Ghidra path validation live **only** in `src/patchtrace/workspace.py`. `backend.py` imports them. A test asserts that no other module builds a string beginning `.quarantine` or `runs/.` (§6.2 T-A07). |
| SRC-2 | `tools/build_windows.py` refuses to build if `git status --porcelain` is non-empty or if `HEAD` is not a commit. A local-only `--allow-dirty` produces `version` output marked `dirty: true`, and the release workflow rejects such builds. |
| SRC-3 | The build writes `_internal/patchtrace/build-info.json` = `{version, git_commit, git_describe, dirty, source_sha256, python, pyinstaller, pyside6, built_utc}`. `source_sha256` is the SHA-256 of the sorted `(relative path, file SHA-256)` list of `src/patchtrace/**/*.py`. `patchtrace version --json` prints it (§3.6). |
| SRC-4 | Each release ships `PatchTrace-<ver>-source.zip` (from `git archive HEAD`) and its SHA-256 next to the binary ZIP. The binary ZIP contains `SOURCE.txt` with the repository URL, the commit, and the three build commands from `../windows.md`. |
| SRC-5 | The Windows CI job builds from a clean checkout and runs `PatchTrace.exe self-test` and `PatchTrace.exe version --json`. It fails if `git_commit` ≠ `$GITHUB_SHA`. |
| SRC-6 | `self-test` additionally asserts that `workspace.RUN_DIR_PREFIX` does not start with `.` and that `validate_ghidra_paths(plan_workspace(defaults…))` returns no errors on the build machine. |
| SRC-7 | Hand-patching `.pyc` files or the PYZ is prohibited. Every fix starts in `src/`. |

---

## 3. Part B: CLI design

### 3.1 Dispatch rule (one executable)

`patchtrace.__main__.main(argv=None)` calls `entry.classify(argv)`, which returns one of the following. `classify` is pure and table-tested.

| argv after program name | Mode |
|---|---|
| empty | GUI |
| `gui [PROJECT_DIR] [common options]` | GUI (opens `PROJECT_DIR` if given) |
| exactly one argument that is an existing directory containing `project.sqlite3` (Explorer "drop onto exe" / "Open with") | GUI opening that project |
| first non-option token ∈ {`diff`, `doctor`, `config`, `version`, `self-test`, `import`, `export`, `show`, `project`, `interpret`, `help`} | CLI |
| `-h`, `--help`, `-V`, `--version` | CLI (top-level help/version) |
| `--self-test` (legacy, used by `tools/build_windows.py`) | CLI `self-test` |
| anything else | CLI usage error → exit 64 |

The CLI path imports `patchtrace.cli` and **MUST NOT** import `PySide6` or `patchtrace.ui`. A subprocess test enforces this (§6.3 T-B02). `self-test` is the only CLI command that may import Qt.

### 3.2 Windows console behavior

The current build uses `--windowed` (GUI subsystem). A GUI-subsystem exe has no stdout/stderr, and `cmd.exe` and PowerShell do not wait for it, so exit codes and output would be lost. Decision: build with the **console subsystem** and hide the console when the exe owns it:

- `tools/build_windows.py`: replace `--windowed` with `--console --hide-console hide-early` (PyInstaller ≥ 6.0; pinned 6.22.3). The bootloader hides the console only when the process *owns* it (double-click / Start menu). A console inherited from `cmd`, PowerShell or Windows Terminal stays visible and attached.
- Consequences, to be documented in `../windows.md`:
  - Double-click → GUI, with at most a brief console flash.
  - `PatchTrace.exe diff …` in a terminal → blocks, prints, and sets `%ERRORLEVEL%` / `$LASTEXITCODE`.
  - `PatchTrace.exe` with no arguments in a terminal → the GUI opens and the terminal waits until it closes. Use `start PatchTrace.exe` to detach.
- The CLI reconfigures `sys.stdout` and `sys.stderr` to UTF-8 with `errors='replace'` at startup. If `sys.stdout is None` (unexpected host), output goes to the log file only and the exit code is still returned.
- Rejected alternative: GUI subsystem + `AttachConsole(ATTACH_PARENT_PROCESS)`. Rejected because the shell does not wait and exit codes are unreliable.
- Rejected alternative: a second `patchtrace-cli.exe` or a `.com` shim. Rejected because the requirement is one executable. This **MAY** be added later as a convenience; it is not required.

### 3.3 Command tree

| Command | Purpose | Phase |
|---|---|---|
| `diff` | Create or reuse a project, run ghidriff, normalize, commit, emit artifacts | 1 |
| `doctor` | Diagnose Python/ghidriff/pyghidra/Ghidra/Java/path policy. `--deep` probes `ghidriff --help` capabilities. | 1 |
| `config` | `path`, `show`, `get`, `set`, `unset`, `init`, `validate`, `migrate-qsettings` | 1 |
| `version` | Version and build provenance | 1 |
| `gui` | Launch the desktop | 1 |
| `self-test` | Frozen-package smoke test (existing behavior + SRC-6) | 1 |
| `import` | Import an existing ghidriff PDiff JSON into a project (`service.prepare_import`/`apply_import`) | 2 |
| `export` | Markdown/HTML/JSON reports from a project (`reports.export_project`) | 2 |
| `show` | List matches/findings/runs from a project (table/JSON/CSV) | 2 |
| `project` | `review`, `note`, `correct-match`, `restore-override`, `swap`, `backup`, `history` (service operations) | 2 |
| `interpret` | Build exact context, write preview, send only with a matching digest (§3.7) | 2 |
| `rank`, `cve`, `fetch`, `cache` | Reserved names (§7). In phase 1/2 each exits 64 with "not implemented in this version". | 3 |

Phase 1 is the acceptance scope for this spec. Phase 2 is specified here so its contracts are fixed now.

### 3.4 Common options (accepted by every subcommand)

| Option | Meaning |
|---|---|
| `--config FILE` | Load this config file instead of the default. A missing or invalid file → exit 2. |
| `--no-config` | Ignore the default config file (built-in defaults + env + flags only) |
| `--log-file FILE` / `--no-log-file` | PatchTrace log file. Default for `diff`: `<out>/patchtrace.log`. Other commands: none. |
| `--log-level {debug,info,warning,error,critical}` | Console (stderr) level. Default `info`. |
| `--file-log-level {…}` | File log level. Default `debug`. |
| `--log-format {text,json}` | File log format. Default `text`. `json` = one object per line. |
| `-q`, `--quiet` | Console level `error`. Suppresses the end-of-run summary but not `--json` output. |
| `-v`, `--verbose` | `-v` = console `debug`. `-vv` also streams the live engine output to stderr. |
| `--json` | stdout carries exactly one JSON document (the command's result object). Human summaries are suppressed. |
| `--redact-paths` | Replace user-profile and project-absolute paths in metadata and logs with `<HOME>`, `<PROJECT>`, `<OUT>`, `<WORK>`. |
| `-h`, `--help` | Help for the command |

**stdout/stderr contract:** stdout carries **results only**: the summary, a single JSON document, `--print-command` text, or `config get` values. Logs, progress and errors go to stderr. Scripts can therefore pipe stdout safely.

### 3.5 `diff`: full flag reference

`[]` = optional. "cfg" = config key (§4.3). "env" = environment variable. Defaults shown are the built-in defaults.

**Inputs and project**

| Flag | Type / default | Meaning | Validation |
|---|---|---|---|
| `OLD` (positional) or `--old PATH` | path, required | Older (vulnerable) binary | Readable regular file; PE AMD64; ≤ 1 GiB (`inspect_artifact`). Positional and named forms are mutually exclusive. |
| `NEW…` (positional) or `--new PATH` (repeatable) | path(s), ≥ 1 | Newer (patched) binary or binaries, oldest to newest | Same checks. **More than one NEW → exit 64** "N-way comparison is reserved (SPEC-05 §7.7)" in phases 1–2. |
| `--project DIR` | path, default `<out>/project` | PatchTrace project directory. Created if absent. If it exists, its artifact hashes must equal the inputs' hashes (order-sensitive); then a new run is appended. | Hash mismatch → exit 8. Lock held → exit 8. |
| `--name TEXT` | str, default `"<old name> → <new name>"` | Project display name (new projects only) | ≤ 200 characters |

**Engine**

| Flag | Default (cfg) | ghidriff mapping |
|---|---|---|
| `--engine {version-tracking,structural-graph,simple}` | `version-tracking` (`analysis.engine`) | `--engine VersionTrackingDiff\|StructualGraphDiff\|SimpleDiff`. The upstream class is spelled `StructualGraphDiff`. Aliases accepted: the three upstream class names and `StructuralGraphDiff`. The chosen class must appear in the probed `--engine` choices, otherwise exit 2. |

**Output**

| Flag | Default (cfg) | Meaning |
|---|---|---|
| `-o, --out DIR` | `./patchtrace-runs/{old}-{new}-{date}T{time}` (`output.directory`) | Output directory, created if needed. It is not passed to Ghidra, so dot-prefixed elements are allowed here. |
| `--emit KINDS` | `ghidriff-md,ghidriff-json,report-md,summary,metadata` (`output.emit`) | Comma-separated and repeatable. **Replaces** the default set. Kinds: `ghidriff-md`, `ghidriff-json`, `matches-json`, `sxs-html`, `ghidriff-log`, `report-md`, `report-html`, `report-json`, `summary`, `metadata`, `all`, `none`. Unknown kind → exit 64. |
| `--name-template TPL` | `{old}-{new}` (`output.name_template`) | Stem for emitted files. Tokens: `{old}`, `{new}` (sanitized original stems), `{old_sha8}`, `{new_sha8}`, `{engine}`, `{date}` (UTC `YYYYMMDD`), `{time}` (UTC `HHMMSS`), `{run_id}`, `{run_id8}`. Rendered value: one path element, 1–96 characters, `[A-Za-z0-9._-]`, must not start with `.` → else exit 64. |
| `--overwrite` | off | Allow replacing existing emitted files. Without it, an existing target → exit 7 before analysis starts. Writes are atomic (temp + `os.replace`). |
| `--sxs`, `--side-by-side` | off | Adds `sxs-html` to the emit set |
| `--md-title TEXT` | `"<old name> → <new name>"` | Upstream Markdown title |
| `--max-section-funcs N` | 200 (`analysis.max_section_funcs`) | Upstream Markdown section cap. Integer ≥ 1. |
| `--include-code` | off (`output.report_include_code`) | PatchTrace reports include decompiled code (reports exclude it by default) |
| `--exclude-notes` | off | PatchTrace reports omit analyst notes |
| `--summary-diff` | off | Reserved for N-way: ghidriff `--summary` (first-to-last). Accepted only with more than one NEW. |
| `--keep-ghidra-project` | off (`output.keep_ghidra_project`) | Keep `W/gp` and `W/gzf` after success, and print their location |
| `--keep-workspace` | off | Keep all of `W` (debugging) |
| `--allow-empty` | off | Exit 0 instead of 4 when no differences are found |
| `--allow-identical` | off | Exit 0 instead of 6 for identical inputs |

**Environment overrides**

| Flag | env | cfg | Meaning |
|---|---|---|---|
| `--python PATH` | `PATCHTRACE_PYTHON` | `backend.python_executable` | External Python 3.10+ with ghidriff installed. Must be absolute and must not be `PatchTrace.exe`. |
| `--ghidra-install-dir DIR` | `GHIDRA_INSTALL_DIR` | `backend.ghidra_install_dir` | Extracted Ghidra root; must contain `Ghidra/application.properties`. |
| `--java-home DIR` | `JAVA_HOME` | `backend.java_home` | JDK root; must contain `bin/java(.exe)`. Exported to the child as `JAVA_HOME` and prepended to `PATH`. |
| `--symbols-path DIR` | — | `analysis.symbols_path` | Persistent local symbol store (validated as Ghidra-facing). Default: `W/sym`, which is discarded. |
| `--ghidra-project-location DIR` | — | `backend.ghidra_project_location` | Persistent Ghidra project parent (validated). Default `W/gp`. Setting it means projects are reused across runs (see §7.4). |
| `--ghidra-project-name NAME` | — | `backend.ghidra_project_name` | Default `pt`; `[A-Za-z0-9_-]{1,32}` |
| `--gzfs-path DIR` | — | `backend.gzfs_path` | Default `W/gzf` |
| `--work-root DIR` | `PATCHTRACE_WORK_ROOT` | `backend.work_root` | Workspace parent (§2.3.1) |
| `--workspace {local,project}` | — | `backend.workspace` | Default `local` |

**Analysis tuning**

| Flag | Default (cfg) | Validation |
|---|---|---|
| `--threaded` / `--no-threaded` | threaded (`analysis.threaded`) | — |
| `--force-analysis` | off | — |
| `--force-diff` | off | — |
| `--no-symbols` | off (`analysis.symbols = true`) | — |
| `--min-func-len N` | 10 | int ≥ 0 |
| `--max-ram-percent PCT` | 60.0 | float, 0 < PCT ≤ 95 |
| `--bsim` / `--no-bsim` | bsim on | — |
| `--bsim-full` / `--no-bsim-full` | off | — |
| `--timeout SECONDS` | 3600 (`backend.timeout_seconds`) | Whole-analysis wall clock, enforced by PatchTrace (process-tree kill). int 1–604800. |
| `--decompiler-timeout SECONDS` | 60 | Per-function, enforced by Ghidra. int ≥ 1. |
| `--use-calling-counts` / `--no-use-calling-counts` | off | — |
| `--base-address ADDR` | none | `0x` hex or decimal, ≤ 2⁶⁴−1 |
| `--program-options FILE` | none | Strict JSON (PatchTrace `strict_json`) with `program_options.Analyzers`, ≤ 1 MiB. Copied into `W/` before use so the file cannot change between check and use. |
| `--gdt FILE` (repeatable) | none | Existing `.gdt` file, absolute after resolution |
| `--verbose-analysis` | off | — |
| `--jvm-arg ARG` (repeatable) | none | Passed as `--jvm-args=ARG`. Values come only from the user's flags or config file, never from projects, imports or models. Recorded in metadata. |
| `--print-jvm-flags` | off | — |
| `--engine-log-level LEVEL` | `INFO` | ghidriff console level: `CRITICAL\|ERROR\|WARNING\|INFO\|DEBUG` |
| `--engine-file-log-level LEVEL` | `INFO` | ghidriff file log level |

**Behavior**

| Flag | Meaning |
|---|---|
| `--print-command` | Print the exact child argv, cwd and environment changes (§3.8.2) to stdout, then continue the run. With `--json`, the same data goes into the result object instead. |
| `--dry-run` | Resolve config, validate inputs (read-only PE checks and hashing), plan the workspace, run path validation, probe ghidriff capabilities (unless `--no-probe`), print the plan including the command, and **create, copy or launch nothing**. Exit 0 if the plan is valid, otherwise the matching error code. The planned run ID is illustrative; a real run gets a new one. |
| `--no-probe` | Skip the `ghidriff --help` capability probe (§3.8.3). All flags are assumed supported. |
| `--save-config FILE` | Write the effective configuration (§4) to FILE atomically. Inputs, `--out`, `--project` and per-run flags are excluded. Works with `--dry-run`. |
| `--metadata-json FILE\|-` | Write the run report (§5.4) to FILE (`-` = stdout, same as `--json`). Default: `<out>/<stem>.run.json` when `metadata` is in the emit set. |

### 3.6 Full `--help` text

Top level (`PatchTrace.exe --help`):

```
usage: PatchTrace [-h] [-V] <command> [options]

PatchTrace: compare binaries, trace fixes, investigate flaws.
Run without arguments to open the desktop application.

commands:
  diff        Compare an older and a newer binary with ghidriff (headless)
  doctor      Check Python, ghidriff, Ghidra, Java and workspace paths
  config      Show, edit, validate or migrate the shared configuration
  version     Print version and build provenance
  gui         Open the desktop application (optionally a project)
  self-test   Run the packaged smoke test
  import      Import a ghidriff JSON result into a project        [phase 2]
  export      Write Markdown/HTML/JSON reports from a project     [phase 2]
  show        List matches, findings or runs of a project         [phase 2]
  project     Review, annotate, correct, swap, back up a project  [phase 2]
  interpret   Preview and (explicitly) send AI interpretation     [phase 2]

options:
  -h, --help     show this help and exit
  -V, --version  print version and exit

Exit codes: 0 ok, 1 internal error, 2 environment/config, 3 analysis failed,
4 no differences, 5 input, 6 identical inputs, 7 output, 8 project/storage,
9 engine output rejected, 10 provider, 11 network, 64 usage, 124 timeout,
130 cancelled. See 'PatchTrace help exit-codes'.

Target binaries are never executed. Ghidra, Java and ghidriff are external.
```

`PatchTrace.exe diff --help`:

```
usage: PatchTrace diff [options] OLD NEW
       PatchTrace diff [options] --old OLD --new NEW

Statically compare OLD (vulnerable) and NEW (patched) binaries with ghidriff,
store the result in a PatchTrace project and emit reports.

inputs:
  OLD                       older / vulnerable binary (PE AMD64)
  NEW                       newer / patched binary (one; N-way is reserved)
  --old PATH                named form of OLD
  --new PATH                named form of NEW
  --project DIR             PatchTrace project to create or append to
                            (default: OUT/project)
  --name TEXT               project display name (new projects only)

engine:
  --engine {version-tracking,structural-graph,simple}
                            ghidriff engine (default: version-tracking)

output:
  -o, --out DIR             output directory
                            (default: ./patchtrace-runs/{old}-{new}-{date}T{time})
  --emit KINDS              comma list, repeatable; replaces the default set.
                            ghidriff-md ghidriff-json matches-json sxs-html
                            ghidriff-log report-md report-html report-json
                            summary metadata all none
                            (default: ghidriff-md,ghidriff-json,report-md,
                            summary,metadata)
  --name-template TPL       file stem; tokens {old} {new} {old_sha8} {new_sha8}
                            {engine} {date} {time} {run_id} {run_id8}
                            (default: {old}-{new})
  --overwrite               replace existing output files
  --sxs, --side-by-side     emit side-by-side HTML (adds sxs-html)
  --md-title TEXT           title of the ghidriff Markdown report
  --max-section-funcs N     functions per Markdown section (default: 200)
  --include-code            include decompiled code in PatchTrace reports
  --exclude-notes           omit analyst notes from PatchTrace reports
  --keep-ghidra-project     keep the Ghidra project and GZFs after success
  --keep-workspace          keep the whole local workspace (debugging)
  --allow-empty             exit 0 instead of 4 when no differences are found
  --allow-identical         exit 0 instead of 6 when inputs are identical

environment:
  --python PATH             external Python with ghidriff   [PATCHTRACE_PYTHON]
  --ghidra-install-dir DIR  Ghidra installation root        [GHIDRA_INSTALL_DIR]
  --java-home DIR           JDK root for Ghidra             [JAVA_HOME]
  --symbols-path DIR        persistent local symbol store
  --ghidra-project-location DIR
                            persistent Ghidra project parent
  --ghidra-project-name NAME
                            Ghidra project name (default: pt)
  --gzfs-path DIR           GZF cache directory
  --work-root DIR           local workspace parent          [PATCHTRACE_WORK_ROOT]
  --workspace {local,project}
                            where Ghidra works (default: local)

analysis:
  --threaded, --no-threaded threaded import/analysis/diff (default: threaded)
  --force-analysis          re-analyze even if the Ghidra project has results
  --force-diff              diff despite architecture/symbol mismatch
  --no-symbols              disable symbol loading
  --min-func-len N          minimum function length (default: 10)
  --max-ram-percent PCT     JVM max heap as % of RAM (default: 60)
  --bsim, --no-bsim         BSim correlation (default: on)
  --bsim-full, --no-bsim-full
                            slower, fuller BSim matching (default: off)
  --timeout SECONDS         whole-analysis timeout (default: 3600)
  --decompiler-timeout SECONDS
                            per-function decompiler timeout (default: 60)
  --use-calling-counts, --no-use-calling-counts
                            add calling/called counts (default: off)
  --base-address ADDR       rebase both programs (hex 0x… or decimal)
  --program-options FILE    JSON analyzer options (strict JSON)
  --gdt FILE                data type archive; repeatable
  --verbose-analysis        verbose Ghidra analysis logging
  --jvm-arg ARG             extra JVM argument; repeatable
  --print-jvm-flags         print JVM flags at start
  --engine-log-level LEVEL  ghidriff console level (default: INFO)
  --engine-file-log-level LEVEL
                            ghidriff file log level (default: INFO)

behavior:
  --print-command           print the exact ghidriff command, cwd and env
  --dry-run                 validate and print the plan; change nothing
  --no-probe                skip ghidriff capability probing
  --save-config FILE        save effective settings to FILE
  --metadata-json FILE|-    write the run report (JSON) to FILE or stdout

common:
  --config FILE, --no-config, --log-file FILE, --no-log-file,
  --log-level LEVEL, --file-log-level LEVEL, --log-format {text,json},
  -q/--quiet, -v/--verbose, --json, --redact-paths, -h/--help

examples:
  PatchTrace diff old\clfs.sys new\clfs.sys -o out\clfs-2026-07
  PatchTrace diff old.dll new.dll --engine simple --no-bsim --emit all
  PatchTrace diff a.sys b.sys --dry-run --print-command
```

The help text is generated by argparse from the same option definitions. A golden-file test (T-B01) pins it, so any flag change shows up in the diff.

### 3.7 Other commands (synopses)

```
PatchTrace doctor [--deep] [--python P] [--ghidra-install-dir D] [--java-home J] [--work-root W] [--json]
    exit 0 = all checks pass; 2 = at least one error. --deep runs the ghidriff --help probe
    and reports supported engines/flags, the long-path setting, the OneDrive locations
    and the validation of the default workspace plan.

PatchTrace config path                      # print the resolved config file path
PatchTrace config show [--origin] [--json]  # effective settings; --origin adds default|file|env|flag per key
PatchTrace config get KEY                   # dotted key, e.g. analysis.engine
PatchTrace config set KEY VALUE             # typed parse + validation, atomic write
PatchTrace config unset KEY
PatchTrace config init [--force]            # write defaults (+ migrated QSettings, if present)
PatchTrace config validate FILE             # exit 0 valid / 2 invalid
PatchTrace config migrate-qsettings [--dry-run]

PatchTrace version [--json]                 # version + build-info.json (SRC-3)
PatchTrace gui [PROJECT_DIR]
PatchTrace self-test

# phase 2
PatchTrace import PROJECT_DIR --ghidriff-json FILE
PatchTrace export PROJECT_DIR --format {md,html,json} --dest FILE [--include-code] [--exclude-notes]
                  [--finding ID]... [--overwrite]
PatchTrace show PROJECT_DIR [{matches,findings,runs}] [--category C]... [--review S]... [--format {table,json,csv}] [--limit N]
PatchTrace project review PROJECT_DIR --match ID --status {accepted,rejected,needs-review}
PatchTrace project note PROJECT_DIR --target ID --text TEXT [--kind {note,bookmark}]
PatchTrace project correct-match PROJECT_DIR --match ID --older ID... --newer ID... --reason TEXT
PatchTrace project restore-override PROJECT_DIR --annotation ID
PatchTrace project swap PROJECT_DIR
PatchTrace project backup PROJECT_DIR --dest DIR
PatchTrace project history PROJECT_DIR [--json]
PatchTrace interpret PROJECT_DIR --match ID... --provider {ollama,openai-compatible}
                  --endpoint URL --model NAME [--context-budget N]
                  (--preview FILE | --send --expect-digest SHA256)
                  [--api-key-env VAR]
```

`interpret` keeps the explicit-transmission rule in a non-interactive setting:
1. `--preview FILE` writes the exact request (context, system prompt, provider, model, endpoint) and prints its digest. Nothing is sent.
2. `--send --expect-digest D` rebuilds the context and sends it **only if** the digest equals `D`. Otherwise it exits 64 and sends nothing.
3. Credentials come from the environment variable named by `--api-key-env`, or from an interactive `getpass` prompt when stdin is a TTY. They are never taken from argv or the config file, and are never written anywhere.

### 3.8 Mapping to ghidriff and to backend settings

#### 3.8.1 Flag mapping table

| PatchTrace CLI flag | Config key | ghidriff argument (pinned rev) | Backend effect |
|---|---|---|---|
| `OLD` / `--old` | — | positional `old` (staged `W/in/older/<name>`) | `inspect_artifact(path,'older',root)` → artifact copy → staged |
| `NEW` / `--new` | — | positional `new` (staged `W/in/newer/<name>`) | same, `'newer'` |
| `--project` | — | — | `ProjectService.create/open` |
| `--name` | — | — | `ComparisonProject.name` |
| `--engine` | `analysis.engine` | `--engine <Class>` | `AnalysisRun.settings.engine` |
| `-o/--out` | `output.directory` | — (not given to Ghidra) | publish target |
| `--emit` | `output.emit` | `--sxs` iff `sxs-html` ∈ emit | artifact registry (§5.5) |
| `--name-template` | `output.name_template` | — | publish names |
| `--md-title` | — | `--md-title` | — |
| `--max-section-funcs` | `analysis.max_section_funcs` | `--max-section-funcs` | — |
| `--summary-diff` | — | `--summary` | reserved N-way |
| (internal) | — | `-o/--output-path W/out` | validated (§2.4) |
| `--python` | `backend.python_executable` | — (`argv[0]`) | `_config_errors`, probe |
| `--ghidra-install-dir` | `backend.ghidra_install_dir` | — (env `GHIDRA_INSTALL_DIR`, child cwd) | version from `application.properties` |
| `--java-home` | `backend.java_home` | — (env `JAVA_HOME`, `PATH`) | doctor Java check |
| `--symbols-path` | `analysis.symbols_path` | `-s/--symbols-path` | validated |
| `--no-symbols` | `analysis.symbols=false` | `--no-symbols` | `--symbols-path` still passed (under `W`) because ghidriff derives it anyway |
| `--ghidra-project-location` | `backend.ghidra_project_location` | `-p/--project-location` | validated |
| `--ghidra-project-name` | `backend.ghidra_project_name` | `-n/--project-name` | effective name `<n>-<old>-<new>` |
| `--gzfs-path` | `backend.gzfs_path` | `-g/--gzfs-path` | validated |
| (internal) | — | `--log-path W/ghidriff.log` | published as `ghidriff-log` |
| `--work-root` | `backend.work_root` | — | `W` parent |
| `--workspace` | `backend.workspace` | — | §2.3 |
| `--threaded/--no-threaded` | `analysis.threaded` | `--threaded/--no-threaded` | — |
| `--force-analysis` | `analysis.force_analysis` | `--force-analysis` | — |
| `--force-diff` | `analysis.force_diff` | `--force-diff` | — |
| `--min-func-len` | `analysis.min_func_len` | `--min-func-len` | — |
| `--max-ram-percent` | `analysis.max_ram_percent` | `--max-ram-percent` | — |
| `--bsim/--no-bsim` | `analysis.bsim` | `--bsim/--no-bsim` | — |
| `--bsim-full/--no-bsim-full` | `analysis.bsim_full` | `--bsim-full/--no-bsim-full` | — |
| `--timeout` | `backend.timeout_seconds` | — | `run_process(timeout_seconds=…)`; exit 124 |
| `--decompiler-timeout` | `analysis.decompiler_timeout` | `--decompiler-timeout` | — |
| `--use-calling-counts/--no-…` | `analysis.use_calling_counts` | `--use-calling-counts/--no-use-calling-counts` | — |
| `--base-address` | `analysis.base_address` | `--base-address` | — |
| `--program-options` | `analysis.program_options` | `--program-options W/program-options.json` | strict JSON validated and copied |
| `--gdt` | `analysis.gdt` | `--gdt` (repeated) | — |
| `--verbose-analysis` | `analysis.verbose_analysis` | `--va` | — |
| `--jvm-arg` | `analysis.jvm_args` | `--jvm-args=<ARG>` (repeated, `=` form) | — |
| `--print-jvm-flags` | — | `--print-flags` | — |
| `--engine-log-level` | `logging.engine_level` | `--log-level` | — |
| `--engine-file-log-level` | `logging.engine_file_level` | `--file-log-level` | — |
| `--log-level`, `--file-log-level`, `--log-file` | `logging.*` | — | PatchTrace logging (§5) |
| `--print-command`, `--dry-run`, `--no-probe`, `--config`, `--save-config`, `--metadata-json`, `--json` | — | — | CLI behavior only |
| `--include-code`, `--exclude-notes` | `output.report_*` | — | `export_project` flags |
| `--keep-ghidra-project`, `--keep-workspace` | `output.keep_*` | — | §2.3.4 |
| `--allow-empty`, `--allow-identical` | — | — | exit mapping |

#### 3.8.2 Canonical argv (`build_ghidriff_argv`)

PatchTrace passes **every** option explicitly, including default values, so a run does not depend on upstream defaults that may change. The argv order is deterministic:

```
[<python>, '-m', 'ghidriff',
 '--engine', E,
 '--output-path', W/out, '--project-location', P, '--project-name', N,
 '--symbols-path', S, '--gzfs-path', G, '--log-path', W/ghidriff.log,
 '--log-level', L1, '--file-log-level', L2,
 '--threaded' | '--no-threaded',
 ['--force-analysis'], ['--force-diff'], ['--no-symbols'],
 '--min-func-len', n,
 '--use-calling-counts' | '--no-use-calling-counts',
 '--bsim' | '--no-bsim', '--bsim-full' | '--no-bsim-full',
 '--max-ram-percent', f, ['--print-flags'], *['--jvm-args=' + a for a in jvm_args],
 '--decompiler-timeout', t, ['--base-address', hex], ['--program-options', W/program-options.json],
 *[x for g in gdt for x in ('--gdt', g)], ['--va'], ['--sxs'],
 '--max-section-funcs', m, ['--md-title', title], ['--summary'],
 '--', W/in/older/<a>, W/in/newer/<b>]
```

- `cwd` = Ghidra install dir (existing behavior).
- Environment changes relative to the inherited environment: set `GHIDRA_INSTALL_DIR` and `PYTHONIOENCODING=utf-8`; set `JAVA_HOME` and prepend `PATH` when configured; remove `PYTHONPATH` and `PYTHONHOME`.

`--print-command` text format (stdout):

```
# cwd: C:\Tools\ghidra_12.0.4_PUBLIC
# env set: GHIDRA_INSTALL_DIR=C:\Tools\ghidra_12.0.4_PUBLIC PYTHONIOENCODING=utf-8 JAVA_HOME=C:\jdk-21
# env removed: PYTHONPATH PYTHONHOME
"C:\Users\me\AppData\Local\PatchTrace-backend\Scripts\python.exe" -m ghidriff --engine VersionTrackingDiff --output-path "C:\Users\me\AppData\Local\PatchTrace\work\a6e3382d\out" …
```

The command line is rendered with `subprocess.list2cmdline` on Windows and `shlex.join` on POSIX. The JSON form (`ghidriff.argv`) is the canonical list. The printed command is **exactly** the argv passed to `run_process`; test T-B06 compares the two. The command is for inspection and reproduction by the user. PatchTrace never executes text from it.

#### 3.8.3 Capability probe

`probe_ghidriff(config) -> GhidriffCapabilities` runs `<python> -m ghidriff --help` with the existing `run_process` containment, a 30 s timeout and a 64 KiB log limit. This imports ghidriff and pyghidra but does not start the JVM. The probe parses:
- the option strings (`--[a-z0-9-]+`);
- the `--engine` choices from `{A,B,C}`.

Results are cached in memory per `(python path, python mtime, ghidriff version)`.

Rules:
- A flag whose value differs from the upstream default and is not supported → exit 2: "installed ghidriff does not support --X; upgrade or remove the option".
- A default-valued flag that is not supported → omitted, with a warning recorded in `path_issues`/`warnings`.
- If the probe fails, the run continues only with `--no-probe` semantics if the user passed `--no-probe`. Otherwise → exit 2.

`BackendCapabilities` (existing model) gains `engines: list[str]` and `options: list[str]`. Generate the schemas after the model change.

### 3.9 Exit codes

| Code | Name | Raised when | PT taxonomy |
|---|---|---|---|
| 0 | `OK` | Command succeeded. For `diff`: analysis completed, ≥ 1 added/deleted/modified function, every requested artifact written. | — |
| 1 | `INTERNAL` | Unexpected exception (a PatchTrace defect). The traceback goes only to the log file; stderr gets a one-line message plus the log path. | — |
| 2 | `ENVIRONMENT` | Invalid or missing config file. External Python, ghidriff, pyghidra, Ghidra or Java missing or incompatible. Probe failure. Unsupported engine or flag. Any `GP-*` path error. `doctor` found errors. | `PT-BACKEND` (pre-launch), `PT-CONFIG` (new) |
| 3 | `ANALYSIS_FAILED` | ghidriff exited non-zero, was killed for unsafe or oversized output, or produced zero or multiple PDiff JSONs. The output is quarantined. | `PT-BACKEND` (post-launch) |
| 4 | `NO_DIFFERENCES` | Analysis completed, but the normalized result has 0 added, 0 deleted and 0 modified functions. Becomes 0 with `--allow-empty`. | — |
| 5 | `INPUT` | Input missing, unreadable, not PE AMD64, oversize, changed during copy, or staged hash mismatch | `PT-INPUT` |
| 6 | `IDENTICAL` | Input SHA-256 values are equal; analysis skipped (existing `identical` status). Becomes 0 with `--allow-identical`. | — |
| 7 | `OUTPUT` | Cannot create or write `--out`, a target exists without `--overwrite`, or a report export failed | `PT-EXPORT` |
| 8 | `PROJECT` | Project lock held, database corrupt or of a future version, or the existing project's artifact pair differs from the inputs | `PT-STORAGE` |
| 9 | `ENGINE_OUTPUT_REJECTED` | ghidriff succeeded, but normalization or identity verification rejected its JSON. The output is quarantined. | `PT-SCHEMA` |
| 10 | `PROVIDER` | `interpret`: transport, status, malformed or ungrounded response | `PT-PROVIDER` |
| 11 | `NETWORK` | Reserved: acquisition / CVE fetch (§7) | `PT-NETWORK` (new, reserved) |
| 12–19 | reserved | Reserved for extensions (§7). Must be registered in this table before use. | — |
| 64 | `USAGE` | Bad flags or arguments, unknown subcommand, invalid template, reserved feature (N-way, `rank`…), `--expect-digest` mismatch | — |
| 124 | `TIMEOUT` | `--timeout` elapsed. The process tree was killed and output quarantined. | `PT-BACKEND` (timeout) |
| 130 | `CANCELLED` | Ctrl+C, Ctrl+Break, console close or SIGTERM. The process tree was killed, output quarantined, and prior results preserved. | `PT-CANCEL` |

Rules:
- argparse's default usage exit code (2) is overridden to 64 so that 2 always means "environment".
- When several problems exist, the **first fatal** one determines the code. Validation order: usage → config → input → path/environment → output pre-check → analysis → normalization → publish.
- The code ↔ PT taxonomy mapping is implemented once in `cli.exit_code_for(error)`. `PT-…` prefixes stay the source of truth inside the backend; the CLI only maps them.
- `PT-CONFIG` is a new prefix for invalid config files and values. It is added to the SPEC-01 error taxonomy.

### 3.10 Example invocations

```powershell
# Typical Patch Tuesday diff
PatchTrace.exe diff C:\bins\clfs.sys.10.0.26100.4202 C:\bins\clfs.sys.10.0.26100.4484 -o C:\cases\clfs-2026-07

# Everything, side-by-side, faster engine, no BSim, 2 h budget
PatchTrace.exe diff old.dll new.dll --engine simple --no-bsim --emit all --timeout 7200

# CI: JSON on stdout, fail only on real errors
PatchTrace.exe diff old.sys new.sys -o out --json --allow-empty -q > run.json; echo $LASTEXITCODE

# Show exactly what would run; change nothing
PatchTrace.exe diff old.sys new.sys --dry-run --print-command

# Explicit environment, persistent symbols, bigger heap
PatchTrace.exe diff a.dll b.dll --python C:\venvs\ghidriff\Scripts\python.exe `
  --ghidra-install-dir C:\Tools\ghidra_12.0.4_PUBLIC --java-home "C:\Program Files\Eclipse Adoptium\jdk-21" `
  --symbols-path C:\symbols --max-ram-percent 75 --jvm-arg=-XX:+UseG1GC

# Share settings between GUI and CLI
PatchTrace.exe config set backend.ghidra_install_dir C:\Tools\ghidra_12.0.4_PUBLIC
PatchTrace.exe diff a.dll b.dll --no-bsim --save-config team.json --dry-run
PatchTrace.exe diff a.dll b.dll --config team.json

# Project lives in OneDrive under a dot folder: works, because Ghidra uses the local workspace
PatchTrace.exe diff a.sys b.sys --project "C:\Users\me\OneDrive - Lab\.cases\clfs"

# Diagnose
PatchTrace.exe doctor --deep
```

---

## 4. Architecture: one entrypoint, one config

### 4.1 Module plan (to be indexed in `../modules.md` before implementation)

| ID | File | Responsibility | Depends on | Qt? |
|---|---|---|---|---|
| entry | `__main__.py` | `classify(argv)`, then GUI or CLI dispatch. Keeps `--self-test`. | cli (lazy), ui (lazy) | GUI branch only |
| cli | `cli.py` | argparse tree, option → `RunRequest`, output rendering, exit-code mapping, signal handling | config, analysis, workspace, backend, reports, service | **never** |
| config | `config.py` | `PatchTraceConfig` (pydantic, strict), load/merge/save, provenance per key, QSettings migration (the migration function takes a plain `dict` so it has no Qt import) | models, persistence.strict_json | never |
| workspace | `workspace.py` | §2.3–§2.4 path planning, validation, staging, publish, cleanup | ingestion | never |
| analysis | `analysis.py` | Headless orchestration lifted from `ui.MainWindow.run_analysis/complete_analysis` (below) | backend, service, workspace | never |
| backend (changed) | `backend.py` | `GhidriffOptions`, `build_ghidriff_argv`, `probe_ghidriff`, `classify_engine_failure`, `run_comparison` using workspace | jobs, workspace | never |
| jobs (changed) | `jobs.py` | `run_process(..., on_chunk: Callable[[str], None] \| None = None)`. Redacted, line-buffered streaming for `-vv` and the GUI log pane. Bounded tail behavior unchanged. | — | never |
| desktop (changed) | `ui.py` | Settings dialog edits `PatchTraceConfig`, with a new "Analysis" tab covering every `analysis.*` key. "Copy equivalent CLI command". Calls `analysis.*`. | config, analysis | yes |
| packaging (changed) | `tools/build_windows.py` | console + hide-console, build-info, source ZIP, clean-tree gate | — | — |

Orchestration split. `analysis.py` keeps the SQLite thread-confinement rule (connections stay on the thread that created them; commits happen on the owner thread):

```python
@dataclass(frozen=True)
class RunRequest:            # everything a run needs; built by CLI flags or GUI settings
    config: EffectiveConfig
    run_id: str | None = None
    plan_only: bool = False

@dataclass(frozen=True)
class AnalysisOutcome:
    run: AnalysisRun
    raw_path: Path
    prepared: PreparedImport | None
    plan: GhidraPaths
    argv: list[str]
    failure: EngineFailure | None

def execute(request: RunRequest, snapshot: ComparisonProject, root: Path, service_prepare,
            cancel: threading.Event, on_event) -> AnalysisOutcome      # worker-safe; no commits
def commit(service: ProjectService, outcome: AnalysisOutcome, cancelled: bool) -> AnalysisRun  # owner thread
```

- The GUI calls `execute` on its `Worker` thread and `commit` in `complete_analysis`, which is the existing behavior moved out of `ui.py` without semantic change.
- The CLI calls both on the main thread. The child wait happens inside `run_process`, so Ctrl+C sets `cancel`.

### 4.2 Data flow (`diff`)

```mermaid
flowchart TD
    A[argv] --> B{entry.classify}
    B -- no args / gui --> GUI[ui.MainWindow]
    B -- subcommand --> C[cli.parse]
    C --> D[config.resolve: defaults < file < generic env < PATCHTRACE_* env < flags]
    D --> E[ingestion.inspect_artifact x2 -> ProjectService.create/open]
    E --> F[workspace.plan_workspace + validate_ghidra_paths]
    F -- errors --> X2[exit 2]
    F --> G[backend.probe_ghidriff -> capabilities]
    G --> H[backend.build_ghidriff_argv]
    H -- --dry-run --> P[print plan, exit 0]
    H --> I[workspace.create_workspace: stage inputs, verify hashes]
    I --> J[jobs.run_process: Job Object / process group, timeout, cancel]
    J -- non-zero/timeout/cancel --> Q[quarantine + classify_engine_failure -> exit 3/124/130]
    J --> K[workspace.publish_outputs -> runs/<id>/raw]
    K --> L[service.prepare_analysis -> normalize]
    L -- PT-SCHEMA --> Q9[quarantine_failed_run -> exit 9]
    L --> M[service.apply_import commit]
    M --> N[emit registry: ghidriff md/json/sxs, reports, summary, run.json]
    N --> O[exit 0 / 4]
    GUI --> D
```

### 4.3 Shared configuration

- **Format:** UTF-8 JSON, parsed with `persistence.strict_json` (rejects duplicate keys, NaN and Infinity). It is validated by the pydantic model `PatchTraceConfig` (`extra='forbid'`, `schema_version` exactly 1) and the generated schema `docs/schemas/PatchTraceConfig.json` (add it to `tools/generate_schemas.py`). JSON was chosen over TOML or INI because it is the project's existing strict-import format and it can be written without a new dependency.
- **Location** (first match wins):
  1. `--config FILE`
  2. `PATCHTRACE_CONFIG`
  3. `%APPDATA%\PatchTrace\config.json` on Windows, `$XDG_CONFIG_HOME/patchtrace/config.json` on POSIX (not given to Ghidra, so a dot-prefixed `~/.config` is fine)
- **Writes:** atomic (sibling temp + `os.replace`). Concurrent GUI and CLI writers: last writer wins at file level. The GUI re-reads the file before applying a Settings dialog change and refuses with a notice if the file changed since the dialog opened.
- **Precedence**, lowest to highest:

  | # | Source |
  |---|---|
  | 1 | built-in defaults |
  | 2 | generic environment (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`) |
  | 3 | config file |
  | 4 | PatchTrace environment (`PATCHTRACE_PYTHON`, `PATCHTRACE_WORK_ROOT`) |
  | 5 | CLI flags |

  Rationale: the PatchTrace config is an explicit choice and should beat ambient machine-wide variables that other tools also use. PatchTrace-specific variables are explicit too, so they sit above the file. `config show --origin` reports the source of each value.
- **Never stored:** credentials, API keys, inputs, `--out`, `--project`. `provider.api_key` does not exist in the model. Test T-C05 scans saved files for secret-like values.
- **UI-only state** (window geometry, splitter state, recent projects) stays in `QSettings`. It is not analysis configuration.
- **Migration:** On first GUI start without a config file, `config.migrate_qsettings(values: dict)` maps `backend/python → backend.python_executable`, `backend/ghidra → backend.ghidra_install_dir`, `backend/timeout → backend.timeout_seconds`, `provider/kind|endpoint|model|context_budget → provider.*` and `desktop/font_size|sync → desktop.*`. It then writes the file. The QSettings keys are left in place for one release to allow rollback.

```json
{
  "schema_version": 1,
  "backend": {
    "python_executable": null, "ghidra_install_dir": null, "java_home": null,
    "timeout_seconds": 3600, "workspace": "local", "work_root": null,
    "ghidra_project_location": null, "ghidra_project_name": "pt", "gzfs_path": null
  },
  "analysis": {
    "engine": "version-tracking", "threaded": true, "force_analysis": false, "force_diff": false,
    "symbols": true, "symbols_path": null, "min_func_len": 10, "max_ram_percent": 60.0,
    "bsim": true, "bsim_full": false, "decompiler_timeout": 60, "use_calling_counts": false,
    "base_address": null, "program_options": null, "gdt": [], "verbose_analysis": false,
    "jvm_args": [], "max_section_funcs": 200
  },
  "output": {
    "directory": null, "emit": ["ghidriff-md", "ghidriff-json", "report-md", "summary", "metadata"],
    "name_template": "{old}-{new}", "report_include_code": false, "report_include_notes": true,
    "keep_ghidra_project": false, "keep_workspace": false
  },
  "logging": {"console_level": "info", "file_level": "debug", "format": "text",
              "engine_level": "INFO", "engine_file_level": "INFO"},
  "provider": {"kind": "ollama", "endpoint": "http://127.0.0.1:11434", "model": "", "context_budget": 24000},
  "desktop": {"font_size": 11, "sync_scroll": true},
  "extensions": {}
}
```

`extensions` is the only open object. Each key in it is owned by one extension module, which validates its own sub-object (§7). Unknown top-level keys fail with `PT-CONFIG`.

`AnalysisRun.settings` records the **effective** analysis options and the argv digest. A run can therefore be reproduced with `--config` + flags, and the stale-invalidation rule ("settings change … marks previous contexts stale") has a concrete basis.

---

## 5. Logging and error handling

### 5.1 Streams and logs

| Stream | Content | Bounds | Redaction |
|---|---|---|---|
| stdout | Results only (§3.4) | — | `--redact-paths` |
| stderr | PatchTrace console log (stages, warnings, errors). With `-vv`, also the live engine output prefixed `ghidriff│ `. | — | `redact_log` always |
| `--log-file` (default `<out>/patchtrace.log`) | Full PatchTrace log, including the traceback for exit 1 | 20 MiB, then rotate once (`.1`) | `redact_log` always |
| `runs/<id>/analysis.log` (or `quarantine-<id>`) | Merged child stdout/stderr tail (existing behavior) | 2 MiB tail | `redact_log` |
| `runs/<id>/raw/ghidriff.log` → `ghidriff-log` emit | ghidriff's own file log (`--log-path`) | 50 MiB tail | `redact_log` on publish |

Text line format: `2026-10-11T12:00:00.123Z INFO  patchtrace.backend  message`. JSON line format: `{"ts", "level", "logger", "msg", "run_id", "stage"}`. Every `JobEvent` is logged at INFO with its stage. Logs never contain credentials; for the CLI this is structural, since no credential is ever accepted from argv or config.

### 5.2 Error rendering

```
PatchTrace: error E2 PT-BACKEND (GP-DOT): --ghidra-project-location 'D:\cases\.ghidra' contains the dot-prefixed element '.ghidra'; Ghidra rejects such paths.
  hint: choose a directory without leading-dot names, or omit the option to use the local workspace.
  log:  C:\cases\out\patchtrace.log
```

One error block per failure. Warnings use the same shape with `warning`. With `--json`, the same data appears under `error` / `warnings` in the result object, and stderr still gets the human form unless `-q` is set.

### 5.3 Signals and cancellation

- Windows: `SetConsoleCtrlHandler` maps CTRL_C, CTRL_BREAK and CTRL_CLOSE to `cancel.set()`. POSIX: SIGINT and SIGTERM do the same.
- A second Ctrl+C within 5 s skips publication of partial output and exits 130 immediately after the process-tree kill. The kill itself is never skipped.
- The Job Object kill-on-close (existing) guarantees the child dies even if PatchTrace is killed hard.

### 5.4 Run report (`--metadata-json`, `--json`, `<stem>.run.json`)

New pydantic model `CliRunReport` (schema `docs/schemas/CliRunReport.json`, `schema_version` 1):

```json
{
  "schema_version": 1,
  "tool": {"name": "PatchTrace", "version": "0.2.0", "git_commit": "…", "dirty": false, "frozen": true},
  "command": "diff",
  "argv": ["diff", "old.sys", "new.sys", "-o", "out"],
  "started": "2026-10-11T12:00:00Z", "finished": "2026-10-11T12:21:04Z", "duration_seconds": 1264.2,
  "exit_code": 0, "exit_name": "OK",
  "status": "completed",
  "error": null,
  "warnings": [{"code": "GP-ONEDRIVE", "message": "…", "path": "…"}],
  "inputs": [{"side": "older", "path": "C:\\bins\\old.sys", "name": "old.sys", "sha256": "…", "size": 123},
             {"side": "newer", "path": "C:\\bins\\new.sys", "name": "new.sys", "sha256": "…", "size": 125}],
  "environment": {"python_executable": "…", "python_version": "3.12.10", "ghidriff_version": "…",
                  "pyghidra_version": "…", "ghidra_version": "12.0.4", "java_home": "…",
                  "java_runtime_version": "unverified", "long_paths_enabled": false, "platform": "win32"},
  "settings": {"engine": "VersionTrackingDiff", "analysis": {"…": "…"}, "origins": {"analysis.bsim": "flag"}},
  "ghidriff": {"argv": ["…"], "cwd": "…", "env_set": {"GHIDRA_INSTALL_DIR": "…"}, "env_removed": ["PYTHONPATH", "PYTHONHOME"],
               "argv_sha256": "…", "returncode": 0, "workspace": "C:\\…\\work\\a6e3382d", "workspace_mode": "local",
               "capabilities": {"engines": ["SimpleDiff", "StructualGraphDiff", "VersionTrackingDiff"], "probed": true},
               "failure": null},
  "project": {"root": "…", "id": "…", "run_id": "…", "revision": 3},
  "results": {"counts": {"modified": 12, "added": 3, "deleted": 1}, "identical_inputs": false},
  "artifacts": [{"kind": "ghidriff-md", "path": "out\\old-new.ghidriff.md", "sha256": "…", "size": 4096}],
  "extensions": {}
}
```

The report is written even on failure (`status` ∈ `completed|no-differences|identical|failed|cancelled|timeout|dry-run`), unless the failure is that the report target itself cannot be written. In that case it is printed to stderr in JSON form and the command exits 7.

### 5.5 Artifact registry

`EMITTERS: dict[str, Emitter]`, where `Emitter = (kind, requires: set[str], produce(ctx) -> list[Path])`. Each kind resolves to files under `--out`:

| Kind | File(s) | Source |
|---|---|---|
| `ghidriff-md` | `<stem>.ghidriff.md` | upstream Markdown (verbatim) |
| `ghidriff-json` | `<stem>.ghidriff.json` | raw PDiff (verbatim, hash recorded in `AnalysisRun.raw_sha256`) |
| `matches-json` | `<stem>.matches.json` | upstream matches |
| `sxs-html` | `sxs/<stem>.combined.html`, `sxs/<stem>.<func>.html` | upstream side-by-side output. The `.md` suffix is renamed to `.html`. **Upstream content**: not covered by PatchTrace's self-contained, script-free HTML guarantee. The run report records this. |
| `ghidriff-log` | `<stem>.ghidriff.log` | engine log (redacted) |
| `report-md` / `report-html` / `report-json` | `<stem>.report.{md,html,json}` + manifest | `reports.export_project` |
| `summary` | `<stem>.summary.json` | Counts and the 25 lowest-similarity modified functions (name, old/new address, ratio). Includes the explicit note "similarity is not security relevance". Ranking (§7.1) extends this file. |
| `metadata` | `<stem>.run.json` | §5.4 |

Upstream files are copied from the project's retained `runs/<id>/raw`, so the emitted copy and the project copy are byte-identical. The report records SHA-256 for both.

---

## 6. Acceptance criteria and test cases

### 6.1 Acceptance criteria

| ID | Criterion | Evidence |
|---|---|---|
| R15 (A) | No Ghidra-facing argv path contains a dot-prefixed element, for any project location, including dot-prefixed, OneDrive and space-containing ones. Explicit unsafe overrides fail before launch with exit 2 and a `GP-*` code. A native Windows run from a project under `OneDrive - X\.cases\` completes. | T-A01…A12 + live L1 |
| R16 (B) | The same exe opens the GUI with no arguments and runs headless with a subcommand. Every ghidriff option in §3.8.1 is reachable and maps to exactly the documented argv. The exit codes in §3.9 are produced exactly. stdout carries results only. The CLI path never imports Qt. | T-B01…B20 + live L2, L3 |
| R17 (config) | GUI and CLI read and write one strict, versioned config. Precedence and provenance are as specified. No credentials are persisted. QSettings migration is lossless for the mapped keys. | T-C01…C07 |
| R18 (A3) | Every distributed exe reports its source commit. Release assets include the source archive. Builds from a dirty tree are rejected. Workspace naming exists only in `workspace.py`. | T-P01…P04 + Windows CI |

Mocked or fake-backend tests verify wiring and invariants only. They **MUST NOT** be recorded as live compatibility evidence (AGENTS.md). L1–L4 remain open release gates until a real Windows run passes, and each outcome is recorded in `../qa.md`.

### 6.2 Part A tests (`tests/test_workspace.py`, `tests/test_jobs.py`)

The fake ghidriff (`write_backend` fixture) is extended so that it **mimics Ghidra's rule over every Ghidra-facing path**. It parses its argv with the pinned upstream option names, applies ghidriff's default-derivation logic (§2.1), and exits 1 with `java.lang.IllegalArgumentException: Path element starting with '.' is not permitted` if any element of the effective project location, symbols, GZF or log path starts with `.`. It records its argv as JSON for assertions.

| ID | Test | Assertion |
|---|---|---|
| T-A01 | **Reproduce the bug.** Monkeypatch `workspace.validate_ghidra_paths` to return `[]` and force `--workspace project` with the project root at `tmp/.cases/p`. | The run fails. The exit code is 3. `analysis.log` contains `Path element starting with '.'`. The classifier reports `GF-DOTPATH`. The error names the log path. Prior project runs are unchanged. |
| T-A02 | **Verify the fix (same inputs, default settings).** Same project root `tmp/.cases/p`, real validator, default `--workspace local`. | Exit 0. One completed run. `runs/<id>/raw/json/*.ghidriff.json` exists. The fake's recorded argv passes T-A03's predicate. |
| T-A03 | **Regression predicate (parametrized).** Project roots: `tmp/p`, `tmp/.hidden/p`, `tmp/OneDrive - Lab/My Cases/p`, `tmp/über/p`, `tmp/a b/c d/p`, a symlink/junction to `.hidden`. | For every recorded argv, each value after `--output-path`, `--project-location`, `--symbols-path`, `--gzfs-path`, `--log-path`, and each positional input, has no element (literal or resolved) starting with `.`. The same holds for `--project-name` and the effective `<n>-<old>-<new>`. |
| T-A04 | Explicit unsafe override: `--ghidra-project-location tmp/.g`, and likewise `--symbols-path`, `--gzfs-path`, `--work-root` | Exit 2, `GP-DOT` naming the flag. `run_process` is never called (monkeypatched to fail). Nothing is created under the override. |
| T-A05 | `--workspace project` with a dot-prefixed project ancestor | Exit 2, `GP-DOT`. Inputs and prior runs preserved. A failed run is recorded with `failure.txt`. |
| T-A06 | `stage_name` table | Covers `.hidden.dll`→`older_hidden.dll`, `-x.sys`, 300-character names, unicode names, no extension, `CON.sys`, names with spaces. The output matches `^(older\|newer)_[A-Za-z0-9._-]{1,24}$` and never ends with `.`. |
| T-A07 | Static guard | AST/grep over `src/patchtrace` finds `'.quarantine'` or `"runs/."` only in the legacy-recognizer constant in `workspace.py`. |
| T-A08 | Legacy project | A project whose failed run has `raw_path='runs/.quarantine-<id>/raw/x.json'` loads, displays and exports. A new run on it succeeds. |
| T-A09 | `check_ghidra_path` unit table | One case per `GP-*` code with Windows rules injected via `platform='win32'`: UNC, `\\?\`, `NUL`, `com1.txt`, trailing dot/space, `:` mid-path, OneDrive environment variable present, non-ASCII. |
| T-A10 | `predict_deepest` | With long paths disabled, a work root of 200 characters → `GP-LENGTH` error. The default `%LOCALAPPDATA%`-like root of 50 characters with 24-character names → passes. Enabled → `GP-LENGTH-WARN` only. |
| T-A11 | Publish/cleanup | After success, `W` is gone (unless `--keep-workspace`). After failure, the quarantine contains `analysis.log`, `failure.txt` and `ghidriff.log`. `cleanup_stale_workspaces` never deletes a directory without a marker, nor one whose marker has a live PID. |
| T-A12 | Failure classifier fixtures | One log fixture per `GF-*` row. An unknown log → `None` and the generic message (with log path). |

### 6.3 Part B tests (`tests/test_cli.py`, `tests/test_entry.py`)

| ID | Test | Assertion |
|---|---|---|
| T-B01 | Golden help | `diff --help` and the top-level `--help` equal `tests/golden/*.txt` (normalized width 100). |
| T-B02 | No Qt on CLI path | Subprocess `python -c "import sys; from patchtrace.__main__ import main; rc=main(['diff','--dry-run',…]); assert not any(m.startswith('PySide6') for m in sys.modules)"` |
| T-B03 | `classify` table | Every row of §3.1, including a project directory dropped onto the exe and an unknown token → 64. |
| T-B04 | Flag → argv mapping (parametrized from one table) | For each row of §3.8.1 with a ghidriff argument: set the flag to a non-default value and assert the exact argv fragment and its position relative to `--`. Booleans are checked in both polarities. `--jvm-arg=-Xmx8G` → `--jvm-args=-Xmx8G`. `--engine structural-graph` → `StructualGraphDiff`. |
| T-B05 | Defaults explicit | With no tuning flags, the argv contains every option of §3.8.2 with the upstream default values. |
| T-B06 | `--print-command` fidelity | The printed JSON argv equals the fake backend's recorded argv byte-for-byte. The text line round-trips through `shlex.split` (POSIX) or `CommandLineToArgvW` (Windows-only test). |
| T-B07 | `--dry-run` changes nothing | Snapshot (path, size, mtime) of tmp, the work root and the config directory before and after → identical. The fake is never invoked. Exit 0. Output contains the plan and the command. |
| T-B08 | Exit 0 / 4 / 6 | The fake emits non-empty, empty and identical-input cases → 0, 4, 6. `--allow-empty` → 0. `--allow-identical` → 0. |
| T-B09 | Exit 2 | Missing Python, missing Ghidra root, probe failure, engine not in probed choices, `--max-ram-percent 0` (this one is 64: value validation is usage), invalid config file → 2. |
| T-B10 | Exit 3 / 9 / 124 / 130 | Fake exits 1 → 3. Fake writes an unrecognized JSON → 9 (quarantined). Fake sleeps longer than `--timeout 1` → 124. Cancel via SIGINT (POSIX test; Windows CI uses `GenerateConsoleCtrlEvent`) → 130 with no residual child (`psutil`-free check using the existing job/process-group helpers). |
| T-B11 | Exit 5 / 7 / 8 / 64 | Non-PE input → 5. Existing output without `--overwrite` → 7, before analysis. Project lock held by a second `ProjectService` → 8. Two NEW inputs → 64. Template `.x` → 64. Unknown `--emit` kind → 64. |
| T-B12 | stdout purity | `--json -q`: stdout parses as exactly one JSON document that validates against `CliRunReport.json`. stderr is empty on success. |
| T-B13 | Run report on failure | For each of exits 2, 3, 5, 9, 124 and 130, `<stem>.run.json` exists (when `--out` is writable), `status` and `exit_code` match, and the error has a PT code. |
| T-B14 | Emit registry | `--emit all` produces every file in §5.5. SHA-256 values in the report match the files. Emitted upstream files are byte-identical to `runs/<id>/raw`. |
| T-B15 | Project reuse | A second `diff` with the same inputs and `--project` appends a run (2 runs, revision incremented, earlier findings stale per SPEC-01). Different inputs → 8. |
| T-B16 | `doctor` | Fake environment fully valid → 0 and every check listed. Ghidra missing → 2. `--json` validates against the schema. |
| T-B17 | `--program-options` | Duplicate key, `NaN`, > 1 MiB, or missing `Analyzers` → 64/2 per §3.5, before launch. A valid file is copied into `W` and the argv points at the copy. |
| T-B18 | Capability gating | The probe lacks `--decompiler-timeout`: default value → omitted with a warning; non-default → exit 2. |
| T-B19 | `version --json` | Fields from SRC-3 present. From source: `frozen=false` and `git_commit` from `git rev-parse` or `"unknown"`. |
| T-B20 | GUI parity | `ui` Settings "Copy equivalent CLI command" produces argv that, when parsed by `cli`, yields an `EffectiveConfig` equal to the GUI's (pytest-qt). |

### 6.4 Live and Windows-only checks (release gates, tracked in `../../tasks/todo.md`)

| ID | Procedure | Pass condition |
|---|---|---|
| L1 | Rebuilt `PatchTrace.exe` on Windows 11. Project at `C:\Users\<u>\OneDrive - <org>\.cases\Patch Work\clfs`. Known-patch fixture DLLs (`tools/live_backend_check.py` pair). Run once from the GUI and once with `PatchTrace.exe diff`. | Both complete. The expected modified function is present. `run.json` shows `workspace_mode=local`. No `.quarantine` path appears anywhere in the logs. |
| L2 | `cmd.exe` and PowerShell: `PatchTrace.exe diff … & echo %ERRORLEVEL%` and `$LASTEXITCODE` for the 0, 2, 3 and 130 cases | Correct codes. Output appears in the invoking console. The shell waits. |
| L3 | Double-click `PatchTrace.exe` | The GUI opens. No persistent console window. |
| L4 | Calibrate `GHIDRA_SUFFIX_RESERVE`: with long paths **disabled**, run with a work root grown until failure | The recorded failing deepest path ≥ the prediction (no false pass). Update the constant and `../qa.md`. |
| L5 | `--java-home` pointing at a second JDK while `JAVA_HOME` points at an incompatible one | ghidriff uses the configured JDK (visible with `--print-jvm-flags`). If pyghidra ignores `JAVA_HOME`, record the limitation and document Ghidra's `java_home.save` instead. |

### 6.5 Config and packaging tests

| ID | Test |
|---|---|
| T-C01 | Round trip: `config init` → `config show --json` equals the defaults. `set`/`get`/`unset` per type. Invalid value → 2 and the file is unchanged. |
| T-C02 | Strictness: unknown top-level key, duplicate key, `schema_version: 2`, NaN → `PT-CONFIG`, exit 2. |
| T-C03 | Precedence matrix: each of the 5 layers overrides the layer below for `backend.ghidra_install_dir`. `--origin` reports the winning layer. |
| T-C04 | `--save-config` excludes inputs, `--out` and `--project`. Loading it reproduces an identical `ghidriff_argv_digest` for the same inputs and run ID. |
| T-C05 | Secret scan: after `interpret --api-key-env` (phase 2) and a GUI provider session, no config, log or run report contains the key (reuse the existing secret-scan helper). |
| T-C06 | QSettings migration from an INI fixture: all mapped keys are carried, geometry is not, and the result is idempotent. |
| T-C07 | GUI writes `analysis.bsim=false`, then the CLI `diff --dry-run --print-command` contains `--no-bsim`. |
| T-P01 | `build_windows.py` refuses a dirty tree (simulated with a temporary git repo). |
| T-P02 | `build-info.json` `source_sha256` is reproducible from `src/` (pure function test). |
| T-P03 | Windows CI: `PatchTrace.exe version --json` `git_commit == $GITHUB_SHA`. `PatchTrace.exe self-test` passes, including SRC-6. `PatchTrace.exe diff --dry-run` with a fake backend returns 0 and `$LASTEXITCODE` is 0. |
| T-P04 | Release assets include the binary ZIP, the source ZIP, both `.sha256` files and `SOURCE.txt`. |

Gate commands (unchanged): `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools`. Regenerate schemas after the model changes (`BackendCapabilities`, `PatchTraceConfig`, `CliRunReport`).

---

## 7. Future extension points (Part C)

Each extension has a reserved slot in five places, so none of them requires changing the contracts above:
1. a config sub-object under `extensions.<name>`
2. a subcommand name or a `diff` flag group
3. emit kind(s) in the artifact registry
4. a `CliRunReport.extensions.<name>` object
5. an exit code in 11–19 if it can fail on its own

Extensions that touch the network follow the explicit-transmission rule. Each one requires `--allow-network` (or a GUI confirmation that shows the exact URL and payload) and exits 11 on failure.

### 7.1 Function-change ranking / triage

- Module `ranking.py`. `Ranker` protocol: `score(match: FunctionMatch, project) -> RankResult{score: float in [0,1], signals: list[Signal{id, weight, evidence_ids}]}`. The score is a **heuristic triage order, not a probability**; this wording is required in output, following SPEC-01's "uncalibrated" rule.
- Initial signal catalog (each signal is a pure function over old/new decompiled text and instruction metadata, with fixtures):
  - added comparisons of a length or size variable against a constant or a field (`if (len > …)`)
  - changed relational operators (`<` ↔ `<=`)
  - new calls to validation or safe-arithmetic helpers (`RtlULongAdd`, `RtlSizeTMult`, `ProbeForRead/Write`, `memcpy_s`, `*_s`)
  - new `Feature_*` / `wil_details_FeatureStaging*` / `IsEnabled` rollout checks
  - new early returns of `STATUS_INVALID_PARAMETER`/`STATUS_BUFFER_TOO_SMALL`-style constants
  - added locking (`ExAcquire*`, `KeAcquireSpinLock*`)
  - added reference-count operations
- Hooks: `diff --rank` and `rank PROJECT_DIR`. Config: `extensions.ranking {enabled, weights{signal_id: float}, top_n}`. Emit kind `ranking` → `<stem>.ranking.json`, and the `summary` file gains `ranking` ordering. The GUI navigator gains a sort key. Every signal cites `EvidenceReference` ranges, so the AI context builder can reuse them.

### 7.2 CVE correlation

- Module `cve.py`. `CveSource` protocol with MSRC CVRF and NVD 2.0 implementations. Imports pass through `strict_json` with size caps (2 MiB) and are cached by CVE ID under the cache root (§7.4).
- `cve PROJECT_DIR CVE-2026-XXXXX [--source msrc|nvd] [--from-file FILE] --allow-network`. Matching extracts component and impact keywords from the description, scores them against function names, strings, imports and ranking signals, and outputs `CveCorrelation{cve, description_digest, candidates[{match_id, score, reasons}]}`.
- Emit kind `cve` → `<stem>.cve.json`. **Only the CVE ID is transmitted.** No binary or code data leaves the machine. The SPEC-01 rule "no inferred CVE/severity" for model output stays. Correlation is a separate, labeled heuristic.

### 7.3 Binary acquisition (Winbindex / Microsoft Symbol Server)

- `InputSpec` resolver for `diff` positionals. A plain path means a local file. `wb:<name>@<selector>` means acquisition. A scheme of two or more characters avoids ambiguity with `C:`. Selector: `YYYY-MM` (Patch Tuesday month), `kb:<KB>`, `ver:<file version>`, plus `arch=amd64` and `os=<build>` qualifiers.
- In phases 1–2, any `scheme:` input exits 64 "acquisition not implemented".
- `fetch` subcommand and `diff wb:clfs.sys@2026-06 wb:clfs.sys@2026-07 --allow-network`:
  1. Winbindex metadata gives SHA-256, `TimeDateStamp` and `SizeOfImage`.
  2. Download from `https://msdl.microsoft.com/download/symbols/<name>/<TimeDateStamp:08X><SizeOfImage:X>/<name>`.
  3. Verify the SHA-256 against the metadata, then hand the file to `inspect_artifact` (never executed or installed).
- Config `extensions.acquisition {winbindex_base_url, cache_dir, user_agent}`. The run report records source URLs and hashes.

### 7.4 Diff/result caching

- Key = SHA-256 of the canonical JSON `{old_sha256, new_sha256, engine, effective analysis options, ghidriff_version, pyghidra_version, ghidra_version, adapter_version}`. This is the key SPEC-01 requires ("no cache use until keyed by hashes/version/settings").
- Store: `<cache_root>/<k[:2]>/<k>/{pdiff.json, manifest.json}`. The cache root is validated like a work root because it may host persistent Ghidra projects and GZFs. A per-binary analysis cache (`gzf/` keyed by input SHA-256 + analysis options) feeds ghidriff's `--gzfs-path` / persistent `--ghidra-project-location`.
- Flags reserved now: `--cache/--no-cache` (default off until implemented), `--cache-dir`, and a `cache {list,verify,purge}` subcommand. A cache hit creates a **new** `AnalysisRun` with `settings.cache_hit=true` and the source run ID. Raw bytes are re-verified by hash before reuse. Exit 12 is reserved for `CACHE_CORRUPT`.

### 7.5 Interop / export

- Emit kinds `bindiff` and `binexport`. These need the external BinExport Ghidra extension, which is detected by `doctor --deep`, and they are produced by a separate post-analysis step on the kept Ghidra project, which therefore requires `--keep-ghidra-project`.
- `capa`: an external `capa` executable path in `extensions.capa.executable`. capa analyzes the binaries statically (it does not execute them). Its JSON (strict import) is mapped by function address onto `FunctionRecord`s as `capabilities: list[str]` labels. Emit kind `capa` → `<stem>.capa.json`. The ranking signal `capa-label-changed` becomes available.
- The exporter registry (§5.5) is the extension seam. New kinds register `(kind, requires, produce)` and automatically appear in `--emit` validation and help.

### 7.6 Pluggable AI interpretation

- `providers.py` gains a registry `PROVIDERS: dict[str, ProviderFactory]` keyed by `provider.kind`. Built-ins: `ollama` (loopback only) and `openai-compatible` (HTTPS only). Frozen builds cannot load arbitrary Python plugins. New providers are added in source and released, or reached through the `openai-compatible` transport.
- Invariants that no provider can bypass:
  - exact preview and digest-gated send (§3.7)
  - strict JSON response
  - citation validation against the exact context
  - session-only credentials
  - no tool or command execution
- Config `provider.*` (already shared). `extensions.interpretation {prompt_profile, max_output_bytes}`. The `Interpret selection` GUI action and the `interpret` subcommand call the same `interpretation.interpret(context, provider)`.

### 7.7 N-way / series

- The parser already accepts several NEW inputs and `--summary-diff` and rejects them with 64.
- The future implementation creates a `series` of adjacent pairwise PatchTrace projects. A series is a new aggregate, so the two-artifact `ComparisonProject` contract is unchanged. ghidriff is invoked once with all inputs (upstream supports `old new [new …]` and `--summary`), and the PDiffs are split per pair by `old_meta`/`new_meta` hashes.
- Exit code semantics: the worst pair result wins, ordered 3 > 9 > 0 > 4 > 6.

---

## 8. Implementation order and done criteria

1. Spec and index updates (this document, `../modules.md`, `verification.md` R15–R18, `../../tasks/todo.md`).
2. `workspace.py` + backend changes + fake-Ghidra fixture → T-A*. **This alone fixes Part A for GUI users.**
3. `config.py` + GUI Settings migration → T-C*.
4. `analysis.py` (extract GUI orchestration, no behavior change; the existing UI tests must stay green).
5. `cli.py` + `entry` + exit codes + run report → T-B*.
6. Packaging (console subsystem, provenance, source ZIP) → T-P*. Windows CI.
7. Phase 2 commands. Live gates L1–L5 recorded in `../qa.md`.

The work is not complete while any of L1–L5 or a phase-1 test is unverified. Blocked live checks stay open in `../../tasks/todo.md` and are never counted as passed.
