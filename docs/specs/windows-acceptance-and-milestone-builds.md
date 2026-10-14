# Windows acceptance and milestone builds

Status: draft spec, 2026-10-14. Sections marked **(new)** are not implemented; everything else describes current behaviour.

Observed state (read-only GitHub REST, 2026-10-14; re-check before acting): remote `main` = `4985132535` (local HEAD `c0df3ad` adds this file and is unpushed); open PRs = 0; latest prerelease `v0.1.0-beta.131` targets `b7e819a`. The `main` push run 135 at `4985132` **failed in `qa (ubuntu-latest)`** at the `pytest` step, so `release` was skipped and no prerelease exists for that commit. The run log was not retrievable from this session, so the failing test is unknown.

---

## 1. Milestone build policy

### 1.1 What publishes today

From `.github/workflows/qa-windows.yml`:

| Trigger | Jobs that run | Publishes a GitHub prerelease? |
|---|---|---|
| `push` to `main` | `qa` (ubuntu-latest, windows-latest), `linux-package`, `linux-smoke` (22.04, 24.04), `release` | Yes, only if `qa` and `linux-smoke` succeed. Tag `v0.1.0-beta.<run_number>` |
| `push` of a tag matching `v*` | same jobs | Yes. The tag name is used as the release tag |
| `pull_request`, `workflow_dispatch` | QA jobs only | No |

- `live-backend.yml` (native Ghidriff matrix) never publishes. It is a gate for the same SHA.
- The `release` job has no `paths` filter, so docs-only merges to `main` also publish. Decide whether this is wanted (open decision).
- `run_number` counts every run of the workflow, including PR and failed runs. Observed tags therefore have gaps (beta.118, .120, .127, .129, .131).
- Release body is hard-coded and says "beta"; `target_commitish` is `github.sha`.
- Uploaded release assets (`release/*`): `PatchTrace-0.1.0-windows-x64.zip`, `PatchTrace-0.1.0-windows-x64.zip.sha256`, `PatchTrace-0.1.0-linux-x86_64.tar.gz`, `PatchTrace-0.1.0-linux-x86_64.tar.gz.sha256`. The version `0.1.0` is hard-coded in `pyproject.toml`, both build scripts and the workflow, so the tag is not in the filenames.
- Known failure mode: publishing returns HTTP 403 `Resource not accessible by integration` when the head commit adds or changes `.github/workflows/*` (see `docs/plans/phase-c-multi-engine-plan.md`, handoff B1). The build is green but no release exists. The ZIP and tarball remain as Actions artifacts `PatchTrace-windows-x64` and `PatchTrace-linux-x86_64`. Report such a run as "build green, publish failed", never as a release.

### 1.2 Which commits are milestone candidates

A commit is a **milestone candidate** only when all of these hold on that exact SHA:

1. `qa (ubuntu-latest)`, `qa (windows-latest)`, `linux-smoke (ubuntu-22.04)` and `linux-smoke (ubuntu-24.04)` are green.
2. `Native Windows Ghidriff acceptance` is green when `src/**`, `tools/live_*`, `tools/seed_symbol_cache.py` or `tests/fixtures/**` changed.
3. The automated additions in section 2 are green (once implemented).
4. The release notes (section 4) list every open gate. No manual check is marked passed without a row in the section 3 record.

Naming:

- `v0.1.0-beta.<run_number>` remains the automatic integration build from `main`. It is not an acceptance statement.
- Acceptance candidates use an **annotated** tag on the reviewed SHA: `v0.1.0-alpha.<n>` (n starts at 1 and never reuses a number).
- **(new)** The workflow currently hard-codes the release name `PatchTrace beta <run_number>` and the beta body for every tag. Before the first alpha tag, change the release name and body to derive from `github.ref_name`. Until then, a tag push publishes under a misleading name and must not be advertised as alpha.

### 1.3 Verification after each release

Replace `<TAG>` and `<SHA>`. Use an empty directory for downloads.

```bash
# Metadata: target commit, prerelease flag, asset list
gh release view "<TAG>" --repo djshellshoxxx/patchtrace \
  --json tagName,isPrerelease,targetCommitish,assets \
  --jq '{tagName,isPrerelease,targetCommitish,assets:[.assets[].name]}'

# Tag must peel to the reviewed SHA
git ls-remote --tags origin "refs/tags/<TAG>^{}"

# Download and verify both artifacts
gh release download "<TAG>" --repo djshellshoxxx/patchtrace --dir "<EMPTY_DIR>"
cd "<EMPTY_DIR>" && sha256sum -c PatchTrace-0.1.0-windows-x64.zip.sha256
```

PowerShell (sidecar is `<sha256>  <name>`, two spaces):

```powershell
$zip = 'PatchTrace-0.1.0-windows-x64.zip'
$exp = (Get-Content "$zip.sha256").Split(' ')[0].ToLower()
$got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($exp -ne $got) { throw "SHA-256 mismatch: $got" }
Expand-Archive $zip -DestinationPath .\extract
Test-Path .\extract\PatchTrace\PatchTrace.exe, .\extract\PatchTrace\file-inventory.json, .\extract\PatchTrace\dependency-versions.json
```

Then compare the digest with the Actions artifact of the same run (`gh run download <RUN_ID> -n PatchTrace-windows-x64`), and record in `docs/qa.md`: tag, peeled SHA, run URL and number, both sizes, both SHA-256 values. If publishing returned 403, record the Actions artifact and "release not published".

---

## 2. Automated Windows acceptance additions

Existing: `tools/build_windows.py` runs the frozen `--self-test` and `rank --help` after freezing. Windows-only Job Object tests in `tests/test_jobs.py` are skipped on Linux. The native Ghidriff matrix covers the known DLL patch and raw cache hit.

Exit codes (`src/patchtrace/cli.py`): 0 success, 2 invalid arguments or environment, 3 runtime failure, 4 no results, 5 cancelled. Unknown first arguments reach the CLI and must exit 2 (`tools/desktop_entry.py`).

| ID | Status | Test | Command or method | Pass criterion |
|---|---|---|---|---|
| A1 | partly existing | Frozen CLI help for every command | `.\PatchTrace.exe <cmd> --help` for `rank flags correlate cache acquire series secondary` | Each exits 0, prints `usage:` to stdout |
| A2 | implemented | Frozen usage error | `.\PatchTrace.exe bogus-command` | Exit 2, no traceback on stderr |
| A3 | implemented | Frozen missing project | `.\PatchTrace.exe rank C:\does\not\exist` (check the positional form with `rank --help` first) | Exit 2, actionable message, no Qt window |
| A4 | existing, extend | Frozen desktop self-test | `$env:QT_QPA_PLATFORM='offscreen'; .\PatchTrace.exe --self-test` | Exit 0; temporary `patchtrace-self-test-*` directory removed afterwards |
| A5 | implemented in `tools/frozen_smoke.py` (CI-only for the frozen EXE) | Frozen JSON contract | `.\PatchTrace.exe rank <sample-project> --json` | Exit 0 or 4; stdout is exactly one JSON document; stderr holds diagnostics only |
| A6 | **(new)** | Native 3-build N-way series | `.\PatchTrace.exe series create --builds v1.dll v2.dll v3.dll --root C:\gout\series --labels a b c --run --python <venv python> --ghidra-dir <ghidra> ` then `series chains --json` | Exit 0; two hops in `series.json`; each pair exit 0 or 4; chains list parses. Needs a third fixture DLL (`tests/fixtures/` currently has old and new only) |
| A7 | **(new)** | Job Object containment, kill-on-close | Harness process starts `run_process` on a child that spawns a grandchild sleeping 300 s; `taskkill /F` the harness | Grandchild PID absent within 5 s (`tasklist /FI "PID eq <pid>"` returns no match) |
| A8 | **(new)** | Job Object cancel and timeout | Same tree; cancel, then separately time out | No surviving PID; process returns cancelled or timeout status |
| A9 | **(new, after C1)** | Scheduler fan-out cancel | Two fake engines, one cancel event | Both children gone; each outcome reports its own status |
| A10 | partly implemented (spaces, Unicode, OneDrive-style, 200-char; no trailing-dot/reserved names), `tools/frozen_smoke.py` and `tests/test_acceptance_smoke.py` | Path cases (pytest, `windows-latest`) | Parametrised `tmp_path` roots: spaces; Unicode (`Проект\дело`, `研究`); OneDrive-style `OneDrive - <Org>\PatchTrace`; path over 240 characters; trailing dot or space segment; reserved names `CON`, `NUL` | Project create, open, save round trip works, or fails with the existing actionable error. Never a traceback. Ranking output equals the ASCII-path baseline |
| A11 | **(new)** | Transient files off the sync folder | Create a project under a OneDrive-style root, run analysis with fake runtime | Scratch and GZF paths are local temporary paths (see `src/patchtrace/backend.py` around line 446), not under the sync root |
| A12 | **(new)** | Antivirus or other process holding a file | Helper opens the artifact or project file with share mode `None`; PatchTrace attempts export or save | Clear error, no crash, no partial output file, project SQLite hash unchanged |
| A13 | implemented in `tools/frozen_smoke.py` (SPEC-31 S1, A-20) | Frozen unified-engine package contents | `tools/frozen_smoke.py dist/PatchTrace/PatchTrace.exe` (check U1; U2 runs `unified --help` and `unified _worker --self-check` as soon as `src/patchtrace/unified/cli.py` exists in the tree) | The extractor script `patchtrace/unified/extract/ghidra_script.py` is in the onedir exactly once and byte-identical to the source tree, `licenses/upstream/bindiff-v8-aecc14d/LICENSE` ships; `tools/build_windows.py` and `tools/build_linux.py` refuse to publish without both |

Run A2 to A5 in the release job after `tools/build_windows.py`. Run A6 to A8 in the native matrix (`live-backend.yml`). Windows-only tests stay `skipif(os.name != 'nt')`, and the CI summary must list which of them ran.

A7 must drive the real `jobs.run_process` path and write the grandchild PID to a temp file for the assertion. A PowerShell-only harness proves nothing about PatchTrace.

---

## 3. Manual acceptance checklist (clean Windows 11 profile)

Not automatable here. Nothing counts as passed until a named tester records it.

Setup:

1. Clean Windows 11 x64 profile, or a new local account with no Python, Java, Ghidra or Ghidriff installed.
2. Record `winver` build, display scale, theme, ZIP SHA-256, tester, date. Keep Defender real-time protection on.
3. Extract the ZIP to `%USERPROFILE%\Downloads\PatchTrace`; repeat M03, M04 and M18 from a OneDrive-synced folder if available.

Result is `pass`, `fail` or `not-run`; default `not-run`.

| ID | Check | Steps | Expected result |
|---|---|---|---|
| M01 | Launch | Double-click `PatchTrace.exe` | Window appears within 15 s; no error dialog; no console window left open |
| M02 | Sample | Open Sample | Project label contains `SYNTHETIC SAMPLE`; matches list is non-empty |
| M03 | New project | New, choose a folder whose name has a space | Project created; closing and reopening it works |
| M04 | File overview | Open File overview before any analysis | PE metadata for both files shown without analysis; changed and unchanged fields distinguishable |
| M05 | Raw views | Hex, Binary, Base64; whole file and from function entry; page forward and back; go to offset; enter an out-of-range offset | Values match the original bytes; out-of-range offset gives a message, no crash |
| M06 | Tooltips, main window | Hover each toolbar control and each File overview row | Readable text with WHAT, WHY and SOURCE; no visible markup tags |
| M07 | Tooltips, disabled controls | Open Setup; hover disabled controls | Tooltip states why the control is disabled |
| M08 | DPI 100% | Settings, Display scale 100%; use every main tab | No clipped labels or buttons; tables readable |
| M09 | DPI 150% | Same at 150% | Same as M08 |
| M10 | DPI 200% | Same at 200% | Same as M08; no controls hidden |
| M11 | High contrast | Settings, Accessibility, Contrast themes, high contrast | Text legible; keyboard focus visible on every focused control |
| M12 | Resize and keyboard | Shrink to about 800 x 600, then maximise; Tab through the main controls | Splitter panes keep content; no clipped page without scrolling; focus order follows layout |
| M13 | Export | Export each format offered in the UI | File created; content matches the on-screen ranking and preview |
| M14 | Cancel analysis | Start analysis with a configured native runtime; cancel after about 30 s | Status shows cancelled; no `java.exe`, `ghidra` or Ghidriff child left in Task Manager within 10 s |
| M15 | Close during analysis | Close the window while analysis runs | Prompt or clean stop; afterwards no residual `java.exe`; project opens without a lock error |
| M16 | Antivirus or file lock | Hold the export target or project file open exclusively (helper as in A12); attempt export and save | Clear error; no crash; no partial file; project still opens |
| M17 | Restart persistence | Quit and relaunch | Last project and settings restored |
| M18 | Unicode path | Project folder with non-ASCII name; open, export | Works; exported file name and content correct |

Record table (copy per test run; one row per check):

| ID | Result (pass / fail / not-run) | Windows build | ZIP SHA-256 (first 12) | Tester | Date | Evidence or notes |
|---|---|---|---|---|---|---|
| M01 | not-run | | | | | |
| M02 | not-run | | | | | |
| M03 | not-run | | | | | |
| M04 | not-run | | | | | |
| M05 | not-run | | | | | |
| M06 | not-run | | | | | |
| M07 | not-run | | | | | |
| M08 | not-run | | | | | |
| M09 | not-run | | | | | |
| M10 | not-run | | | | | |
| M11 | not-run | | | | | |
| M12 | not-run | | | | | |
| M13 | not-run | | | | | |
| M14 | not-run | | | | | |
| M15 | not-run | | | | | |
| M16 | not-run | | | | | |
| M17 | not-run | | | | | |
| M18 | not-run | | | | | |

A `fail` links to an issue and states observed behaviour. A check not performed stays `not-run` with the reason. Never copy a result to a new SHA.

---

## 4. Release-notes template (every milestone; never write "production ready")

```markdown
## PatchTrace <TAG> - <one-line purpose>

Commit: <full SHA> (<main | tag>) - Run: <run URL> (run number <n>)
Assets:
- PatchTrace-0.1.0-windows-x64.zip - <bytes> bytes - SHA-256 <hex>
- PatchTrace-0.1.0-linux-x86_64.tar.gz - <bytes> bytes - SHA-256 <hex>
Verify: `sha256sum -c <file>.sha256`. Extract the whole ZIP before running PatchTrace.exe.

### What changed
- #<PR> <title> - <one line>

### Automated evidence (this SHA only)
| Check | Result | Link |
|---|---|---|
| Linux pytest | <passed / skipped / failed counts> | <run> |
| Windows pytest | <counts> | <run> |
| Ruff | pass / fail | <run> |
| Linux package and smoke, 22.04 and 24.04 | pass / fail | <run> |
| Windows frozen self-test and rank --help | pass / fail | <run> |
| Section 2 additions A1-A12 | <which ran, which did not exist> | <run> |
| Native Ghidriff matrix (5 variants) | pass / fail | <run> |

### Manual evidence
Clean Windows 11 checklist (section 3): <n> pass, <n> fail, <n> not-run. Record: <link or path in docs/qa.md>. A gate leaves "Open" only with a recorded pass and evidence link.

### Open gates (not passed in this build)
- Clean Windows GUI acceptance M01-M18 (unless listed as pass above)
- Live local and remote AI provider acceptance (no credentials supplied)
- Relocatable offline backend bundle and disconnected Windows acceptance
- Confirmed Windows OneDrive-backed real Ghidriff analysis
- rz-diff and BinDiff live runs
- Matching accuracy and performance: unmeasured, no claim made

- Limitations: unsigned beta; Ghidra, Java and Ghidriff external. Release publication: <published | not published (403), Actions artifact only>.
```