# E-6 plan: final feature audit, bug check, scripted beta, performance, Windows smoke

Status: plan, 2026-10-14. Base: `main` 67e5a6c (PR #42 merged). Owner: whoever runs phase E-6 (roadmap section 1). Documents only; no source change.
Authority: `AGENTS.md`, `CLAUDE.md`, `docs/plans/program-e-roadmap.md` (charter section 3, gates section 5), `docs/qa.md`, `docs/specs/windows-acceptance-and-milestone-builds.md` (A1-A12, M01-M18). Where this plan names a tool or fixture, the path was checked on main; items that do not exist yet are marked **(to build)**.

## 0. Rules for this phase

1. Automated evidence and owner-only evidence are reported in two separate tables. A row in the owner-only table (section 7) is never counted as done by any bot.
2. A scenario passes only on its stated, checked output. "Did not crash" is not a pass. A mocked or fake-executable run is wiring evidence, never live-compatibility evidence (`AGENTS.md`).
3. Prerelease only. No final release, and no claim of a GitHub Release unless the asset and its sha256 were fetched back and compared (roadmap standing rules).
4. No Microsoft binary, PDB or Winbindex-derived label enters the repository or CI logs. Every fixture below is synthetic or self-made.
5. A failing test is fixed or recorded in `docs/qa.md` with the exact command and output; it is never skipped to get green.
6. Every number in a report states host, Python, Qt version, repeat count and whether it is local Linux, CI Linux or CI Windows.

## 1. Entry criteria (do not start E-6 until all hold)

| # | Criterion | Check |
|---|---|---|
| X1 | Roadmap E-3, E-4 and E-5 exit gates passed; ledger rows `done` | `docs/plans/program-e-roadmap.md` section 7 |
| X2 | `main` SHA recorded; all open PRs listed with checks (CLAUDE.md rule) | `gh pr list`, `gh run list --branch main` |
| X3 | Last E-4 audit findings closed or recorded in `docs/qa.md` | grep `E-4` in `docs/qa.md` |
| X4 | Schemas regenerated, drift test green | `python tools/generate_schemas.py` then `git diff --exit-code docs/schemas` |
| X5 | `docs/specs/REGISTRY.md` statuses refreshed (snapshot at 1560531, older than PR #42; known stale rows in `OUTSTANDING-specs-ledger.md` section 3) | read-through |

## 2. Final feature audit checklist

Method: one read-only auditor per row group, never the builder of that feature. The auditor fills the matrix from code and tests, not from a spec's own status line. Charter items are `docs/plans/program-e-roadmap.md` section 3 (C1 pair-aware, C2 delta, C3 anchors in/out, C4 triage, C5 one click to code, C6 provenance, C7 offline-first, C8 teachable, C9 synergy test). Evidence per cell: a file path plus a test name, or the word `absent`.

### 2.1 Matrix (one row per track; columns C1..C9 plus extra items)

| Track | Code location expected | Extra "feature done" items (roadmap section 5) |
|---|---|---|
| UE unified engine (SPEC-31) | `src/patchtrace/unified/` (main has S0a only: contracts, keys, limits, store) | GUI offscreen x20, tooltip ids, accessibility names, frozen smoke imports it |
| KB-CVE + KB patch search (SPEC-34/37) | `acquisition/`, planned KB package | consent preview shown before any fetch |
| LBL label training (SPEC-32/33/39) | `tools/calibration/`, `src/patchtrace/calibration/` | honest-scope artifact; `display_level()` stays `ordinal` until the locked test passes |
| WB1 search, WB2 call graph, WB3 strings, WBQ quick wins | per `docs/specs/workbench/` (on PR #43 at the registry snapshot) | virtualized at 100k rows (section 5) |
| CAP capa, DIE Detect It Easy, FLOSS | `intelligence/tools/{capa,floss,diec}.py` exist on main | DiE value gate stays `unvalidated` unless benchmarked |
| YRX YARA-X, KEV | to be located from the E-1 plans | rule provenance; KEV never treated as a score |
| PIL patch intent + CSAF | `intelligence/csaf/`, `intelligence/hypotheses.py` | advisory text bounded and escaped |
| FAB anchor fabric | `intelligence/anchors.py`, `enrichment/storage.py` kinds | shared-origin evidence counted once (test name required) |
| GUI panel registry | `ui*.py`, `tooltips.py` | single main window (finding F1 in the ledger: `ui_series.SeriesWindow` is a `QMainWindow`) |
| GDE teacher (E-5) | to be located | every lesson step resolves to a real feature id; no AI call |
| Existing: enrichment, N-way, BinDiff/BinExport/rz-diff, evidence panel, acquisition, PE overview, raw views | see `docs/modules.md` | regression only |

### 2.2 Cross-cutting checks (scripted or grep, on the release-candidate SHA)

| ID | Check | How | Pass |
|---|---|---|---|
| FA1 | No target-binary execution | grep `subprocess`, `Popen`, `os.system`, `ctypes` calls; every spawn goes through `jobs.run_process`; argv built from allowlists | only reviewed hits, each in a documented adapter |
| FA2 | No silent network | run the suite with sockets blocked (wrapper that patches `socket.socket.connect`) | zero non-declared-live tests open a socket |
| FA3 | Strict JSON only | grep `json.loads(` for untrusted inputs lacking duplicate-key and NaN rejection | each hit is a trusted file or uses the strict helper |
| FA4 | Orientation explicit | every exported two-sided record carries `older`/`newer` literals | schema review |
| FA5 | Uncalibrated number never shown as confidence | search UI strings and report templates for "confidence", "probability", "likelihood" | each hit labels a calibrated field or says ordinal |
| FA6 | Tooltip and accessible-name coverage | `tests/test_tooltips.py` enumeration; add a test that every interactive widget has non-empty `accessibleName` **(to build)** | zero uncovered widgets |
| FA7 | Single main window | construct `MainWindow`, open every feature, assert one visible top-level (message boxes excluded) | exactly one |
| FA8 | Schema drift | `tools/generate_schemas.py` plus drift test | clean |
| FA9 | Licences and notices | frozen package carries notices for Qt, protobuf and each pinned tool; no GPL/AGPL source copied (Ghidriff, Diaphora, PatchDiff2, Turbodiff are references only) | `tools/build_windows.py` notice guard green |
| FA10 | Persisted contracts additive | open a project written by the previous prerelease with the new build | opens, nothing rewritten |
| FA11 | Docs match code | `docs/modules.md` has a row for every package under `src/patchtrace`; `tests/test_spec_registry.py` green | no orphan package |
| FA12 | Tracker hygiene | `tasks/todo.md` repeats lines (series window and 3c/3d appear 2-4 times); collapse and mark superseded | one line per item |

Output: `docs/qa.md` section "E-6 feature audit" with the filled matrix; each `absent` becomes a fix, an owner-approved deferral, or a blocked-external entry.

## 3. Bug-check procedure

Run in order; fix between stages so a later stage never runs on a known-red base.

1. **Static**: `python -m ruff check src tests tools`; review new contracts for strict/frozen pydantic. Pass: clean.
2. **Unit and integration, Linux**: `QT_QPA_PLATFORM=offscreen python -m pytest -q`, twice (order independence, no leaked state). Pass: identical counts, 0 failed, skips only where a test declares Windows-only.
3. **Qt stability**: GUI subset (`tests/test_ui*.py`, `test_evidence_ui.py`, `test_inspection_row_tooltips.py`) 20 times without abort: `for i in $(seq 20); do QT_QPA_PLATFORM=offscreen python -m pytest -q -x tests/test_ui*.py tests/test_evidence_ui.py || break; done`. Pass: 20 of 20, no `Fatal Python error`, no "QThread destroyed while running".
4. **Windows CI** (`.github/workflows/qa-windows.yml`): same suite plus frozen smoke. Windows checklist (roadmap section 4): CRLF on pinned/generated files, 32767-character `PYTEST_CURRENT_TEST` (short explicit parametrize ids), coarse `time.monotonic()` (`>=`), YAML plain scalars containing `: `, `--only-binary=:all:`, hermetic tests.
5. **Property and fuzz**: existing `hypothesis` suites (`test_binexport_property.py`) and nightly `tools/fuzz_binexport.py`; every parser added in E-3 (CSAF, capa/FLOSS/diec JSON, KEV feed, YARA-X output) needs one hostile-input property; the auditor lists any parser without one.
6. **Leak and teardown**: Qt loop under `python -X dev -W error::ResourceWarning`; assert no thread alive after window close (class of the 2026-10-12 "inspection thread teardown" defect).
7. **Process containment (A7-A9)**: Windows-only tests driving `jobs.run_process` with a grandchild; no surviving PID within 5 s.
8. **Round trip and compatibility**: open each committed project fixture from the previous prerelease; export every report format; compare to goldens.
9. **Triage**: P0 data loss, security-invariant break, crash on launch; P1 wrong result shown as right; P2 wrong or missing explanation; P3 cosmetic. P0/P1 block the build. Each finding gets a red test before the fix and a `docs/qa.md` line with the commit.

Bug-hunter themes (read-only, one each): (a) untrusted text rendering (HTML/Markdown injection via advisory, string, rule, KB text); (b) paths (spaces, Unicode, OneDrive-style, 260 characters, reserved names); (c) cancellation and timeouts for every child process and network call; (d) SQLite thread ownership and locks; (e) orientation and stale-cache mix-ups (swap older/newer and assert the output changes meaning); (f) numeric display (no NaN/inf, no percent for ordinal scores).

## 4. Scripted beta scenarios (synthetic, fixture-based, no Microsoft binaries)

A script set in `tools/beta/` **(to build, one Sonnet worker, exclusive directory)** drives the CLI and, where stated, the offscreen GUI. Each step prints `PASS`/`FAIL`; any FAIL exits 1 (style of `tools/frozen_smoke.py`). Inputs come only from `patchtrace.sample.synthetic_pe(variant)` (explicit synthetic PE, never executed), `tests/fixtures/` (`binexport/`, `secondary/`, `csaf/`, `cve/`, `intel_tools/`, `tier_w/` self-made PE+PDB, `winbindex/afd.sys.json` metadata only), and projects the harness generates with imported synthetic Ghidriff JSON (no Ghidra run), as `tools/frozen_smoke.py` A5/A6s already do. The launcher is a parameter: `python -m patchtrace` on Linux/CI, `PatchTrace.exe` for the frozen run.

Expected outputs below are checkable properties. Exact values are pinned in `tools/beta/expected.json` on the first green Linux run, reviewed by a human, and the Windows run must reproduce them byte for byte (cross-platform determinism).

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| B01 | First launch, sample | offscreen start; `MainWindow.open_sample()`; `--self-test` | project label contains `SYNTHETIC SAMPLE`; match list non-empty; one visible top-level; self-test exit 0 and `patchtrace-self-test-*` removed |
| B02 | Rank a known patch | generated project from `sample.OLD_CODE`/`NEW_CODE` (added `if (buffer == NULL \|\| index >= length)`); `rank <proj> --json` | exit 0; one JSON document; `read_item` is rank 1; explanation names the added bounds check; second run reports a cache hit |
| B03 | Orientation swap | same project with older/newer exchanged | the check is reported as removed, not added; no record keeps the old orientation |
| B04 | Identical build (A/A) | two identical synthetic PEs | no changed functions; no attention above the noise floor; UI states "nothing changed" |
| B05 | Layout-only noise | pair where only addresses shift | classified address-only; ranked below any semantic change; no vulnerability wording |
| B06 | CVE context offline | `correlate <proj> --cve CVE-2024-38063 --snapshot tests/fixtures/cve/nvd_CVE-2024-38063.json --snapshot tests/fixtures/cve/msrc_CVE-2024-38063.json` | exit 0; base ranking unchanged; CVE context shown separately; zero sockets (FA2) |
| B07 | Network refusal | `correlate --fetch` without matching `--consent-providers` | exit 2 with consent message; zero sockets |
| B08 | CSAF advisory | validator and applicability over `csaf/synthetic-advisory-rev1.json`, `-rev2.json`, `synthetic-vex.json` | rev2 supersedes rev1 with an explicit revision note; VEX shown as advisory context; unmapped product reported `unknown`, never `not affected` |
| B09 | Hostile advisory text | field with `<script>`, 1 MiB text, control characters | escaped and truncated at the documented bound; label says truncated; plain text only (`Qt.PlainText`) |
| B10 | Tool evidence | `intel_tools/{capa,floss,diec}` goldens through the adapters on a synthetic pair | capability, string and packer deltas per side; an absent tool shows `unavailable`, never a negative vote; shared-origin evidence counted once |
| B11 | BinExport acceptance | `secondary binexport-check` on `binexport/synthetic-older.BinExport` and on a JSON renamed to `.BinExport` | first exit 0 (pinned protobuf with upb); lookalike exit 2, reason slug, no traceback (frozen B1/B2) |
| B12 | Second opinion | `secondary import-bindiff` with `secondary/bindiff-v8-real-on-synthetic.BinDiff` on its synthetic pair, then `secondary reconcile` | agree/contested/unknown counts equal the golden; Ghidriff records unchanged byte for byte |
| B13 | Engine absent | `secondary run --engine rz-diff` with no rz-diff | status `unsupported` with reason; core analysis unaffected; exit per CLI contract |
| B14 | Series of three | `series create` over three synthetic builds with imported results (frozen A6s), then `series chains --json` | two hops, one three-node chain, per-hop attention from stored ranking; one locked pair degrades to "no score" |
| B15 | Series view | offscreen Series window on B14's root | ready, partial and stale states render; a corrupt sibling gives a banner, not a crash |
| B16 | Acquisition metadata only | `acquire search` over `winbindex/afd.sys.json` through a fake transport | sorted candidates; consent host must equal `winbindex.m417z.com`; no download without `--consent-hosts` |
| B17 | Search and navigation (WB1) | index B02's project; query a function name, a string, a typo | exact hit first; typo hit labelled fuzzy; one click opens old/new code in the main window |
| B18 | Call graph (WB2) | B14 pair | caller/callee counts equal `FunctionRecord`; DOT export is inert text |
| B19 | Rules (YRX) | promote one reviewed discovery to a rule | provenance recorded (input sha256, tool version); rule compiles; matches the old sample, not the new |
| B20 | Guide (GDE) | first lesson on B02's project | every step resolves to an existing feature id; each step has expected-result text; zero sockets, no model call |
| B21 | Cancel storm | long fake child through `run_process`; cancel at 0, 50, 500 ms | status cancelled each time; no child alive after 5 s; project reopens without a lock error |
| B22 | Corrupt inputs | truncated JSON, wrong schema version, 0-byte PE, section size claiming 4 GiB | each rejected with a `PT-*` code and an actionable message; prior committed results untouched |
| B23 | Upgrade | open a previous-prerelease project, run `rank`, save | opens; contracts additive; verified backup exists before any prune (`verified_backup.py`) |
| B24 | Path hostility | repeat B02 under spaces, Unicode, OneDrive-style and ~200-character paths | same ranking as the ASCII baseline, or an actionable exit 2/3 (frozen A10) |

B01-B24 are automated evidence. They do not replace section 7.

## 5. Performance budgets and measurement method

### 5.1 Method

- Record CPU, cores, RAM, OS, Python 3.12.x, PySide6 version (6.12.0 pinned per the specs), and whether the host is shared (the 2026-10-14 benchmark notes noisy shared hosts).
- Qt: `QT_QPA_PLATFORM=offscreen`; build the real `MainWindow` or panel; `app.processEvents()` until idle; time with `time.perf_counter()`. Offscreen proves model/view cost and layout logic, not GPU painting or DPI (owner checks, section 7).
- Repeat: best of 3 for latency (as `tools/bench_enrichment.py --repeat 3`), median of 5 for startup; publish all raw values.
- Memory: peak RSS in a fresh process. Linux `resource.getrusage(...).ru_maxrss` (KiB); Windows `GetProcessMemoryInfo` peak working set via `ctypes` in the harness (no new dependency). `tracemalloc` only for diagnosis.
- Responsiveness proxy for large views: count `data()` calls (pattern of `test_large_models_stay_lazy_with_data_call_ceilings`) plus wall time of reset, sort, filter, first paint. A model that calls `data()` beyond the visible cells fails regardless of wall time.
- A budget is a target (report the measured value) and a CI ceiling of about 3x on shared runners, as `tests/test_evidence_perf.py` does (7.5 s gate, 1.5 s target). A ceiling is never raised to make a test pass without a `docs/qa.md` entry.
- Harness **(to build)**: `tools/bench_gui.py` (Qt, 100k-row views, startup) and `tools/bench_features.py` (one function per feature), both with `--json`, following `tools/bench_enrichment.py`.

### 5.2 Budgets

"Existing" rows come from committed tests or `docs/qa.md`; "proposed" rows are E-6 targets to be measured once, then pinned.

| Area | Workload | Target | CI ceiling | Basis |
|---|---|---|---|---|
| Enrichment cold | 10,000 pairs / 100k lines (`tools/bench_enrichment.py`) | 10 s, 512 MiB peak RSS | same | SPEC-07 objective. Measured 6.6 s / 240 MiB (older host), 8.95 s / about 775 MiB (later noisy host): the RSS objective is unreconciled, re-measure on a quiet host |
| Enrichment cache hit | same | 500 ms | none until met | **Not met**: 1.79 s to 3.1 s per `docs/qa.md`. E-6 meets it or the owner relaxes SPEC-07; do not hide it |
| Enrichment small | `tests/test_enrichment_perf.py`, 2,000 pairs | hit 0.25 s, cold 1.2 s | hit 5 s, cold 20 s | existing test |
| Evidence view model | 10,000 matches, 2 secondary engines | 1.5 s | 7.5 s | `tests/test_evidence_perf.py` |
| Evidence Qt model | 900x500 panel, 10k and 100k rows | `data()` calls = visible cells; 100k reset/sort/filter about 130/122/20 ms | reset 500 ms, sort 500 ms, filter 100 ms | `docs/qa.md` (local Linux) |
| Every new table/tree (WB1 results, WB2 list, WB3 strings, KB candidates, rules, teacher steps) | 100,000 rows offscreen | first paint 250 ms; reset 250 ms; sort 500 ms; filter 150 ms; `data()` calls <= 3x visible cells | 3x | proposed; `QAbstractItemModel` with lazy rows, never `QTableWidget` |
| Search index (WB1) | FTS5 over 100k functions + 1M string rows | build 30 s; query p95 50 ms; fuzzy p95 150 ms | 3x | proposed |
| Call graph (WB2) | 100k functions / 500k edges | load 3 s; neighbourhood query 20 ms; drawing capped at 2,000 nodes with a visible "truncated" notice | 3x | proposed |
| Strings (WB3) | parse a 50 MiB FLOSS report | 5 s, 300 MiB | 3x | proposed; the external FLOSS run is reported, not budgeted |
| Frozen startup | `PatchTrace.exe --self-test`, first window shown | manual bar 15 s (M01); automated target 5 s on CI | 15 s | M01; needs a `windowShown` marker behind an env flag **(to add)** |
| Source startup | `python -m patchtrace --self-test` offscreen | 3 s | 10 s | proposed |
| Import cost | `python -X importtime -c "import patchtrace.ui"` | no feature package imported at top level (lazy, as `open_series` does) | n/a | proposed |
| Memory idle | main window, 10k-pair project | 400 MiB | 800 MiB | proposed |
| Memory large | three 100k-row views open | 1.0 GiB | 1.5 GiB | proposed |
| Project open | 10k matches, 3 runs | 2 s | 6 s | proposed |
| Cancel latency | provider call / child process | 0.5 s to "cancelled" | 0.5 s | `tests/test_cancel_latency.py` |
| Child kill | grandchild gone after cancel | 5 s | 5 s | windows-acceptance A7/A8 |
| Package size | Windows one-folder ZIP | record; flag growth over 15 percent versus previous prerelease | n/a | build log |

If a feature misses its budget, fix in this order: virtualize; move work to a worker thread with progress and cancel; cap and show "truncated, showing N of M"; only then change the budget with an owner-approved note. Silent truncation is a bug.

## 6. Windows frozen-build smoke

Run on `windows-latest` after `tools/build_windows.py`; test the frozen executable, never source. Existing coverage: `tools/frozen_smoke.py` A1-A5, A6s, A10, B1, B2 and `--self-test`. E-6 adds:

| ID | Check | Pass |
|---|---|---|
| W1 | Every new CLI command from E-3/E-5 answers `--help` (extend `COMMANDS` in `tools/frozen_smoke.py`) | exit 0, `usage:` on stdout |
| W2 | Import smoke of every new package inside the frozen exe: a hidden `--import-check` flag importing each feature package and printing `name ok` **(to build)** | all ok; a missing PyInstaller hiddenimport, data file or protobuf `_message.pyd` fails here |
| W3 | Offscreen self-test displays the synthetic project and opens each new panel once | exit 0, temp dir removed |
| W4 | B02, B03, B06, B11, B14, B22, B24 against the exe | same golden as Linux |
| W5 | `pip install --only-binary=:all:` of the package set in a clean Windows venv | zero source builds |
| W6 | Notices present, ZIP inspected, no PDF/WebEngine/virtual-keyboard components (existing build guards) | guards green |
| W7 | A7-A9 Job Object tests and A11/A12 file-lock tests if still `(new)` | green on Windows CI |
| W8 | Size and startup versus previous prerelease | in the build summary |
| W9 | After publication: download the asset, recompute sha256, compare to the sidecar, confirm the prerelease flag | run id recorded in the ledger |

A failed W-row blocks the prerelease. Missing token permission is reported as blocked, never as a successful release.

## 7. Blocked external acceptance (owner's machine, Windows desktop, screen reader)

Reported separately in every status message; none counts as done. Each row: ID, state (default `not-run`), who, date, evidence.

| ID | Item | Why automation cannot close it |
|---|---|---|
| O1 | Windows manual checklist M01-M18 on a clean Windows 11 profile (launch, sample, raw views, tooltips, DPI 100/150/200, high contrast, resize, export, cancel, close during analysis, AV lock, restart, Unicode path) | needs a human on a real desktop |
| O2 | NVDA and Narrator pass over the main window and each new panel: names, roles, status announcements, focus order (findings cite Qt Accessibility and Microsoft UI Automation docs) | the offscreen accessibility tree is not an assistive-technology run |
| O3 | DPI 125/150/200 percent and mixed-DPI monitors for the new docks | offscreen has no real DPI scaling |
| O4 | Real Ghidra/Ghidriff analysis of a real PE pair through the frozen GUI, including OneDrive-backed project and symbol-store behaviour | needs the external runtime and a real profile |
| O5 | Tier W with Microsoft binaries and PDBs on the owner's machine (Winbindex/msdl access, label error rate, Ghidra time per family; data stays local) | Microsoft hosts blocked in the sandbox; data may not be committed |
| O6 | Real BinDiff 8 `bindiff.exe` and a real Ghidra/IDA `.BinExport` pair through the GUI; first green `live-bindiff` and `live-rizin` runs | third-party executables and human goldens (C3-7) |
| O7 | Live NVD/MSRC and any new live feed (KEV, CSAF directory): first real `live-*` result | no sandbox egress; consent-gated |
| O8 | Real relocatable offline runtime (Python 3.12 / ghidriff / pyghidra / Ghidra / JDK) on a disconnected Windows 11 machine; `python -m ghidriff --help`; known-patch fixture end to end | payload not yet assembled (SPEC-06) |
| O9 | Defender/SmartScreen behaviour for the unsigned ZIP and the protobuf `_message.pyd` | environment specific |
| O10 | msdelta (PA30/PA31) reconstruction on real update payloads | Windows system DLL and Microsoft payloads |
| O11 | Authenticode signed/trusted/revoked outcomes on real signed PEs | trust store and revocation need a real Windows host |
| O12 | Exploratory beta session after the downloadable package exists (`AGENTS.md`) | human judgement |

## 8. Order of work

1. Entry check (section 1); ledger update.
2. Audit (section 2): about six read-only auditors, Sonnet; Haiku for the FA grep checks.
3. Harnesses on disjoint files: `tools/beta/`, `tools/bench_gui.py`, `tools/bench_features.py` (Sonnet); `--import-check` and the startup marker (one Sonnet owner of `__main__.py`). No builder edits `ui.py` for this.
4. Bug check (section 3), fix wave, repeat until two consecutive clean full runs.
5. Performance run on a quiet host; pin budgets in `docs/qa.md`; resolve the cache-hit objective.
6. Windows prerelease build; W1-W9.
7. Final report: automated evidence (exact commands, counts, run ids, SHA), then the separate section 7 table, then open decisions. Opus only for a demonstrated hard blocker or a nuanced security invariant (roadmap section 4).

## 9. Risks

- The 500 ms cache-hit objective is a known miss; a green E-6 must not drop it silently.
- Goldens made on Linux can hide CRLF and path-separator differences; the Windows run compares the same file.
- `SeriesWindow` is a separate `QMainWindow`; if FA7 fails on it, the fix is a dock or tab owned by the GUI track.
- Offscreen passes can hide font, DPI and platform-plugin problems; O1-O3 stay open until a human closes them.
