# 27. Testing and CI

How the suite is organised, what the rules for a PatchTrace test are, which gates run where, and what counts as evidence. Policy sources: `AGENTS.md`, `docs/plans/worker-brief.md` section 3, `docs/qa.md` (the evidence log), `docs/specs/verification.md`. Previous: [26](26-packaging-and-bundle.md). Next: [30 history](30-history-and-process.md).

## The principle

Tests are the specification of the invariants. **A mocked backend or provider test is never live compatibility evidence** (`AGENTS.md`): the suite proves logic, boundaries and contracts with synthetic fixtures; whether Ghidra, BinDiff, rizin, capa or a model provider works with PatchTrace is proven only by a recorded live run, and a live check that cannot run is reported as *blocked*, never silently skipped. Evidence of what ran, on which OS, with which versions and what remained blocked is appended to `docs/qa.md` and `tasks/todo.md` per slice.

## Layout

`tests/` holds 419 files at `21a005e` (382 named `test_*.py`, plus helpers such as `qt_support.py`, `network_guard.py`, `site_helpers.py`, synthetic builders and fake tools (`pe_builder.py`, `fake_exe.py`, `fake_bindiff.py`, `bindiff_builder.py`) and `fixtures/`). Rough families by file-name prefix: unified engine (about 70), GUI framework (about 30), intelligence and tools (about 28), patch-intent (19), tier/corpus (18), UI (15), KEV (15), fabric (14), rules (13), enrichment (13), KB correlation (12), PE overview (11), BinDiff and BinExport (20), secondary (9), calibration (7), plus network consent, live status, nway, backend, acquisition, audits, and workflow/packaging guards.

Run (from a checkout):

```bash
python -m pip install --only-binary=:all: -e '.[dev,search,rules]'
QT_QPA_PLATFORM=offscreen python -m pytest -q            # full suite
QT_QPA_PLATFORM=offscreen python -m pytest tests/test_gui_host.py -q -p no:cacheprovider
python -m ruff check src tests tools                     # line length 110; E4,E7,E9,F,I,UP,B
python tools/generate_schemas.py                         # after any contract edit; also the per-package generators
python tools/qt_gate.py --repeat 5                       # teardown/thread-leak gate for GUI tests
```

`pytest` config (`pyproject.toml`): `pythonpath = ["src"]`, `testpaths = ["tests"]`, one marker `live_bindiff`. `pytest-qt` provides `qtbot`; `hypothesis` powers property tests (derandomised where timing matters); `networkx`, `pefile` and `pygments` are **test oracles only**, never runtime dependencies.

## Rules for a test (worker brief, section 3)

1. **Red, then green** for behaviour; real assertions.
2. **Hermetic and deterministic**: no network, no Microsoft binaries, no target execution, no fixed sleeps (poll or use events), `>=` on timings (the Windows monotonic clock ticks at 15.6 ms).
3. **Windows-safe**: LF fixtures (`.gitattributes` lines for new fixture directories; `* text eol=lf` for CSAF, KEV, KB, intel-tools, schemas, corpus), `pathlib`, `open(..., encoding='utf-8', newline='\n')`, never POSIX-only behaviour; **short explicit `pytest.mark.parametrize(ids=[...])`** because Windows limits `PYTEST_CURRENT_TEST` to 32,767 characters; YAML plain scalars never contain `: `.
4. **Generated schemas** use regenerate-and-compare tests (`test_fabric_schemas.py`, `test_kev_schemas.py`, `test_kbc_schemas.py`, `test_intel_schemas.py`, `test_intel_tools_schemas.py`, ...).
5. **Boundary tests assert the architecture**: no Qt in pure packages, import DAGs (`test_unified_import_dag.py`), one main window (`test_no_new_top_level_window`), `ui.py` line ceiling, hostile text (`HOSTILE` strings through every sink).
6. **Known-answer and oracle tests** use synthetic or repo-owned data: `corpus/`, `tests/fixtures/` (BinExport, CSAF, CVE, KEV, pilot, rules, secondary, unified, WBQ, Winbindex), Tier R corpora built from permissively licensed open-source code, planted mutants. Tier W (Microsoft-derived) data is local-only and never committed (`.gitattributes` `tests/fixtures/tier_w/** -text`, runbook `docs/runbooks/tier-w-local-run.md`).
7. **No stray files**: temporaries go to a scratch directory; `git status` shows only intended files.

## Network and live evidence

- `tests/network_guard.py` (fixture `network_guard`): while armed, socket connect/send/lookup, `urllib.request` and `http.client` raise `NetworkAttempt` and the attempt is recorded; unclaimed attempts fail at teardown. Tests under `test_network_consent_*.py` use it to prove consent and the absence of silent requests (SPEC-42).
- `tests/conftest.py`: `record_live_status(engine, status, reason, **extra)` writes `build/live-status/<engine>.json` with `passed|failed|blocked` and `mocked: false`; `pytest_terminal_summary` prints a `LIVE ACCEPTANCE BLOCKED` section. `PATCHTRACE_REQUIRE_LIVE_BINDIFF` and `PATCHTRACE_LIVE_STATUS_DIR` control the live BinDiff lane.

## Workflows (`.github/workflows/`, 15 files)

| Workflow | Trigger | Purpose |
|---|---|---|
| `qa-windows.yml` | push to main, tags, PRs, dispatch | **the required gate**: `qa` on ubuntu and windows (pytest, ruff, pip check, protobuf/upb check), Windows build + frozen smoke, Linux package + smoke on 22.04/24.04, release gate, prerelease |
| `optional-deps.yml` | PRs, dispatch | wheels-only probe of `rapidfuzz` and `yara-x` on both OS |
| `backend-bundle.yml` | dispatch, tags, workflow_call | zero-download full build, disconnected acceptance, pin report and pin verify (never publishes on tag) |
| `live-backend.yml` | dispatch, push | native Windows Ghidriff known-patch acceptance |
| `live-bindiff.yml` | dispatch, schedule | real BinDiff 8 execution (not a required check) |
| `live-rizin.yml` | dispatch, push | real `rz-diff` on a pair built from repo-owned synthetic sources |
| `live-unified.yml` | dispatch, push | SPEC-31 S1 live extraction (Windows MSVC DLLs and Linux; cross-OS content digest equality) |
| `live-intel-tools.yml` | dispatch, schedule | capa/FLOSS/diec acceptance |
| `live-nvd.yml`, `live-kev.yml` | dispatch, schedule | advisory probes of NVD/MSRC and the KEV catalog |
| `unified-corpus.yml` | dispatch | G-U gates over Tier R (advisory) |
| `corpus-tier-r.yml` | dispatch, push | sharded Tier R build and evaluation matrix |
| `pilot-eval.yml` | dispatch | patch-intent evaluation (advisory) |
| `nightly-fuzz.yml` | schedule 03:17 | BinExport2 fuzz (non-gating) |
| `pages.yml` | push, dispatch | GitHub Pages build; awaits owner settings |

`tests/test_workflows.py` and `test_codex_pkg_workflows.py` lint every workflow file (for example no plain scalar containing `: `); `tests/test_codex_pkg_packaging.py` and `test_unified_packaging.py` check packaging invariants.

## Gates by purpose

| Gate | Command / job | Catches |
|---|---|---|
| Unit and integration | `pytest` | logic, contracts, ownership, hostile text |
| Lint | `ruff check src tests tools` | style, imports, bugbear patterns |
| Panel lint | `patchtrace panels check` | id/shortcut/tab/tip/claims/import problems in specs, no display needed |
| Qt teardown | `tools/qt_gate.py --repeat N` (Linux 20, Windows 5 per the GUI plan) | thread leaks, SIGABRT on destroyed `QThread`, order dependence |
| Frozen | `tools/frozen_smoke.py` | PyInstaller omissions, packaged data files, CLI in the frozen process |
| Live | `live-*.yml` | real tools on real pairs (Windows runners) |
| Release | `tools/release_gate.py` | every third counted merge publishes a prerelease |
| Acceptance | `tools/bundle_acceptance.py` | zero-download bundle under network denial |
| Packaging pins | `tools/check_backend_pin.py --release` | refuses placeholder pins in release builds |

CI runs 60-minute timeouts (raised for the Windows qa job in PR #63).

## What the numbers say (as recorded, not re-measured here)

- At prerelease beta.225 (main `98182e5`): Windows pytest 4,884 passed, Linux 4,891 passed, frozen smoke and Linux smoke on 22.04/24.04 pass (ledger A).
- The GUI framework branch recorded two full-suite runs of 10,068 passed locally and `qt_gate` repeats of 5 over all GUI files at 5,665 and later 6,465 passed (ledger D, `docs/qa.md`). One F4 timing test (`test_data_calls_are_independent_of_the_row_count`) flaked once on a loaded CPU.
- Known issue classes recorded in `docs/qa.md`: a native raw-cache job flaked once because `_java_version` probing returned unknown after a 15 s timeout (hardening suggested for `backend.py`); a rare Qt teardown abort whose cause was undecided (Qt flakiness or upb) and that the repeat gate was introduced to catch.
- **Open acceptance** (not automated): clean-Windows GUI acceptance, NVDA/Narrator and DPI, live local/remote AI provider runs, native Windows msdelta, a disconnected-machine bundle run, live Ghidriff from the frozen Linux build.

## Adding tests (checklist)

1. Name the file after the slice; keep fixtures synthetic and LF; put new fixture directories into `.gitattributes`.
2. Write the failing test first; assert behaviour, not implementation.
3. Qt: import `qt_support`, use `qtbot`, join worker threads, run `tools/qt_gate.py --repeat 5 <file>` before you report.
4. Network or tool code: inject the opener or runner; add a `network_guard` assertion that nothing else is attempted.
5. After a contract edit regenerate schemas; the drift test will fail otherwise.
6. Append your evidence (commands, counts, what you could not verify) to `docs/qa.md` under a unique `### [slice:name]` heading.
