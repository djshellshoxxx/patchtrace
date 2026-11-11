# Store threading: owner-thread-only project store, worker hand-off, KB workspace (KBF-08)

Status: draft, developer-ready design (documents the owner decision QA-S2-2 of 2026-10-15 and one reproduced defect). Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-08. Owner packages: `persistence.py`, `enrichment/storage.py`, `service.py`, `gui/qt/tasks.py`, `kbcorrelation/{store,wiring,panel_qt,cli_leads}.py`, `pilot/{store,collect}.py`, `ui_leads.py`.

## 1. Purpose and non-goals
Purpose: one rule for who may touch which SQLite file, the hand-off pattern workers must use, and the fix for the KB dock. Non-goals: making the project store multi-threaded; a connection pool; changing `ProjectStore`'s schema.

## 2. Rule (binding)
R1. The project database (`project.sqlite3`) and every `EnrichmentStore`/`AdvisoryStore`/`pilot.store` call use the connection of the thread that opened the project (the GUI/owner thread). A write from another thread fails with `sqlite3.ProgrammingError` and writes nothing (test `tests/stress/test_stress2_enrichment_store.py::test_the_store_is_owner_thread_only_and_a_foreign_writer_changes_nothing`, owner decision QA-S2-2, `docs/handoff/owner-actions.md`). R2. Workers receive immutable snapshots and return values; the owner thread stores them. R3. A second `ProjectService.open` of the same project in the same process is refused: reproduced on `54fd085`: first open ok; second open from a worker thread -> `ValueError: PT-STORAGE: project is locked by another writer or lock is inaccessible`. R4. The KB WORKSPACE (`kbc.sqlite3`) is a different file and tolerates concurrent connections (`BEGIN IMMEDIATE`, `busy_timeout=5000`, compare-and-swap revisions); workers may open it. R5. Search segments and derived caches live outside the project (`search/paths.py` refuses a cache root inside a project) and may be built on any thread from a prepared `BuildRequest`.

## 3. Defect found: the KB dock reads the open project from a worker
`kbcorrelation/panel_qt.py:load_report` (runs in `TaskRunner`) calls `leads_outcome(build_service(ws), RealEngine(), project_dir)`; `RealEngine.read` does `ProjectService.open(Path(project_dir), maintenance=False)` and `KbService._project_bundles` uses `RealProjectPort.open_project/list_rows` which also open the project ("every call opens, uses and closes it", `wiring.py`). In the real GUI the dock's project is the OPEN project, so by R3 the open raises, `RealEngine.read` converts it to `KbcStoreError('PT-KBC-STORAGE', 'the project cannot be opened')` and the dock cannot show leads for the project the user is looking at. Tests miss it because `tests/test_ui_kb_panel.py` injects a fake `Loader`. The headless CLI is fine when the GUI is closed. (Reproduced: the lock; by reading: the dock path. UNVERIFIED end to end in a running GUI.)

## 4. Pattern (the fix, KBB-01)
```
owner thread (project_changed / refresh):
    snap = KbSnapshot(
        bundles = [ContextBundle...] from ProjectPort-like reader over the HOST'S service (self.port.service),
        engine  = EngineView built from enrichment.load_default(EnrichmentStore(service.store), service.project)
                  + build_views(service.project)  (cheap, in-memory),
        project_revision, older_sha, newer_sha, run_id)          # frozen dataclass of plain values
worker thread:
    report = build_leads(bundle=snap.bundles[-1], view=snap.engine, alignment, kev=default_kev(), ...)
    return (key, report, model, prepared_table)                   # no Qt, no project
owner thread (_loaded): drop if key != self.key; set model; render
```
`kbcorrelation/snapshot.py` (NEW, pure) defines `KbSnapshot` and `read_snapshot(service) -> KbSnapshot` (owner thread); `cli_leads.leads_outcome(...)` keeps its signature and gains `leads_from_snapshot(workspace_service, snap)` used by both CLI (after its own open) and dock. `RealProjectPort` stays the CLI/attach implementation. KB attach from the GUI is out of scope for beta (CLI only) until K7 UI.

## 5. Same rule audit (other callers)
`ui_leads.py`: `load_stored`, `collect_inputs`, `publish_result` run on the GUI thread; the ranker worker gets `Collected` (immutable); BUT `collect_inputs` does the heavy PE overview/signal work on the GUI thread (KBF-07 splits it). `search/qt_panel.py`: `build_request` on the GUI thread, segments on workers (compliant by design; verify with a thread-id test). Capabilities/strings/rules panels: out of scope here; the generic guard is `tests/test_gui_core_*` plus a new `tests/test_no_worker_opens_project.py`: AST scan of `ui_*.py`, `*/panel_qt.py`, `*/qt_panel.py` for `ProjectService.open` inside any function passed to `tasks.submit`/`lane.submit` (heuristic; list of allowed exceptions empty).

## 6. Error and cancel semantics
A worker never raises Qt or sqlite objects across threads; failures are `TaskFailure(code, exception_class)` shown as `{code}: {exception_class} stopped the work`. A late result after project switch is dropped (key compare); `shutdown()` cancels channels and joins (no `terminate`). `PT-KBC-STORAGE` text for a locked project in the CLI: `the project cannot be opened`; proposed distinct text for the lock: `the project is open in another PatchTrace window or process; close the desktop and try again` (same words as `search/cli.py:LOCKED`).

## 7. Determinism, privacy, security
Snapshots are values: same project revision + same workspace give the same report. No path or credential in a snapshot; absolute project paths stay in the owner thread. Hostile text is cleaned before it enters a snapshot (`plain_text`).

## 8. Budgets
Owner-thread read phase for the KB dock: at most 100 ms for a 5,000-function project (reads stored rows and a few KB bundles); everything else on the worker. GUI slot budget 100 ms (gate in `tests/qt_support.py`).

## 9. Test plan (red first)
`tests/test_kb_dock_open_project.py`: a REAL `ProjectService` held open by the host fixture, the dock's DEFAULT loader (no injection), a project with a stored context and ranking -> state shows leads, no `PT-KBC-STORAGE`; the same test fails on `54fd085` with `the project cannot be opened`. `tests/test_kbc_snapshot.py` (value equality, no handles). `tests/test_no_worker_opens_project.py`. Existing stress test above stays green. Qt gate: `python tools/qt_gate.py --repeat 20 tests/test_ui_kb_panel.py tests/test_kb_dock_open_project.py`.

## 10. Open questions
Q1 Allow a read-only second connection for workers (SQLite WAL) instead of snapshots? Default no (owner decision QA-S2-2). Q2 Provide GUI attach in beta? Default no.

## 11. Acceptance
Test in section 9 green on Linux and Windows; the full `tests/stress/test_stress2_*` green; manual: open a project in the desktop with a KB context and press Refresh in the KB dock -> rows appear (owner gate O1 row).
