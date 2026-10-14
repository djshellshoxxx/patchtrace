# PT-WB: Modular Implementation Plan, Dependency Matrix, Agent Handoff and QA

**Status:** Ready to assign development; this PR contains docs, not feature code. **Date:** 2026-10-14. **Canonical IDs:** `PT-WB-01 Search`, `PT-WB-02 Call Graph`, `PT-WB-03 FLOSS`, `PT-WB-QW Quick Wins`. No numeric SPEC-31 reuse (currently collides between the unified engine and KB/CVE specifications).

## 1. Validated baseline (2026-10-14 main)

PatchTrace runs on Python >=3.12, PySide6 6.12, Pydantic 2.13 and protobuf 7.36.2, Windows packaged via PyInstaller. `src/patchtrace/models.py` already exposes `FunctionRecord(name,code,assembly,callers,callees,...)` and `FunctionMatch(category,older,newer,run_id,...)`. Ghidriff `normalization.py` fills caller/callee labels from `calling`/`called`. `src/patchtrace/enrichment/storage.py` already has a guarded publisher and verified DB backup, `src/patchtrace/persistence.py` owns the project database and writer thread. `src/patchtrace/ui_evidence.py` provides an evidence dock, careful worker/thread lifetime patterns, generation guards and `WindowPort` navigation, plus modules `ui.py` and `tooltips.py`.

SPEC-29 `docs/specs/three-tool-evidence-adapters.md` already plans a FLOSS adapter, but **no `src/patchtrace/intelligence/tools/floss.py` appears in the inspected main**. The first FLOSS PR must create the canonical adapter once, not two wrappers.

Other active planned work: multi-engine unified window specification, N-way series, CVE KB source packages in PR #40/#41. Use independent namespaces and avoid touching the same main UI/CLI file from multiple worker branches.

## 2. Shared package contracts and exact seams

Modules to introduce:
```text
src/patchtrace/
  workbench/
    __init__.py
    source_keys.py          # canonical project/run/artifact guards
    contracts.py            # typed source references + availability/limitations
    graph_contracts.py
    graph_extract.py
    graph_resolver.py
    graph_build.py
    graph_queries.py
    graph_compare.py
    graph_view_model.py
    strings_contracts.py
    strings_delta.py
    strings_search_adapter.py
    strings_view_model.py
  search/
    __init__.py
    contracts.py
    extract.py
    index.py
    query.py
    fuzzy.py
    view_model.py
  intelligence/tools/
    floss.py               # single canonical provider; depends on earlier SPEC-29 design
  ui_workbench.py           # one shared dock/controller, Qt-only
  ui_search.py              # search page only
  ui_graph.py               # graph page only
  ui_strings.py             # strings page only
```
Names are targets, not claims they exist today. If `ui_unified.py` is merged first, the integrator adapts to its single-window navigator seam instead of creating duplicate top-level workspace controls.

Define one common immutable `WorkbenchContextKey`:
```python
@dataclass(frozen=True, slots=True)
class WorkbenchContextKey:
    project_id: str
    revision: int
    run_id: str | None
    older_sha256: str
    newer_sha256: str
    overrides_digest: str
```
All cross-module navigation requests carry this key and machine identity, **never just a function name/address**. UI compares against `WindowPort.key` and current model data immediately before activating an external hit. The source data layer may adapt `WindowPort.key` into `WorkbenchContextKey` while obtaining overrides digest from current effective matching service.

Common capabilities: `available`, `partial`, `unsupported`, `stale`, `cancelled`, `error`. Missing optional integration is **unsupported**, not "no results". Source field completeness and coverage are mandatory. Machine record IDs stable, Pydantic v2 strict/frozen, schema `workbench-*/1`, explicit source-run SHA/version.

**Dependency direction:** `models.py` and verified artifact services → pure `search`/`workbench`/optional tool adapters → service/CLI controller → Qt view. Never import Qt from pure models, SQL into network providers, FLOSS subprocess into a panel, or NetworkX objects into persistence. The original comparison engine remains untouched.

## 3. Three-phase implementation roadmap

### Milestone M0: Baseline and shared schemas (Integrator, low risk)

- Freeze and record main SHA, open-PR list, existing tests and Windows evidence in docs/qa.md.
- Check for concurrent edits to UI, CLI, enrichment extension storage and unified module; reserve main-window seam to single integrator.
- Define `WorkbenchContextKey`, `EvidenceLocator`/source location kinds, `StageResult`, reason codes and test schemas.
- Add `tests/workbench/` golden fixtures and common fake project.
- Add package empty initializer/import isolation contract tests.
- Explicitly document which Ghidriff function populations are included; do not overpromise whole-program graph/search coverage.
- Baseline no new dependencies added by default.

Exit: identity/schema freeze; tests red for intended behavior; basic pure-contract fixtures green.

### Milestone M1: Low-risk value first

- **PR-WB-01A** Search core: FTS5 capability probe, source extraction, disposable derived-cache index, immutable key, safe parser and fielded search. Unit, corruption and performance tests. No UI changes.
- **PR-WB-02A** Graph core: pure caller/callee extraction and uniquely resolvable names, ambiguity stubs, bounded BFS, textual adjacency data. No UI changes. NetworkX is optional until graph adapter validated.
- **PR-WB-QW1** QCompleter exact function-ID navigation, independent UI seam, or Pygments visible-code syntax as stand-alone. No persistent DB schema change.
- **PR-WB-01B** Search UI/controller: shared dock owner / Qt model, command `patchtrace search`, function-match navigation and incomplete-index state.

Exit: search/jump works with existing current projects and offline; call adjacency list generated without Ghidra re-run; no existing functionality broken.

### Milestone M2: Graph and shared navigation

- **PR-WB-02B** bounded NetworkX adapter, graph comparison per matched endpoints, stable source-linked events. Test wrong-identity and no observation.
- **PR-WB-02C** Qt QGraphicsView (or list-first fallback) tab, side-by-side paired navigation, interactive nodes and text accessibility. UI worker/test on frozen Windows.
- **PR-WB-QW2** Optional RapidFuzz name suggestions integrated with search, feature detector and license packaging.
- **PR-WB-QW3** pefile version resource/manifest inspector adapter after checking currently merged PE fields. Do not edit existing resource models without migration tests.

Exit: selected changed function yields useful calls/callees with correct source status, no silent wrong-side jumps, large graphs remain bounded.

### Milestone M3: FLOSS and enrichment

- **PR-WB-03A** Single canonical `intelligence/tools/floss.py` adapter under planned SPEC-29 contracts, tool capability probe, supervised process, JSON parser, synthetic + pinned real fixture tests. If already implemented by another agent, test and reuse instead of overwriting.
- **PR-WB-03B** Pure per-side `StringObservation` normalization, delta classification, location mapping, completeness and save/read adapter using guarded service-owned storage if persistence needed. Keep raw output recomputable/cacheable, preserve immutable provenance.
- **PR-WB-03C** Strings tab, explicit Scan/Cancel, location jump and search indexing of normalized observations, redaction-aware export.
- **PR-WB-QW4** Optional Pygments token formatting if not completed, and DOT export after graph contract stabilized.
- **PR-WB-I** Integrator regression, project backup/reopen, cross-tab stale navigation, release notes, Windows packaged smoke and merge/close all stale branches.

Exit: FLOSS runs without launching target PE, results include source/side/extraction completeness, navigation does not infer impossible function mappings, search sees normalized strings, and existing secondary engines unaffected.

## 4. Parallel-agent work and merge rules

Assign dedicated ownership:
- Search owner: `search/*`, search-related tests/spec docs.
- Graph owner: `workbench/graph_*`, graph-related tests.
- FLOSS owner: `intelligence/tools/floss.py`, `workbench/strings_*`, tool/string tests.
- QA owner: golden fixtures, acceptance harness, performance/regression recording; no functional UI edits.
- **Integrator only:** `ui.py`, `ui_workbench.py`, `cli.py`, `persistence.py`, `tooltips.py`, `pyproject.toml`, `docs/modules.md`, `docs/qa.md` after coordinating with ongoing unified engine.

Before each worker starts: read base PR and source contracts, identify current HEAD, claim paths, write tests first, implement minimal version, check real interfaces/versions, commit only owned files, post concrete tested status. Integrator resolves changes, merges promptly, closes obsolete branches; never silently rebase/delete somebody else's active work or claim CI green without a run.

If multiple agents are simultaneously shipping new docks, favor a *single shared WorkbenchDock with three pages* controlled by integrator. If `ui_unified.py` uses the navigator, avoid competing item models and route selection through its WindowPort contract.

Dependency pinning: no unconditional new heavy packages. FTS5 is built-in if available, RapidFuzz optional, NetworkX optional, FLOSS external executable. For Pygments/pefile optional wheels evaluate their frozen artifact size and license notices. Windows build must keep running if any optional component absent. Each capability probe results cached by version/path only for current app session; an unavailable tool must never crash on import.

## 5. CLI integration and versioned error surface

Reserve commands `search`, `graph`, and `strings` only after verifying current `cli.COMMANDS` and open PR ownership. If `intel-tools` canonical FLOSS engine command exists, reuse it and make `strings` read-only; no duplicate execution CLI.

Common statuses: `ok`, `partial`, `no-results` (complete observed scope only), `unsupported`, `stale`, `cancelled`, `error`.
Error family: `PT-WB-INPUT`, `PT-WB-CAPABILITY`, `PT-WB-SOURCE`, `PT-WB-STALE`, `PT-WB-LIMIT`, `PT-WB-FORMAT`, `PT-WB-TIMEOUT`, `PT-WB-CANCEL`, `PT-WB-STORE`.
Never replace existing PT-ACQ, PT-SECONDARY or PT-ENRICH error codes: wrap them with original safe details. CLI exit 0 valid completion; 2 invalid input/config; 3 runtime error; 4 **complete zero results only**; 5 cancelled. Partial/unsupported results must be explicitly represented and mapping to exit code designed in CLI compatibility tests; do not label them successful complete outputs. `--json` means exactly one stdout JSON body even in failure. Print progress to stderr only and no absolute source paths by default.

## 6. Full integration regression matrix

| Area | Required scenarios | Severity |
| --- | --- | --- |
| Search source integrity | old/new hashes, source offsets, run identity, stale override, missing unchanged functions | P0 |
| FTS5 compatibility | unavailable extension, trigram unavailable, corruption, disk full, FTS query error, injection characters | P0 |
| Search navigation | duplicated names/addresses, switched project, no match ID, exact side | P0 |
| Graph correctness | direction, cycle, ambiguous names, unresolved unchanged calls, split/merge overrides | P0 |
| Graph scale | dense/cyclic graph cap, >100k records, generation cancel, Windows Qt scene perf | P1 |
| FLOSS provenance | tool binary/config/schema/output SHA, old/new orientation and skipped stage | P0 |
| FLOSS safety | untrusted JSON, timeout/cancel, path changes, HTML injection, local secrets | P0 |
| FLOSS differentiation | same value different offsets, encoder movement, stage mismatch indeterminate | P0 |
| Storage/backups | project continues to open v1, derived sidecar expendable, backup restoration, writer ownership | P0 |
| Existing functions | acquisition, Ghidriff, rank, correlate, secondary, N-way, reports, preflight, raw views | P0 |
| Windows release | tool absent, tool present, PyInstaller imports, DPI, keyboard, clean non-ASCII paths | P0 |

Build synthetic PE fixture with 3 functions: F1 calls F2, F2 calls F3, F2 includes string old/new variants, function names with duplicate symbol variant. Create corresponding older/newer normalized Ghidriff match result with positive and negative edges. Golden source fixture indexed and rendered in all three views verifies navigational ID consistency. Never distribute actual Microsoft binaries in fixture set.

### Test commands (suggested, adapt to repository pytest config)

```bash
python -m pytest tests/workbench -q
python -m pytest tests -q
python -m ruff check src tests
python -m patchtrace --help
```

Windows CI: normal unit tests plus separate packaged build smoke exercising pure CLI search, graph and FLOSS absence; one native Windows acceptance machine verifies FLOSS executable separately and GUI interactive flows. Live FLOSS sample observations and NetworkX large-graph metrics must be logged with exact versions/fixtures; avoid synthetic-only production-readiness claims.

## 7. Functional requirements by acceptance ID

WB-A01: no new analyzer required to search project functions, and all search results cite source identity.
WB-A02: user cannot execute unsafe SQLite MATCH syntax; source text never interpreted as UI markup.
WB-A03: current artifact/project guard prevents stale search/graph/string navigation.
WB-A04: partial coverage explicitly displays missing source populations and interrupted stages.
WB-A05: graph caller/callee arrow direction correct with observed vs inferred edges.
WB-A06: no graph change falsely declared from an unresolved/similar name across versions.
WB-A07: all graph traversals and Qt scene generation bounded and cancellable.
WB-A08: FLOSS JSON is strict, versioned, size-bound and source-linked.
WB-A09: strings missing from incomplete extraction never called 'removed'.
WB-A10: no binary is launched or uploaded, optional tool/network usage user-controlled.
WB-A11: code/strings appear as plain text; sensitive data redacted in default exports.
WB-A12: existing comparison/secondary/series/project semantics untouched.
WB-A13: available/failure states distinguish unsupported capability from no results.
WB-A14: full frozen Windows tests and native GUI acceptance pass before beta feature release.

## 8. Completion and handoff template

Every sub-PR handoff must include:
- Exact changed module paths and public interfaces.
- Baseline SHA and source check date; any current PR collisions.
- Test names, command outputs, Linux and Windows evidence separately.
- Tool version, binary SHA, JSON schema version and Windows packaging consequences.
- Measured memory/runtime on fixture and large case; known untested scenarios.
- Backward compatibility/backups and error/fallback policies.
- Remaining work and open decisions; integration owner and merge status.

No agent should produce a 'complete' claim if optional FTS5, FLOSS, frozen Windows, stale guards or controlled Qt thread teardown are untested. Do not duplicate existing specs, feature code or search/callgraph components. Docs are complete when linked from the index and reviewed, **but runtime remains unimplemented** until code PRs pass their gates.
