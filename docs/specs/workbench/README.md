# PatchTrace Workbench: Three Reusable Integrations and Easy-Win Addenda

**Documentation branch:** `docs/workbench-search-graph-floss-20261014`
**Status:** Developer-ready design; no application implementation or Windows QA asserted.
**Date:** 2026-10-14. **Canonical ID family:** PT-WB; avoids current SPEC-31 naming collision.
**Target:** Existing Python 3.12 / PySide6 Windows stand-alone application, backwards compatible with v1 project storage and current Ghidriff/BinDiff/rz-diff workflows.

## Source documents

| ID | Developer-ready specification | Outcome | Dependencies | Relative complexity |
| --- | --- | --- | --- | --- |
| [PT-WB-01](01-search-fts5-rapidfuzz.md) | Indexed search and fuzzy names | Search analyzed functions, strings, annotations and binary context with exact navigation | Built-in SQLite FTS5, optional RapidFuzz | Low overall, very low core |
| [PT-WB-02](02-networkx-callgraph.md) | Call graph / XREF navigation | Explore Ghidriff's caller/callee labels, unresolved references, old/new changes and source-backed jumps | Existing FunctionRecord, optional NetworkX | Low–medium |
| [PT-WB-03](03-floss-strings.md) | Recover and compare strings | Static/stack/tight/decoded/language strings with source location, per-side delta and search | External FLOSS executable, existing SPEC-29 adapter plan | Medium total, small adapter |
| [PT-WB-QW](04-quickwins.md) | Eight low-effort integrations | Pygments, pefile, RapidFuzz, built-in Qt autocomplete, FTS5, intraline diff, DOT export, demangling | Optional/bundled | 1/5 slices with explicit limits |
| [Implementation Plan](../../plans/workbench-search-graph-floss-implementation.md) | Agent coordination and release | Modules, typed contracts, build order, PR splits, QA, Windows and source integrity gates | All docs | M0–M3 |

## Immediate priorities

1. **Build a minimal FTS5 search index and result navigation**: no Ghidra analysis added, no network, no new runtime dependency when FTS5 supported. The existing project has changed-function code and metadata but cannot assert search completeness for unchanged functions.
2. **Build caller/callee adjacency explorer**: Ghidriff already supplies `calling` and `called` fields stored as `FunctionRecord.callers` / `callees`. Start with clickable text table before the NetworkX graph canvas. Unknown names are unresolved rather than 'removed'.
3. **Add a single canonical FLOSS runner**: use the preexisting `docs/specs/three-tool-evidence-adapters.md` plan, do not duplicate it. FLOSS optional executable, strict versioned JSON, validated source SHA and per-extraction completeness.
4. **Independent 1/5 improvements**: exact-id Qt QCompleter and bounded Pygments syntax colors in the existing code panes; optional RapidFuzz suggestions; pefile VERSIONINFO/manifest extraction only for inspector fields not yet present.

## Architectural rules

- The project remains an ordered two-PE comparison with immutable source files and single-writer project storage. Derived search index is disposable and built in separate cache; graph and FLOSS evidence is source-linked, not silently inserted as original match truth.
- Integrate with existing `ui_evidence.py` WindowPort, Qt workers and tooltips. Workbench features are independent registry panels (GUI plan section 10), not pages of one workbench dock; the KB wizard stays a modal dialog and its results go to docks. Do not introduce three competing full UI windows.
- NetworkX models graph relations inside one artifact; existing `nway/graph.py` tracks correspondences across builds and must remain separate.
- Strings returned by FLOSS may be *newly detected* because analysis settings/decoder changed; do not call them a confirmed security fix. Source type, location/address space and tool version always visible.
- Compilers, DLLs, analysis engines and fuzzy scores are not vulnerabilities. Do not silently upgrade text similarity or call adjacency to CVE causation.
- Optional features must not block normal comparison, opening older project files, exports or Windows packaging.
- No external network fetches or target binary execution, no arbitrary external plugin installation, no shell interpolation, and no unsafe rendering of string/code content.
- No merge until tests pass. Documentation created by this PR is **not** runtime implementation.

## Specific current-repository constraints

The inspected `main` lists `src/patchtrace/ui_evidence.py`, `src/patchtrace/normalization.py`, `src/patchtrace/models.py`, `src/patchtrace/persistence.py`, `src/patchtrace/secondary/*`, `src/patchtrace/pe_overview/*` and `src/patchtrace/tooltips.py`. `intelligence/tools/floss.py` has not landed in main. The unified-engine spec already proposes its own UI seam and should be coordinated at merge time. Existing open PRs #40/#41 cover KB workflows and must not be rewritten here.

## Background references

- SQLite FTS5: https://www.sqlite.org/fts5.html
- RapidFuzz: https://rapidfuzz.github.io/RapidFuzz/Usage/process.html
- NetworkX: https://networkx.org/documentation/stable/
- FLOSS JSON schema: https://github.com/mandiant/flare-floss/blob/master/doc/results_document.md
- FLOSS CLI: https://github.com/mandiant/flare-floss/blob/master/doc/usage.md
- Pygments: https://pygments.org/docs/quickstart/
- pefile: https://github.com/erocarrera/pefile

## Integrator definition of done

All three workbench capabilities implemented with real source-linked navigation; run identity and completeness exposed; indexing/search bounded and offline; call graph edges typed and limited; FLOSS output versioned and validated; no canonical project corruption or API regression; optional components degrade safely; native Windows frozen-executable smoke and interactive accessibility passed. Record source versions and exact QA command outputs in `docs/qa.md`. Until then document-only.
