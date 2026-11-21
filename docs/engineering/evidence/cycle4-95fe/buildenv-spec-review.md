# Independent specification review: Build environment header help

## Decision and exact source

**No blocking or nonblocking specification finding in the reviewed delta.**

- Baseline: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Reviewed integrated source: `b65fba2f5567f0b129331364bbf6db1cd699c901`.
- Reviewed complete tree: `889c6383fb4d231fd6698b71511214e8c9c8fac0`.
- Review checkout: `/workspace/scratch/patchtrace-95fe-c4/buildenv-spec`, detached and clean.
- Delta: five files, 221 insertions and five deletions. Two production files contain only five column `tip_id` assignments and five static tooltip entries. The other files are the new contract, new regressions, and the existing registry audit's real-host activation.

The review used `docs/specs/buildenv-header-help.md`, the Build environment presentation and uncertainty rules in `docs/specs/program-e/DIE-integration-plan.md`, the registered header/accessibility mechanism in `docs/specs/program-e/GUI-integration-plan.md`, `docs/modules.md`, and `AGENTS.md`. The contract is recorded in `17f9f958` before the author regression and runtime commits. The root audit activation extends the existing registry-coverage test rather than altering the presentation contract.

## Requirement-to-implementation review

| Requirement | Implementation and assessment |
| --- | --- |
| All five prepared horizontal headers expose matching registered help, with no rows and after results arrive | `buildenv/panel_model.py:COLUMNS` maps Fact, OLDER, NEWER, Status and Basis to five corresponding `build_env.col.*` IDs. `buildenv/panel.py:PANEL` and `qt_panel.py:BuildEnvController.__init__` already register the same `TIPS`; no new registration path is required. `VirtualTableModel.headerData` resolves these IDs independently of row count. |
| Copy accurately distinguishes values, missing displays, comparison state and provenance | `view_model.fact_rows` displays `-` for absent values and uses `copy.STATUS_TEXT` for all five states. The new OLDER/NEWER descriptions explain the displayed placeholder without inferring a change. Status enumerates changed, added, removed, same and unknown (one side), and explicitly states that unknown is not a difference. Basis describes the recorded sources and retains the limitation that signatures/header fields do not prove how the file was built. |
| Display/accessibility labels, cells, sorting, filtering, row identity and copying remain unchanged | The production AST comparison is identical after removal of only the five new `tip_id` keywords. Existing column getters, widths, keys and table specification are unchanged. Header help is consumed only by the existing header tooltip branch; display and accessible roles keep the existing labels. The new maintained regression checks representative cells and copied plain text. |
| Escaping, missing-ID fallback and Qt-free declarations remain intact | Rendering still uses the existing safe tooltip registry. The authored regression checks registry escaping, fallback to the title after removal of an ID, and isolated imports without Qt. No renderer, template parser or import architecture changes appear in the delta. |
| Actual host observation without exemptions | The new header test opens Build environment through the real host. The root change in `tests/test_tooltips.py:test_every_registry_id_is_applied_somewhere` calls `show_panel('build_env')` and asserts five header sections before the existing model-role collection. It introduces no exemption and no direct injection of declared IDs into the observed set. |
| No backend, persistence, comparison or external execution change | Only static column metadata and static tooltip data change in production. The controller, readers, parsers, delta calculation, artifacts, schemas and external-tool behavior are unchanged. |

No missing or partial requirement, unrelated scope expansion, or incorrectly implemented requirement was found. The new help speaks about recorded row values and sources; it does not promote a row-level state into an overall toolchain or accuracy claim. Existing loading, incomplete, stale and error messages remain authoritative.

## Independently executed controls

A separate, source-bound review environment used `python -I` against the exact detached checkout. It executed the reviewer-authored `buildenv-spec-controls.py`:

- Five synthetic `BuildChange` semantic cases covered every displayed comparison state, older/newer placeholder behavior, and a multi-source basis containing both Detect It Easy and PE header provenance.
- Two exact production AST controls confirmed that deleting the five added `tip_id` keywords and the five added `TIPS` entries respectively restores each original production file's complete AST.

All controls passed. The clean exact-source receipt records return code 0 at `2026-11-21T06:18:31Z`, before/after head and tree identity, isolated source path, command and full output. These are five synthetic semantic cases and two structural checks, **not seven additional repository pytest passes**, hosted compatibility evidence, or target execution.

Evidence locations:

- `/workspace/scratch/patchtrace-95fe-c4/buildenv-spec-controls.py`
- `/workspace/scratch/patchtrace-95fe-c4/buildenv-spec-evidence/independent-copy-semantics.json`
- `/workspace/scratch/patchtrace-95fe-c4/buildenv-spec-evidence/independent-copy-semantics.log`

The author's missing-help baseline and earlier global-audit failure remain valid historical failures. The root owns the integrated maintained-suite result; this reviewer did not rerun that broad selection or replace its receipt.

## Acceptance boundary

Specification review passes for this bounded header-help delta. This is not whole-project acceptance or authorization to merge PR349. Exact combined-source hosted checks, the parallel owner's storage repairs and remaining findings, and native Windows screen-reader/high-contrast/DPI acceptance keep their existing gates. The coordinator and other workers' worktrees, shared environments, PRs and workflow runs were not modified by this review.
