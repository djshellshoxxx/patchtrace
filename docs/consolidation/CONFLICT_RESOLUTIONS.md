# Integration conflict resolutions

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Main baseline: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
Original local merge: `a9e40d27d4b2ef9a7166f5127039d4837e9448f3`.
Parents: reviewed #319 `a56ab13aaf9916fc12bea70ba1494075991b7f09` and
#318 (including #316) `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5`.
Current code checkpoint source: `cb1b508c`; no unresolved Git conflicts.

The eleven original conflicts are reproducible with
`git merge-tree --write-tree --name-only --no-messages a56ab13a c4ace208`.

| File | Resolution and reason |
|---|---|
| `.github/workflows/live-unified.yml` | Keep #319's H7 native environment/cache receipt and #318's pinned artifact upload action. Both requirements apply. |
| `src/patchtrace/kbcorrelation/service.py` | Keep the current `_stored_scope(..., *, unreadable=())` propagation and its inventory/saved-scope behavior. Dropping unreadable scope would overstate correlation coverage. |
| `src/patchtrace/strings/export.py` | Keep #319's safer no-force ownership/cancellation behavior instead of restoring the older path-based implementation. Subsequent export repairs are separately recorded with real regressions. |
| `docs/specs/program-e/KB-integration-plan.md` | Retain #318 inventory selection and unreadable-scope contract additions, consistent with the implementation. |
| `docs/specs/program-e/WB3-integration-plan.md` | Preserve truthful no-force guarantees and the explicit weaker force limitation. Later source-verification fixes do not erase the remaining final source-name race. |
| `docs/modules.md` | Retain both new module histories, including the more complete raw-alignment entry. Subsequent significant modules are indexed before integration. |
| `docs/qa.md` | Retain both sets of historical observations with their original source scope. No historical suite result is relabeled as current integrated proof. |
| `tasks/todo.md` | Retain both completed and outstanding work, including native, packaging and security gates. |
| `docs/help/67-cli-kb.md` | Retain both applicable user-facing KB workflow additions. |
| `docs/specs/csaf-cve-interpretation-engine.md` | Preserve both appended contract histories rather than discard a distinct update. |
| `docs/specs/enrichment-hardening-backlog.md` | Preserve the independent backlog additions and their qualification limits. |

## Later selective recoveries

The Calls graph port conflicted in `docs/specs/panels/graph-inspection.md` only.
The resolved document preserves the existing capped-view/table/DOT behavior and
adds the new bounded layout contract. No duplicate minimap or obsolete canvas
implementation was imported.

Tier-W admission and runner provenance edits both extend
`docs/specs/tier-w-local-corpus.md`; their distinct CLI and section 9 amendments
merged cleanly. The training-artifact recovery must preserve current legacy
exit-1 diagnostic semantics outside explicit transfer mode, and must preserve
current action pins and Windows gates.

Static compilation and normal Ruff passed after the initial merge. Focused and
broader results, including failures, are recorded in `TEST_RESULTS.md`.

The managed training transfer port retained the current legacy diagnostic exit
semantics and isolated strict transfer behavior behind explicit opt-in. Runner
publication, GUI accessibility and research modules were integrated by selective
commits; no unresolved conflict remains. Research source was adapted to current
manifest/output-store interfaces. Shared module index edits were coordinated
before workers created Search wiring, offline review and strict fetch modules.

## Current recovery conflicts

Saved FetchPlan integration conflicted with the separately recovered review
contracts in `tools/calibration/schemas.py` and `tests/test_calibration_tools.py`.
The resolution keeps FetchPlan, RunRecord and all three review schemas. The
Tier-R TrainingManifest uses its separate generator and remains intact. The
integrated schema/CLI/publication selection passed 209 tests with one native skip.

The historical Strings producer expected a raw file for every result. Current
cache/empty producers legitimately omit one. The additive normalized evidence
digest preserves traceability without inventing raw bytes; null omission preserves
legacy raw-backed serialization and basis digests. Full affected selection passed
1464 tests and independent review approved 49 controls. Newer export ownership
was retained throughout. No unresolved Git conflict remains.
