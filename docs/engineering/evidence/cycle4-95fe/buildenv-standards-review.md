# Independent standards review: Build environment header help

## Reviewed identity

- Fixed point: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Reviewed integrated source: `b65fba2f5567f0b129331364bbf6db1cd699c901`.
- Reviewed complete tree: `889c6383fb4d231fd6698b71511214e8c9c8fac0`.
- Comparison: `git diff 11f51c105bf63946f59373ae605b937c4fee607a...b65fba2f5567f0b129331364bbf6db1cd699c901`.
- Isolated reviewer checkout: `/workspace/scratch/patchtrace-95fe-c4/buildenv-standards`.
- Dedicated reviewer interpreter: `/workspace/scratch/patchtrace-95fe-c4/buildenv-standards-venv/bin/python`.

The checkout was clean before and after both executed audit runs. Its separate
editable environment resolved the reviewed worktree; the missing-binding control
also asserted the exact imported source path under Python isolated mode.
No production source, coordinator checkout, remote ref or workflow was changed.

## Findings

**Zero documented-standard violations and zero actionable baseline code-smell
findings in this diff. No blocking standards finding.**

`AGENTS.md` requires backend/schema/provider logic to remain outside the UI and
meaningful invariant/integration verification. The only production differences
are the five `ColumnSpec.tip_id` arguments in `buildenv/panel_model.py` and five
static entries in `buildenv/tooltip_entries.py`. Independent AST controls removed
only those additions and reproduced both original modules exactly. Existing
imports, field getters, widths, row keys, preparation, state, parsing, persistence,
network and worker lifecycle behavior are unchanged.

The GUI plan's panel contract (section 8.2, `tips`/`tip_templates`) requires pure
registry entries under the panel prefix and idempotent registration. All five new
IDs use `build_env.col.*`; existing `PANEL.tips` and controller registration supply
them through the existing registry. The existing shared table renderer handles
registered header help and title fallback; no second renderer or registration
mechanism was added. The changes introduce no Qt import into the pure modules.
Existing display/accessibility roles and cell/copy paths are unchanged.

The new application tests inspect actual controllers and model header roles,
including empty/populated states, normal host activation, cell/copy preservation,
registry escaping, fallback and a missing-mapping control. The global audit's
three-line change initializes Build environment through the real host and checks
five real sections. It neither adds an exemption nor credits declarations without
observing actual header help. The narrowly authorized audit extension is consistent
with the new header-help contract's requirement for actual application coverage;
it is not an expansion of the old shared-file integration seam.

Repeated static effect copy and literal expected header IDs are appropriate to
this small declarative change; extracting an abstraction would add complexity.
No smell warrants a requested change. Lint-only concerns are outside this review.

## Independently executed evidence

| Control | Actual outcome |
| --- | --- |
| Unmodified `tests/test_tooltips.py::test_every_registry_id_is_applied_somewhere` | **1 passed** in 2.52 seconds |
| Same global audit with only the Basis `tip_id` removed in memory | **1 deliberate failure**, listing exactly `build_env.col.basis`, in 2.39 seconds |
| Remove only five new bindings from the panel-model AST | Exact equality with fixed-point AST |
| Remove only five new entries from tooltip-data AST | Exact equality with fixed-point AST |

The negative control is an expected test-of-the-test, not a candidate defect or
an additional passing product case. It used the unchanged on-disk source and
existing global audit. The positive test overlaps the coordinator's maintained
selection; do not add it to distinct qualified-test totals.

Full commands, source/tree identities, timestamps, exit codes, complete output,
JUnit and the control script are in `buildenv-standards-evidence/` alongside the
independent AST receipt and a SHA-256 manifest.

## Limits and handoff

This is the independent standards axis only. The separate spec reviewer owns
requirement completeness and copy-semantic conclusions. The coordinator owns the
combined-source selection, full hosted qualification, documentation/evidence
publication and coordination with the other foreground session. No full-suite,
Windows, NVDA/Narrator, high-contrast, DPI or release acceptance is inferred.
