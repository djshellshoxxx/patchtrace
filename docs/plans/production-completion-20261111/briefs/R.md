# WORKSTREAM R - Specification registry and feature completion
Read docs/specs/REGISTRY.md and INDEX.md fully, docs/specs/program-e/OUTSTANDING-specs-ledger.md,
docs/specs/completeness-audit.md, docs/specs/non-goals.md, docs/modules.md (built slices; 1335 lines - skim by headings then
targeted reads), tasks/plan.md.
Produce one feature row per SPEC (SPEC-01.. and Program E ids such as KB, KEV, CAP, DIE, YRX, WB1-3, WBQ, FAB, PIL, LBL,
GDE, BUNDLE, UE): registry status as written; actual state verified by checking that the named modules and tests exist and
are wired (CLI registry in src/patchtrace/cli.py, panel manifest src/patchtrace/panel_manifest.py); the acceptance gates
the spec lists, counted: gates_total, gates_met, gates_blocked_external, gates_open - put the counts in each feature's
`acceptance_tests` (as strings like "gates_total=12 met=8 blocked_external=3 open=1") and use them for implementation_pct
and validation_pct; flag registry rows whose status is stale (master-todo T13) with the correction.
Also list specs that are approved but not built, and features built without a spec.
This workstream's numbers feed the project-wide completion estimate, so `basis` must give the summed gate counts.
actionable_now: registry/status corrections (docs) and small spec-vs-code mismatches you verified.
