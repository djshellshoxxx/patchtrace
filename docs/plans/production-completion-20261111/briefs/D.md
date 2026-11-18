# WORKSTREAM D - Patch correlation and recommendations (end-to-end vulnerability-to-patch workflow)
Scope: src/patchtrace/kbcorrelation/** (KB/CVE correlator, patch search, pair resolution, source adapters, store),
src/patchtrace/pilot/** (patch-intent localization, leads), ui_leads.py and ui_kev.py (entry points only),
src/patchtrace/nway/**, series window.
Specs: kb-cve-correlation-and-acquisition.md, kb-patch-search-and-pair-resolution.md,
kb-patch-search-contract-blueprint.md, kb-patch-search-pair-lifecycle.md, kb-patch-search-qa-and-fixtures.md,
kb-patch-search-source-adapters.md, kb-patch-search-ui-cli-contract.md, patch-intent-localization-engine.md,
docs/specs/kb/*.md, docs/specs/kb-cve/31-A..31-H (31-H-tests-release.md lists acceptance),
docs/plans/kb-cve-adapters-finish-gameplan.md, kb-patch-search-implementation.md.
QA: docs/qa/audit-kb-correlation-20261107.md (KBA-01..08: 5 fixed; KBA-06..08 open with xfail tests:
`grep -rn 'KBA-0[678]' <main checkout>/tests <main checkout>/src`),
docs/qa/investigation-acceptance-matrix-20261105.md, candidate-correlation-20261105.md, investigation-candidates-20261105.md;
docs/research/accuracy-cases (L1 join corpus) and tools/research_qualification/l1_check.py.

Target chain: Binary -> Product identification -> Version -> CVE -> Security update -> KB -> Patched binary -> Binary
comparison -> Evidence -> Recommendation. For EACH hop: implementing module/function, CLI entry point, GUI entry point, tests
and evidence class, gaps.
Then the 15 required capabilities: identify candidate products/versions; correlate binaries with vulnerability records;
locate candidate security updates; identify patched versions; retrieve or reference update artifacts; compare vulnerable and
patched binaries; identify relevant changed functions; preserve supporting evidence; defensible confidence indicators;
analyst-readable recommendations; handle missing or contradictory information; manual corrections; persist findings and
evidence; export structured results; the same workflow from the CLI.
Does anything claim a vulnerability is 'fixed' merely because two binaries differ? Is there an analyst-readable
'recommendation' output at all (where; what does it say)? State exactly what an analyst can do today, offline, with
fixtures, end to end via the CLI (try the commands' --help and, if a checked-in fixture allows, one read-only invocation
writing only under your scratch dir).
For KBA-06..08 give the precise fix design and the test that would flip each xfail to pass.
