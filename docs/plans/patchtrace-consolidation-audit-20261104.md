# PatchTrace consolidation audit — 2026-11-04

This is a verified initial inventory, not a claim that source code has been merged. GitHub compare was run against current `main` using `pull/N/head` refs.

| PR | Ahead | Behind | Files reported | Focus |
|---|---:|---:|---:|---|
| #174 | 29 | 2 | 57 | live gate / rz-diff |
| #176 | 26 | 2 | 98 | offline KB / calibration / GUI |
| #177 | 7 | 3 | 8 | parallel QA |
| #178 | 1 | 4 | 11 | research handoff |
| #179 | 7 | 2 | 6 | consolidation ledger/tool |
| #180 | 102 | 2 | 188 | unified-engine hardening |
| #181 | 9 | 2 | 13 | rules / callgraph |
| #182 | 4 | 2 | 28 | synthetic KB fixtures |
| #183 | 13 | 2 | 144 | consolidated research/docs |
| #184 | 4 | 2 | 5 | QA load races |
| #185 | 105 | 2 | 191 | help fixes stacked on #180 |

Counts are snapshots of GitHub comparisons, not unique patch counts or completed work.

## Integration strategy

1. Refresh current main and existing ownership from #179 and open PRs; inspect required checks and actual PR bases before editing. Do not modify active contributors' branches.
2. Treat #180 → #185 as one candidate chain. Inspect #185's actual parentage, isolate the help changes, and do not separately merge duplicate engine commits. Run unified-engine and help CLI acceptance tests.
3. Reconcile #177 and #184 test-file overlaps (test_backend_symbol_local.py, test_jobs.py, test_ui_related_panel.py, test_ui_unified.py). Preserve the more complete assertions and run focused QA before integration.
4. Integrate independently reviewed #181 rules/callgraph and #182 KB fixtures after checking overlap with #180. Run their contract/regression suites.
5. Review #174 and #176 as native gate / calibration workstreams; compare against already-merged GT-01 fixes and retain failure evidence. Validate native tools where available, explicitly mark unavailable tool gates.
6. Reconcile #178/#179/#183 research and documentation by deduplicating, preserving source references, and checking that docs match actual implementation.
7. Keep #170/#171/#167 agent automation separate from feature consolidation; do not activate competing API-funded workflows without validating budget/ownership controls.
8. Review older open PRs (#163–#168, #69/#136/#142, #126 and others) for changes already represented by recent consolidation PRs before deciding whether to port or close. Do not assume supersession solely from titles.

## Acceptance for each integration slice

- Identify exact source commits and source PRs.
- Check base/head ancestry and file-level overlap against current main.
- Preserve working implementations; resolve conflicts semantically.
- Run relevant tests and required CI; report missing environments honestly.
- Publish a focused PR with evidence; merge only when current branch protection, review, and checks permit.

**Next executable slice:** reconcile #177 and #184 test changes, or isolate #185's help changes atop #180, after inspecting current CI and active ownership. This audit alone does not perform source-code consolidation.
