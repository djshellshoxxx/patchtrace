# Merge and release blockers — source-pinned checkpoint

## Latest continuation checkpoint — 2026-11-19 10:31:52 UTC

This section supersedes current-status statements in the earlier source-pinned history below. The history is retained verbatim. See the [continuation checkpoint](consolidation-20261119/continuation-checkpoint.md) and [complete remote snapshot](consolidation-20261119/continuation-checkpoint.json) for evidence, source identities and exact continuation.

**No additional main merge is currently qualified.** At the snapshot, #319 head a56ab13aaf9916fc12bea70ba1494075991b7f09 had one successful check, two skipped and 16 queued; #318 head c4ace2088ce8dc9ce78a0bf3036b81096accbdb5 had one skipped and 22 queued. Separate main push checks were 18 successful, one skipped and four in progress. Check/workflow completion and reviews must be refreshed; queued jobs are not passes.

The previous #318 Windows advisory run completed all 11 cases with zero failed/blocked, but its preceding source differs from the current head. The previous Linux full run retained 25,705 passes, one allowlist failure, 60 skips and three expected failures. The narrow test correction has passed focused review; neither historical run qualifies the new heads. Broad strict S-scan failures remain open.

The execution workspace is **unavailable again** after a brief recovery and delayed read-only commands. Shared admission refinements, Strings/Search callers, combined followup source and native/platform gates cannot be qualified while execution is unavailable. Inventory and bounded GUI source reviews are complete at their limited scope, but their runtime code remains local. The helper's 24-pass initial result predates later changes and is not a current-source pass. A corrected Strings red attempt exited 124 at an outer 120-second bound; no complete verdict was observed.

Both earlier local full runs are incomplete (exit 137); the second was not manually interrupted. Isolated controls passed unchanged without establishing an OOM/host/product cause. Do not rerun the whole suite unbounded or weaken assertions to obtain a green badge. Preserve current-source native H7/cache, full hosted, package/lifecycle, strict/resource, macOS/manual and separate accuracy gates.


Observed 2026-11-19 UTC. This file distinguishes merge qualification for a
particular change from the broader release and research program. Exact current
heads and completed actions are in [the operation record](final-consolidation-report.md).
No queued, skipped, mocked or unavailable check is labelled PASS.

## Candidate gates

| Candidate | Source and evidence | Disposition |
| --- | --- | --- |
| Foundation #317 | `88b0b52281dd314aa72f93819145a73135618bc4`, based on main `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. Linux/Windows full QA and repeated Qt passed; Linux package passed. Both Linux smoke jobs subsequently passed; all eight workflows completed successfully. | MERGED with expected-head guard as `fdc2696c23bdbfe7668348f25e3b336ce33039f7`, exact tested tree preserved and `[no release]` retained. Fresh main push checks remain separate. |
| Stable selective recovery | Based on #317; profile, raw/search, parser, advisory reads and default environment recovery plus qualification harness. | Local focused controls and reviews do not replace full exact-candidate hosted Linux/Windows/native/package gates. H7 must produce actual native child and raw-cache receipts on both hosts. |
| #318 portability repair into #316 | Remote `202bda41ea84784f2871289f36b9f5341c366a80`; parent `f2b6827fc6270b96fb241b0722f2878de5a17361`. Tree `391dd4b80ec87a8a803d67610d1e7b86d560ef0e` equals verified local repair tree. | Source repairs published for qualification. Full Windows suite and remaining strict/native/security gates remain open. It is not a main integration. |
| Whole #316 | `f2b6827fc6270b96fb241b0722f2878de5a17361`; 465 commits ahead of frozen main, 0 behind, substantial changes beyond #317. | PARTIAL INTEGRATION only. Original Windows QA: 37 failed, 25,516 passed, 151 skipped, 2 xfailed, 45 errors; original Windows Qt: 5 failed, 10,595 passed. Repairing one cause is not proof the whole stack passes. |
| Inventory #307 | Mixed inventory UI/parser/store, publication callers, native research and Windows qualification. | Separate extraction required. Only the unchanged `owned_publication` dependency and its direct controls were recovered for #313. Preserve current-index/unreadable-source preflight and later caller fixes before any inventory port. |
| Forced strings export | Inherited pathname-based replacement has a confirmed staging substitution race. | Scoped no-force repair may be reviewed independently. Forced replacement is not declared ownership-safe; preserve functionality and the red proof while designing its complete repair. |

## Strict scan and native blockers on the broad stack

At #316, the runtime-only unsuppressed S scan reports (exact flags:
`ruff check src --isolated --select S --ignore-noqa --no-cache --no-respect-gitignore --output-format json`):

| Code | Count |
| --- | ---: |
| S608 | 35 |
| S105 | 14 |
| S110 | 12 |
| S101 | 9 |
| S310 | 6 |
| S314 | 2 |
| S603 | 1 |
| S108 | 1 |
| **Total** | **80** |

This is a scanner result, not a count of established vulnerabilities. The same
gate is red on #318. A supplemental application of those flags found 66
observations on #317 and 68 on stable `96f2f103`; the two additional observations
are a guarded XML parser call and fixed-column SQL assembly, retained for
independent review. The broader exploratory `src tools` scan has 147 findings
and is not the same scan scope. The pass neither suppresses it nor treats historical green
ordinary Ruff as this separate strict gate. Review SQL construction, authored
sentinel literals, error handling, assertions, URL handling, parser invocation,
process arguments and temporary-path policy in their actual trust contexts.

#318's Windows advisory run `44484082165`, job `135423105494`, reached
explicit BLOCKED receipts because `llvm-dwarfdump` and `rz-diff` were absent.
Provisioning changes must retain pinned tools and actual acceptance assertions.
The broad native containment and unified repeatability requirements remain
unqualified until their actual current receipts are inspected. Portable C or
fake-runner tests cannot establish native network containment.

## Platform and release boundaries

- Linux and Windows are the inspected CI platforms. No macOS workflow was
  present in the reviewed tree; macOS is unverified, not passed.
- Native Windows held-handle and reparse behavior cannot be qualified on the
  Linux executor. The two skipped ownership controls remain native gates.
- Default primary environment isolation must succeed with real Ghidriff/Ghidra
  on Linux and Windows, with authored token/JVM-option sentinels absent in the
  actual child and a byte-identical raw-cache hit. Harness unit controls are
  separately labelled.
- Frozen Linux smoke and Windows portable ZIP, installer lifecycle and PE
  resource checks qualify only the tested source/artifacts. Manual interactive
  Windows and clean-machine acceptance remain separate release requirements.
- L1 advisory joins, L2 source-pair comparison and L3 real Windows-pair accuracy
  remain separate. Cases marked `facts: unverified` cannot be scored. Synthetic
  fixtures, test totals and adapter startup are not accuracy estimates.
- No release, tag or deployment is authorized by a passing PR. All merges in
  this pass must retain `[no release]` so automation does not publish a prerelease.

## Historical failures retained

The raw/search local 0.5 s host-construction failure was also reproduced on
untouched #317. Neither failure was suppressed or relabelled. The interrupted
20-repeat Qt attempt and exit-130 profile review have no completed result.
Fresh hosted combined source checks must resolve qualification; repeating a
small warm timing test does not erase those failures.

## Gate refresh procedure

1. Read the PR's exact head/base, draft/mergeability state and current main.
2. Follow all check-run/status pages; inspect workflow completion so downstream
   jobs have not merely failed to appear yet. Read current review evidence.
3. Reconcile changed source/dependencies and rerun affected qualification when
   either ref moves. Never reuse another head's green badge as exact-source proof.
4. Merge through the repository's REST operation with the expected head SHA.
5. Fetch the resulting main, prove ancestry/tree identity, refresh the complete
   branch inventory and retain the operation's response and new CI state.

Do not force-push, bypass checks, delete retained branches, or close a mixed
source PR merely because one useful slice was recovered.

## Publication updates

#318 now has remote head `2e301a74649e59e27b19a83bc283d646109ccd09`.
The Windows tool provisioning defect is repaired in source with pinned full
LLVM resources and Windows Rizin; 116 local workflow/corpus controls passed.
Actual Windows extraction, compilation and corpus outcomes remain pending.
The strict security scan remains a blocker, not a waived advisory.

Independent review of stable’s two additional runtime scanner observations found
only fixed SQL identifier construction at the S608 site and the refusing XML
parser target at the S314 site; 195 boundary controls passed. No suppression
or whole-parser/whole-query resource qualification follows from that review.

## Local full-suite interruption

The stable full suite was interrupted after progress stopped near the authored
BinDiff output-limit/timeout cases for more than 16 minutes (exit 137; no final
JUnit). Its heartbeat stopped on the expected approximate 3 s schedule. A
bounded isolated reproduction is required before attributing this to product
supervision, suite interaction or the executor. No test assertion was changed;
this is ABORTED, not full-suite PASS. Fresh hosted full-source gates remain open.

The two adjacent BinDiff controls subsequently passed unchanged in a bounded
isolated run (2 passed, 6.23 s). No host/product cause is established, and the
incomplete full-suite result is not converted to PASS.
