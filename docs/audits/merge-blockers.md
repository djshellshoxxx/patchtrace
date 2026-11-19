# Merge and release blockers — source-pinned checkpoint

## Published outcome — 2026-11-19 11:56:58 UTC

The reviewed continuation source and evidence were published in draft
[PR #321](https://github.com/djshellshoxxx/PatchTrace/pull/321) at
**2042e24dc7f3eac265e0eb183c738527852b22cf**, tree
**8e5327e9348c41496a029cb090337e1308d3ce5b**. The tree equals verified local
**e8a6592c02544d8186416be64f9df78f31078a52**. The expected-head guard preserved
checkpoint **976dddfbbcdf9a320e48813d8cf2c3c6540aac81** as first parent and
updated core **8d130aefe1be6e737cff1d90d2a5b1658d60a3a6** as second parent. All 212 changed-file blobs,
both parents, the exact tree, branch ref and PR head/base were read back.

This later receipt revision changes documentation only. It records completed
publication, superseding the earlier preparation instructions below. The
reviewed runtime remains 9335e7dc and the sole later test change remains the
approved cache-pin assertion 5575af79. Main remains **fdc2696c23bdbfe7668348f25e3b336ce33039f7**;
there has been no additional main merge, branch deletion, force push, release,
tag or deployment.

[Guarded publication receipt](consolidation-20261119/continuation-publication.json),
[core correction receipt](consolidation-20261119/core-cache-pin-publication.json),
[combined QA](../qa/combined-recovery-20261119/README.md).

### Current qualification boundary

**No additional main merge is qualified.** The complete 11:53:11 UTC gate snapshot
is tied to the published runtime heads. The documentation receipt revision needs
its own current-head check readback; no pending job is converted to a pass.

| Scope | Source | Observed checks |
| --- | --- | --- |
| pulls/318 | `c4ace2088ce8` | 2 queued; 2 skipped; 16 success; 6 in progress; 2 failure |
| pulls/319 | `8d130aefe1be` | 1 skipped; 13 queued |
| pulls/320 | `087f50aae76f` | 28 queued; 3 skipped |
| pulls/321 | `2042e24dc7f3` | 2 skipped; 14 queued |
| pulls/322 | `32cc4b04cf1f` | 21 queued; 1 skipped |
| branches/main | `fdc2696c23bd` | 5 queued; 2 skipped; 22 success |

Main's scheduled/non-gating runs are included in that same-head snapshot; they
are separate from the completed foundation PR qualification. No submitted GitHub
reviews were returned for the candidate heads. Independent source reviews are
recorded separately. The new core/continuation and external candidates remain
draft; #318 retains two actual strict-security failures.

Strict runtime scan results remain red: 68 core, 80 broad and 82 combined. Their
trust-boundary review is not a waiver. Inherited forced Strings publication and
ordinary OSError cleanup ownership remain P2. Fresh applicable full/native,
Windows sharing, packaging/lifecycle, manual/macOS/assistive-technology and
separate L1/L2/L3 accuracy gates remain open.

[Exact gate/status/workflow/review receipt](consolidation-20261119/post-publication-gates.json).


## Earlier preparation checkpoint — 2026-11-19 11:34: 21 UTC

This current section supersedes the dated interruption status below. Original
source records and failed/incomplete evidence remain preserved. The execution
workspace recovered; the previously unpublished inventory, GUI, Strings,
Search and shared-admission source is now assembled locally for guarded publication to the continuation
candidate [PR #321](https://github.com/djshellshoxxx/PatchTrace/pull/321).
At preparation, remote #321 still has documentation checkpoint 976dddfb; the
actual guarded publication is established by its later PR receipt. This is a
candidate, not an additional main merge or release acceptance.

Reviewed runtime: **9335e7dcadc6d0337243f894e8f234ccc74bc62e**, tree
**05509de7d8038a9079fe80b08fa97da8cb61b7fd**. Main remains **fdc2696c23bdbfe7668348f25e3b336ce33039f7**.
The [resumed checkpoint](consolidation-20261119/resumed-checkpoint.md) distinguishes
the tested source, later CI-test correction, publication guard, exact component
pins and remaining gates. The final guarded publication SHA belongs to the PR
operation receipt; local and REST-created commit IDs are not assumed equal.

## Current gate boundary

**No additional main merge is qualified.** This is a precise current-source
test/review/platform boundary, not an execution-workspace outage. The workspace
recovered and the local source/evidence assembly completed.

At **2026-11-19T11:27:59.024Z**, the complete check/status/workflow/review reads were:

| Candidate | Exact head | Check-run snapshot |
| --- | --- | --- |
| pulls/318 | `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` | 6 queued; 2 skipped; 14 success; 4 in progress; 2 failure |
| pulls/319 | `a56ab13aaf9916fc12bea70ba1494075991b7f09` | 2 queued; 10 success; 5 in progress; 2 skipped; 1 failure |
| pulls/320 | `bc7eb6328b477e2ff19cfe36317279eaf5856fb6` | 3 skipped; 28 queued |
| pulls/321 | `976dddfbbcdf9a320e48813d8cf2c3c6540aac81` | 1 skipped; 7 queued |
| branches/main | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` | 1 queued; 22 success; 1 skipped |

All four candidate heads had a successful Snyk legacy status; no submitted
GitHub review was returned. Independent agent reviews are separate records.
Queued/in-progress/skipped jobs are not treated as completed passes. Later
CI-test source updates require their own exact-head checks.

#319's Linux job 135483923306 failed one workflow-pin assertion after 23,268 passes,
50 skips and 6 expected failures. It rejects the approved immutable cache action
because the old assertion expects a version tag. The narrow correction and
independent qualification are tracked in the subsequent CI receipt. Its earlier
full failure remains a failure; local focused success will not relabel it green.

#318's two hosted static-security jobs 135484111301/135484075846 both report the
same80 Ruff-S diagnostics, normal exit 1, with no timeout/output limit/launch error.
The PR checkout is synthetic merge de9a8cf060a5def95acb9d887f68e0dc01237221 and
the push checkout is c4ace2088ce8dc9ce78a0bf3036b81096accbdb5; both have exact
tree ee130e5c201683794abf42b76fb6c9372731d892. No gate is waived.
[Hosted failure summary](consolidation-20261119/pr318-security-c4-summary.json).

The same isolated runtime-only scan on immutable local source reports **68** on
core 319 and **82** on combined 9335, with 14 added and zero removed diagnostics.
Added sites are12 inventory SQL diagnostics, one inventory URL opener and one
Search SQL construction. Fixed SQL/parameters, URL/DNS/TLS and exact consent were
reviewed in context; that review does not suppress the findings or turn the
strict scan green. Ordinary Ruff is a distinct passing check.

## Remaining acceptance work

- Finish applicable exact-source hosted Linux/Windows full QA, repeated Qt,
  actual native/cache/child-environment and packaging/installer lifecycle gates.
- Keep the native Windows existing-object-sharing control unqualified on Linux.
- Keep the inherited forced Strings source/cleanup ownership races open until
  a preserving supported-platform protocol and adversarial controls qualify it.
- Resolve strict-security diagnostics through substantiated fixes/dispositions
  under repository policy; neither suppressions nor automatic waiver were added.
- Preserve the earlier two incomplete exit 137 full runs, the exit 124 Strings
  attempt and known elapsed-time failures. The combined 1199-pass selection is
  not a completed full suite.
- Keep macOS, clean-machine/manual Windows, actual assistive technology and
  separate L1/L2/L3 accuracy acceptance open. Never score unverified facts.

The external #320 and checkpoint81e4 branches retain distinct active source and
their own qualification needs. This continuation does not overwrite or approve
those branches. Source freshness must be checked before any later integration.

### Completed core CI correction and publication

Core PR #319 was guarded forward from a56ab13a to **8d130aefe1be6e737cff1d90d2a5b1658d60a3a6**.
Its tree **ce0399940c5fa24ea017498f9e4cf80b0ee6d2de** equals local
**e9be6e009ff0aee69ca7be78d47c5b740b62fd00**. The four changed files are
one test assertion and three QA files; runtime and workflows are unchanged.
One red control precedes 21 related passes and six independent guard controls.
The old 23,268-pass/one-failure full run remains failed; the new head needs its
own hosted qualification. [Source and QA](../qa/tier-r-cache-pin-20261119/README.md),
[guard, exact tree/parent/ref and PR readback](consolidation-20261119/core-cache-pin-publication.json).
The continuation publication is prepared with original checkpoint 976dddfb as
first parent and this fresh core head as second parent. Its actual ref update
is established by the subsequent PR #321 publication receipt.

## Historical interruption checkpoint — 2026-11-19 10:31:52 UTC

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

The second full suite, on #319's exact tree using the dedicated interpreter,
also ended without a completed result: exit 137, no requested interruption,
1,344 progress outcomes, no final JUnit or diagnostic stack dump. Its active
memory-cap control passed alone (1 passed, 2.97 s). Neither executor memory
exhaustion nor a product cause is established by these observations. Exact
receipts are linked from the operation record; full hosted qualification remains
blocked until actual current-source results complete.
