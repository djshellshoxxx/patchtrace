# PatchTrace audit findings

## November 23 project reliability candidate

The [defect register and verification evidence](project-reliability-20261123.md#defects-ownership-and-dependency-order) cover database retention, constructor cancellation, SQLite share paths, recent-project settings and repository identity.

## Current PR349 Intel + C4 follow-up

[Current report](cycle837fe-native-c4-20261121.md) and [ledger](task-ledger.json):tested `6bf79fef` / `dc659c7e`, 1,396 passes/1 CODEX-5xfail, zero failures/errors/ordinary skips, required lint/dependencies/source binding and independent whole-tree review. ExistingPR349 combines fixed Windows identity, five Build environment help mappings and bounded Pages lock/isolation with earlier storage/Search/pinning/cache/frozen work. Exact new-source hosted/native/package gates remain pending;main/release readiness is not claimed.

Original Windows failures and Tier R 5/11 coverage gap remain evidence; the same Tier R gap occurred on original PR349. Four more historical scopes need no port;whole branches remain partly reviewed and 181/16 census unchanged. Root owns PR349 qualification;C4/Intel histories are retained. Earlier current-state paragraphs are historical for these scopes.

## Cycle4 parent integration update — 2026-11-21 UTC

The separate C4 follow-up includes PR349 `daee337c` and preserves both implementations
and histories. Source `111803d5` / REST code checkpoint `7ddb1130` passed 580 cases,
with one CODEX-5 expected failure and no ordinary skips; all 110 registry cases are
included. Required Ruff/pip/source binding and independent merge/history reviews
passed. CODEX-1 is closed by the parent; wider CODEX-5 and hosted/native/manual/release
gates remain open. [Current report](cycle4-consolidation-20261121-95fe.md) and [exact qualification](evidence/cycle4-parent-20261121/qualification.json)
supersede the earlier pending C4 combination state. PR349 ownership stays with 837FE;
resolve final follow-up head/checks from its live PR. Main/release eligibility remains
false. A qualified main commit requires `[no release] [no deploy]`. Earlier sections
remain source-specific history.

## Cycle4 bounded parallel follow-up — 2026-11-21

This is a separate bounded follow-up to PR #349. Its integration remains with
the parallel 837FE owner. Read the [cycle4 report](cycle4-consolidation-20261121-95fe.md)
and [authoritative ledger](task-ledger.json); resolve the live follow-up PR for
the final published head and hosted checks. Earlier sections below remain source-specific history.

Resolved locally: five missing Build environment header bindings; confirmed Pages
site-only pydantic fixture error; and P3 S-PAGES-01 (pytest prerequisite documentation).
All four independent source reviews have zero remaining findings. Preserve the
original failures and intentional negative controls. The separate CODEX-5
run-block audit blind spot remains open; no compromised workflow is inferred.
PR #349's previously recorded Windows advisory findings remain with its qualification owner.

## Cycle3 current findings and disposition

| ID | Finding | Disposition |
| --- | --- | --- |
| C3-01 | Cache contract reader searched an incomplete rizin step name; negative controls could pass on an already-invalid baseline | Fixed in53e02a47; baseline failure retained; actual-source selection30 passes/2existingxfails; independently reviewed |
| C3-02 | Two cache import-spacing errors and obsolete Linux pytest import failed whole-tree Ruff | Narrow test-only repairs53e02a47/5fa47ac7; original errors retained; final lint passes |
| C3-03 | Sibling reconciliation omitted six required engineering indexes and 14 linked original artifacts | All20 files recovered and blob-verified; current indexes reconciled separately |
| C3-04 | Cache author-control summaries disagreed at12/10 versus retained14/14 receipt | P3 current summaries corrected; older Git versions and original receipt preserved |
| C3-05 | Pages had no explicit per-push deployment hold for authorized integration without deployment | Separate contract/source-reviewed deploy-only `[no deploy]` condition; no deployment performed |

Two independent CODEX-6/CODEX-14 review axes and independent Pages reviews found no blocking source defect in their named changes. This is not a whole-repository security or correctness certification. CODEX-1/5 and broader native/manual/raw/accuracy acceptance remain open. [All reviews and failures](evidence/cycle3-95fe/README.md).

## Retained historical cycle95fe record

Authority: [task-ledger.json](task-ledger.json). Scope: cycle 95fe and the named
late-stack repairs, not an assertion that all repository code has been audited.

| ID | Severity/type | Finding | Status |
| --- | --- | --- | --- |
| C95-01 | Low, request-order correctness | Invalid candidate component values reached current-project verification or service construction before refusal | Fixed in `649ed46e`; independently reviewed; 183 related cases pass on combined source; full/hosted pending |
| C95-02 | Moderate, engineering reproducibility | Inventory replay could not read its own 162,564-character evidence field | Fixed in `076c1ffa`; independently reviewed; real report reproduced exactly |
| C95-03 | Low, acceptance coverage | Required real form-feed CSV inputs were absent from the regression table | Covered in `c71d604e`; no production serializer defect claimed |
| C95-04 | Low, acceptance coverage | Busy-lookup exception and unknown-operation timeout diagnostics lacked checked-out-source controls | Covered in `c71d604e`; original timeout object and 10,000-ms budget preserved |
| C95-05 | Low, coordination | Top-level ledger and feature checkpoint lagged generation-41 entries | Current indexes and cycle ownership reconciled; historical evidence retained |

## C95-01 — candidate request ordering

Affected seam: `kbcorrelation/investigation_service._execute`.
A direct `candidate_pairs` or `candidate_preview` request carrying an invalid
component value and a captured current-project snapshot could enter
`_verified_current` before the component guard. Requests without a snapshot
could still construct the workspace service first. The normal Qt producer
supplies no current-input snapshot for these operations, so this was a contract
ordering gap rather than a demonstrated ordinary GUI regression.

The candidate-only exact-string and start-mode checks now precede those reads.
Cancellation and invalid start-mode precedence remain. The private snapshot
helper has no existing unchecked caller. Regression evidence: four expected
failures against inherited runtime; 21 fixed focused cases included in 183
related passes. Independent reviewer verified source, caller graph and receipts.
No schema or analysis capability changed.

## C95-02 — inventory snapshot replay

Affected seam: `tools/branch_inventory.py::branches`.
The captured 353-topic report is 2,228,790 bytes, with a largest field of 162,564
characters. The original CSV parser rejected it at its 131,072-character default.
The actual failing command and two failing unit regressions are retained.

The reader now enforces a 32 MiB byte budget before decoding/materialization,
temporarily applies the corresponding bounded CSV limit, and restores the prior
limit even on failure. Prior successful output is retained on refusal. Existing
commit resolution, ancestry, duplicate-name and deletion policies are unchanged.

Ten unit cases passed. A full replay of the real captured refs and PR metadata
produced the identical report SHA-256:
`d82d52544646eb029f38684e2dd3802ffa1596c7eb02d5c11d0ae0b5783aa902`.
The first fixed receipts were precommit and the real replay spanned the commit
of identical tool contents; they must not be called clean postcommit runs.
The combined frozen-source selection supplies the clean qualification separately.

## C95-03/C95-04 — test completeness

The real serializer now receives actual form-feed formula-like and ordinary
values, with unchanged JSON values checked across the display table.
Diagnostic regressions exercise a raising busy lookup and an unknown plain
operation. They preserve the original timeout object as the exception cause,
assert the unchanged wait budget, and exclude private diagnostic sentinels.
The two full test modules passed 47 cases. These were passing coverage additions;
no failing production baseline is claimed.

## Independent late-stack source dispositions

- CSV prefix handling already applies to all columns, preserving original text
  behind the protective prefix; it does not claim universal spreadsheet behavior.
- Qt timeout diagnostics retain bounded fixed-vocabulary context and the original
  timeout. Native Windows recurrence remains a separate unresolved question.
- Direct Create final-component junction refusal is narrow and correctly scoped;
  parent substitution or atomic publication is not established.
- Source-plan lead admission uses the expected plain-string/fixed-error policy.
  Its old test name claiming no IO is broader than its actual assertions.

## Preserved open gates

The full local combined attempt at `ccc3664f` ended SIGKILL (-9) after 23.089
seconds, before any test-start event, with no JUnit or terminal pytest summary.
Source remained clean. Maximum recorded child RSS was 197,080 KiB; cgroup memory
events were unavailable. This evidence does not establish an OOM or other cause.

Earlier full-run SIGKILLs, the original Windows Qt timeouts, and the original
native raw-cache `java=unverified` failure remain preserved, even where newer
source-specific hosted runs pass. Linux forced-export publication, complete raw
Winbindex source/index membership, native Windows trust/manual/accessibility
acceptance, and separate L1/L2/L3 evidence remain open or externally owned.
No whole-product security, accuracy or release-completion claim is made.

## Combined-source qualification

The 27-file attempt and the later GUI and integrity/coverage batches also ended
SIGKILL after 70.395, 32.827 and 21.474 seconds respectively. Each lacks a terminal
summary/JUnit. The admission batch passed 183 cases; a later changed-case
selection passed 50. Their 21-case overlap leaves 212 distinct passing cases on
clean `ccc3664f` across two bounded processes. No progress markers from killed
runs are counted. The [qualification record](cycle-95fe-qualification.md) retains
the independent diagnosis and its limits; full/hosted/native acceptance remains
pending.

## Current combined PR349 candidate — 837FE

[Combined report](cycle837fe-combined-pr349-20261121.md) and [authoritative ledger](task-ledger.json) supersede earlier next-action text only for the completed named scopes. Reviewed storage/Search, CODEX-1 and Intel repairs are integrated with the released 95FE Linux/cache/Pages source. Final code `2a67980c` passes 1,296 affected cases with 1 CODEX-5 xfail; new-head hosted qualification and main promotion remain pending. Preserve original failed controls, the PR349 registry failure, Windows Intel limits, all historical branches and separate release gates.
