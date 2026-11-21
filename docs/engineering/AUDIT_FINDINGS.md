# PatchTrace audit findings

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
