# PW-01 retained source pages — 2026-11-18 UTC

## Scope and integration identity

This continuation preserves both published histories: PR #303 at
`66de75b56d372784fcadc95388d41cdcbfd7f975` and the reviewed consolidation
PR #304 at `bb4277aed685d485b57ffe7a718e70bab3e34467`. Local merge
`a783689a` joins those parents without replacing either branch. The reviewed
combined implementation is `c023dec36a464c3e7e1a8689f52a22263f0c24c5`,
published as `be9b168cf24620ad86d04be474660b5d31f655b9`, exact tree
`d390d0f2f77b34cdb0a265b9bfb33e06d4428e09`. The
[publication mapping](pw01-retained-pages-20261118/publication-code-mappings.json)
records every equivalent code commit. Hosted qualification and integration into
main are separate gates.

The change addresses a reproduced source-format limitation: the official saved
KB5036893 CSV begins with more than 21,000 ARM64 rows. The v1 parser's 5,000-entry
budget therefore retains no AMD64 claims, even though a later x64 section is
present. Changing a context assertion to AMD64 does not filter those rows and
must not manufacture a matching architecture.

## Preserved source evidence

The actual CSV is 3,300,683 bytes, SHA-256
`b327eb5d0f8d7a0d6a9c8c2d1a7af1df134bc2a54c3e0da2eff0fb335547a627`.
Its exact source URL is recorded in the [capture receipt](pw01-retained-pages-20261118/proxy-csv-receipt.json).
The complete baseline archive, including original bytes, parser output,
production request plans and failed attempts, is
`patchtrace-pw01-source-evidence-20261118.zip`, SHA-256
`115f3b74245344dda935f07803e01c8bb20b00657f87e9a62f185b8c30ab0741`.
It contains 33 files and preserves the initial source qualification unchanged.

Production `inventory_fetch.fetch_source` was attempted with the exact approved
forwarding, full redirect-chain and direct CSV plans. All three failed during
DNS resolution before TLS, returning PT-KBC-ACQUIRE / PT-ACQ-NETWORK. No opener,
proxy, timeout or transport replacement was injected. The separate environment
proxy capture obtained the support HTML, inspected the 302 target and downloaded
CSV metadata. That saved-source success does not qualify production retrieval.
No target binary or update package was downloaded or executed.

## Implemented behavior

`kb inventory retain IMPORT_ID --architecture amd64 --page 1` appends an
immutable v2 page from an already retained source. The service and desktop use
the same backend. Source-page controls are separate from pagination over rows
in an existing page. Retention does not select a filename or change an
investigation revision.

The parser scans the bounded source to EOF, or reports an incomplete scan at
the captured record limit. It retains at most the original entry budget and
checks metadata conflicts across all scanned rows, including other pages.
Unknown or contradictory architecture claims remain available for review.
Each retained metadata-conflict group has exact source-record witnesses.
Incomplete v2 scans cannot feed filename selection or replayed hints.

The original raw object, SourceDoc, context, limits, asserted URL, retrieval
receipt, v1 record and existing selections remain unchanged. Repeating a policy
is idempotent, including from another page's import ID. Fatal parsing,
cancellation or validation failures publish no page and preserve prior results.

V1 PE classification is explicitly pinned to its original eight suffixes. Root
review reproduced a compatibility defect when the consolidation's new shared
`.tsp` allowance reclassified an existing v1 row under unchanged IDs. The stored
v1 fixture from published #303 now replays byte-for-byte as descriptive-only;
v2 recognizes `.tsp` with separately versioned identities.

The selected-decision reader also bounds SQLite TEXT by byte length before
Python allocation, refuses other storage types and retains previous decisions.
This is the independently reviewed `e0775630` repair retained in local `35ed5fb2`.

## Actual saved-source qualification

Backend author commit: `302eaa6d812038c77b513c9533cd7420903b1622`.
The [four-page receipt](pw01-retained-pages-20261118/real-retention-result.json)
records actual parse, append, verified raw replay and unchanged-source checks.
All four pages scan 42,845 logical records and report 18,761 matching accepted
claims, 18,834 excluded accepted claims and 5,244 rejected data rows.

| AMD64 source page | Retained claims | Original logical records | Conflict groups witnessed |
|---|---:|---|---:|
| 1 | 5,000 | 21,263–26,503 | 537 |
| 2 | 5,000 | 26,504–31,522 | 767 |
| 3 | 5,000 | 31,523–36,533 | 612 |
| 4 | 3,761 | 36,534–42,845 | 1,572 |

These are source claims, not distinct files or confirmed vulnerability fixes.
The `aarsvc.dll` size contradiction at records 24,355 and 41,380 remains visible
on pages 1 and 4. All 18,761 matching claims are reachable without raising the
5,000-entry ceiling. Path-valued and otherwise unsafe filenames remain rejected;
no path stripping or new eligibility inference was introduced. The original v1
import and compressed raw object are unchanged, with zero investigation
revisions created. Repeating page 1 from page 4 returns the same retained import.

Root subsequently ran 13 separate processes through the actual shipped CLI at
the reviewed combined commit: import, inspect, all four retain/show pairs,
reinspect the original, repeat page 1 through page 4, and list. Every operation
returned its expected exit code and JSON status; all four pages were reopened
and verified from persisted raw evidence. The original inspection was identical,
source provenance remained unchanged and the final store contained exactly five
imports. The [CLI receipt](pw01-retained-pages-20261118/real-cli-qualification.json)
retains exact argv, output hashes and per-operation exit codes. Partial exit 3
continues to disclose rejected, excluded or omitted claims; it is not relabeled
complete merely because the bounded source scan reached EOF.

## Independent review and regression evidence

| Check | Result and scope |
|---|---|
| Backend regression proof | 23 initial failures, including frozen v1 replay drift; final adjacent suite 705 passed. |
| Initial service/CLI/Qt slice | Author commit `5c9cd30d`; 25 dedicated and 554 broader inventory tests passed. |
| Independent backend review | Adapter author inspected strict identities, complete-source conflicts, replay, preservation and selection refusal; 167 generated pages, 1,077 retained-entry checks and 574 witness-contradiction checks retained in the review transcript. |
| Independent root reference oracle | 80 generated CSV sources, four architecture policies, 1,770 pages; full-source conflict witnesses, reachability, duplicate links and deterministic replay agree with separately computed expectations. |
| Actual-source independent replay | Separate reviewer verified the raw digest and page-one counts, including the cross-page `aarsvc.dll` contradiction. |
| Worktree-aware receipt identity | Independent 141-test run and 25 extra controls passed at `9ac9cbeb`; shared/private refs, malformed metadata, nonregular files and no process execution verified. |
| Final combined independent gate | At `c023dec3`, 1,076 passed / 2 native-Windows publication skips in 37.13 seconds; Ruff, schema `--check` and whitespace checks passed. |
| Independent adapter and captured-source probes | Ten passed, including fetched provenance, exact captured request identities, cancellation/stale-result preservation and actual `aarsvc.dll` row evidence. |
| Sequential full-file attempt | INCOMPLETE at `c023dec3`: four completed batches report 5,308 passed, 1 failed and 31 skipped; eight other batches were killed without completed JUnit. |
| Native Windows publication gate for PR #304 | At exact head `bb4277aed685d485b57ffe7a718e70bab3e34467`, 15 failed, 61 passed and 3 skipped; subsequent full QA and packaging were skipped. Merge remains blocked. |

Overlapping suite counts are not added. Whole-tree Ruff, schema regeneration
checks and whitespace checks passed for the authored backend and adapter
commits. The prescribed whole-process local pytest attempt at `a6996fd0` ended
with exit 137, a zero-byte pytest log and no JUnit summary. It is incomplete;
the termination does not establish its cause. A separate sequential file-batch
attempt at `c023dec3` has now finished **INCOMPLETE**. All 845 tracked test-file
arguments appeared exactly once across 12 attempted batches. Four batches,
covering 282 file arguments, produced completed JUnit reports: **5,308 passed,
1 failed, 31 skipped and 0 errors**, or 5,340 reported cases. This is a
completed-report subtotal only. Eight batches, covering the other 563 file
arguments, ended with return code -9 / shell exit 137 and no completed JUnit;
execution of every test in those batches is unproven. No retry was performed.

The preserved failure is
`tests/test_binexport_isolation.py::test_run_process_memory_cap_is_enforced`:
its uncapped allocation helper returned -9 before the capped-memory branch was
reached. Neither that return code nor the observer's memory snapshots establishes
the cause. The [qualification report](pw01-retained-pages-20261118/full-batched-c023dec3/qualification-report.md),
[summary with exact batch receipts](pw01-retained-pages-20261118/full-batched-c023dec3/summary.json),
[original controller](pw01-retained-pages-20261118/full-batched-c023dec3/run.py)
and [independent evidence check](pw01-retained-pages-20261118/full-batched-c023dec3/independent-review.json)
are preserved byte-for-byte as a compact extract. The complete 43-file archive
is `pw01-full-batched-c023dec3-20261118T0834Z.tar.gz`, SHA-256
`cdbf61d69fd198029c3e88f7acd208ee8575939c97d36b679654ae683165a66d`.
Independent review verified its 43 archived files, all 42 payload hashes, the
845-file inventory and JUnit aggregation without rerunning tests. Ruff, schema
and whitespace checks passed in this attempt; whole-process QA and Qt repeats
remain mandatory.

### Resolved desktop evidence-visibility finding

Independent review reproduced a real-source failure at `5c9cd30d`: the complete
source preview reached its 65,536-character cap before the conflict witnesses,
while the selected `aarsvc.dll` row's detail omitted record 41,380. The backend
and CLI JSON retained the evidence, but the desktop could not display the second
reference. Additive repair `5960cfbe` places only the row's matching witness
before potentially long original fields, without increasing a display budget.
Two new regressions failed before the repair; 140 focused/adjacent tests and all
ten independent probes pass after it. The final combined actual-source receipt
shows a bounded 2,789-character row detail containing both complete references
and the `size_bytes` field. Original red and green receipts remain separate.

## Research receipt identity

The generic `git_head` helper previously looked only for `.git/HEAD`, leaving
linked-worktree runs with `patchtrace_sha: null`. The reviewed fix understands
bounded gitdir pointers, shared commondir refs, detached heads, packed refs and
private worktree ref namespaces without running Git, reading configuration or
executing hooks. It returns only a validated 40-character lowercase object ID,
or unknown on malformed or unsupported metadata. A commit ID is not a clean-tree
or authenticity assertion. Existing receipts remain immutable; future runs use
the corrected helper and record their own source identity.

## Windows consolidation gate — blocked

PR #304 at exact head `bb4277aed685d485b57ffe7a718e70bab3e34467` failed the
focused native Windows winpairs publication gate in
[QA run 44263225792, job 134661411666](https://github.com/djshellshoxxx/patchtrace/actions/runs/44263225792/job/134661411666).
The retained log reports **15 failed, 61 passed and 3 skipped in 3.68 seconds**
across the three winpairs test modules. Publication operations report
`OSError (OS error 87)`. The early gate failed; the later full-suite and package
steps were skipped and provide no qualification result for this head.

The [failure receipt](pw01-retained-pages-20261118/windows-pr304-bb4277/receipt.json)
records the exact head, run/job identity, full-log checksum and excerpt ranges;
the [unaltered excerpt](pw01-retained-pages-20261118/windows-pr304-bb4277/failure-excerpt.log)
retains the command and complete short failure summary. The full source log is
85,864 bytes, SHA-256
`a3c06a20a70fc31af0ef6c63515289b4e22026afeef2229701df7fe1a7893a04`.
The log does not establish the failing native operation or root cause; cleanup
can mask a primary failure. No `RootDirectory` or `BOOLEAN` diagnosis is treated
as proven. The integration owner is repairing this blocker. **This exact head
remains merge-blocked** pending a reviewed repair and successful required gates.

## Metadata-only L3 acquisition readiness

A separate bounded review assessed the `CVE-2022-34718` / `tcpip.sys` candidate
using retained MSRC and Winbindex metadata, historical pins and the primary IBM
article. The [provenance review](pw01-retained-pages-20261118/l3-cve-2022-34718/provenance-review.md),
[frozen acquisition plan](pw01-retained-pages-20261118/l3-cve-2022-34718/download-plan.json)
and [selected raw records and source receipts](pw01-retained-pages-20261118/l3-cve-2022-34718/source-review.json)
are preserved byte-for-byte. The [offline derivation](pw01-retained-pages-20261118/l3-cve-2022-34718/offline-review.py)
and [successful repeat log](pw01-retained-pages-20261118/l3-cve-2022-34718/offline-review.log)
record reproducible plan construction with socket creation and subprocess
execution forbidden. Paths inside these original artifacts identify the
original review locations; the complete raw metadata captures remain separate
and unchanged.

The candidate is AMD64 `tcpip.sys` version `10.0.22000.918` from KB5016691
(August 25 preview) to `10.0.22000.978` from KB5017328 (September 13 security
update), with two expected 3,208,528-byte files. MSRC's prior security-update
supersedence is KB5016629, distinct from the chosen preview. IBM identifies
`Ipv6pReassembleDatagram` and `IppReceiveEsp`, but the retrieved prose does not
establish this exact byte pair. The [failed image receipt](pw01-retained-pages-20261118/l3-cve-2022-34718/ibm-image-receipt.json)
records that the embedded BinDiff image returned unavailable HTML; it is not
visual verification. The plan artifact's SHA-256 is
`210ce0bc4fc972bfccacc83e5ee1aea49d0c593c0beb253dc4feda33607110b7`;
this is not a `kb acquire --consent-plan` digest.

**No target acquisition authorization exists. Target acquisition remains paused.**
This review downloaded no target binaries, packages or PDBs, executed no target,
changed no `facts: unverified` status and produced no L3 score. Exact source-pair
identity, current target availability, static PE/PDB facts and independent
function validation remain open. The generic acquisition CLI refreshes metadata
and cannot consume this frozen plan unchanged; any next request must first have
a concrete, reviewed acquisition scope and explicit approval.

## Remaining gates and continuation

- Qualify the exact published continuation head on Linux and Windows full QA,
  Qt repeats, standalone packaging, native engines and package smoke checks.
- Complete production Microsoft CSV retrieval on an environment with working
  direct DNS/TLS, retaining exact plans and raw receipts. Current saved-source
  replay is offline compatibility evidence only.
- Complete Windows manual and accessibility acceptance for the new source-page
  controls. Automated offscreen Qt evidence does not replace that gate.
- Merge the reviewed consolidation first with an expected-head SHA guard and
  `[no release]`; only then reconcile demonstrably superseded PRs. Preserve all
  remote branches. Qualify and merge this continuation separately.
- Continue the distinct PW-02 local package-inventory slice and real L2/L3
  qualification. This CSV work does not establish binary identity, package
  membership or a vulnerability-function accuracy percentage.

The first source-backed native L2 pilot is now recorded separately: one ELF/GCC
pair through the production Rizin adapter returned five unchanged matches and
omitted the frozen expected function. Existing ranking returned no candidate;
the per-case result is MISS / FAIL. No result or oracle was rewritten and no
aggregate bound was calculated. See the [sealed pilot record](l2-native-pilot-20261118.md).

The frozen L1 results and their six remaining failures are unchanged by this
inventory extension; see the [CVE consolidation record](cve-consolidation-20261118.md).


### Reviewed Windows prerequisite repair

The owner subsequently published the independently reviewed native publication repair at PR304 head `6cc6b6b77564e12eaec2917877d94525a69c7102`, tree `45a8b6a6b7d90b397ee8790933ca76a1444297ae`. The code tree matches local reviewed `1c49199e` / published `540c7df`; the remaining commit adds QA evidence only. Focused tests: 101 passed, 2 actual-Windows skips; 15 separate adversarial controls passed. The [independent review](winpairs-windows-final-review-20261118/REVIEW.md) permits proceeding to hosted qualification and explicitly leaves native acceptance pending. Current-head QA run `44273464988` must pass before a guarded merge. This later candidate does not replace or erase the failed bb4277 measurement above.
