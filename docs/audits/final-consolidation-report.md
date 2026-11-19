# Consolidation report — active source-pinned checkpoint

Recorded 2026-11-19 UTC. This is the durable operation record for the execution
pass; unfinished gates are listed explicitly. It is not a release acceptance
statement. Later verified operations are appended rather than changing the
meaning of earlier source-pinned evidence.

## Current verified outcome

Foundation [#317](https://github.com/djshellshoxxx/patchtrace/pull/317) was merged
with an expected-head guard. Main is now
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`; its tree
`af464108043aaa42b527a473985350a4daadc0d2` exactly matches the tested #317 tree.
Both parents were verified: previous main `9c411ca3` and reviewed head `88b0b522`.
All eight source workflows completed successfully, with **33 successful checks**
and three intentional skips (`release`, `release-gate`, optional MSVC advisory).
No submitted review blocked the merge. The commit includes `[no release]`.
[Complete guarded-merge receipt](consolidation-20261119/foundation-merge.json).

A complete remote refresh observed **318 retained branches** and **52 open PRs**
at 08:39:01 UTC. GitHub closed the 12 other open PRs contained in the merged
foundation: #290, #291, #292, #293, #294, #295, #297, #301, #302, #304, #305,
and #306. This was one direct main merge, not 13 separate merge operations.
No branch deletion occurred. The original census below remains preserved.
The new main push checks are separate from the completed PR qualification.

## Authoritative baseline and coverage

| Item | Verified identity / count |
| --- | --- |
| Main at inventory | `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` |
| Foundation PR #317 | `88b0b52281dd314aa72f93819145a73135618bc4` |
| Broad follow-up PR #316 | `f2b6827fc6270b96fb241b0722f2878de5a17361` |
| All remote branches at frozen census | 317 including main; 316 topics; pages 100/100/100/17 followed by empty page |
| All PRs / open PRs | 307 / 64; all-state pages 100/100/100/7 |
| Current open-PR checks inspected | 1,257 check runs and 54 legacy statuses; complete review pages, no formal submitted reviews returned |
| Already-integrated topics | 129: 113 exact ancestors plus 16 with all patches equivalent and no unique merge commits |
| Heads contained in pending #317/#316 | 26; this is not integration into main |
| Remaining topic heads | 161 needing review or retention |
| Main merge simulations | 142 conflicting, 174 clean; clean is not qualification |
| Historical focal semantic reviews cross-referenced | 131 scoped reviews; not whole-branch merge proof |

The [complete branch inventory](branch-consolidation-inventory.md) has a row for
every frozen branch and links the detailed machine evidence. Worker activity
outside this pass is unknown. No remote branch was deleted or force-pushed.

## Completed repair and publication operations

### Broad-stack portability repair: PR #318

Published [#318](https://github.com/djshellshoxxx/patchtrace/pull/318) against the
#316 branch, preserving its original source. Remote branch:
`codex/patchtrace-stabilization-20261119`.

| Identity | SHA |
| --- | --- |
| Parent | `f2b6827fc6270b96fb241b0722f2878de5a17361` |
| Verified local repair commit | `d953ab57081277e6e78dc551656e8f8b92b98b63` |
| Published REST commit | `202bda41ea84784f2871289f36b9f5341c366a80` |
| Exact shared tree | `391dd4b80ec87a8a803d67610d1e7b86d560ef0e` |

The commits differ because publication used the repository REST Git-object
operations. Every blob, final tree and remote parent/tree was checked. Repairs
cover Windows creation identity, lazy corpus home lookup and portability of
owned-reader/SQLite/CRLF/symlink/native-C test fixtures. Existing assertions and
production containment boundaries were retained. Local combined result:
**312 passed, 8 skipped**, whole ordinary Ruff and whitespace checks passed.
Independent review covered 57 authored C controls and 9 creation stat-view
controls. These overlapping counts are not added together and are not native
Windows proof. Current strict scan and native dependency blockers remain open.

### Selective stable recovery

Local branch `codex/patchtrace-safe-consolidation-20261119` starts at the exact
#317 foundation. It recovers reviewed slices of #308–#315, profile draft repair,
corpus startup, current help and preserved original evidence, without importing
the whole #316 inventory/native/package stack. Source mapping and limitations
are in [feature status](feature-completion-status.md) and the individual QA
receipts. The shared publication helper is the narrow dependency needed by
advisory reads, not proof that #307 as a whole is integrated.

Independent integration review found the strings staging-source substitution
defect. Its no-force repair and inherited forced-replacement boundary must remain
distinct. The default-primary environment port also required a new native
sentinel/cache qualifier; a historical green engine run without that observation
was not accepted as sufficient.

## Validation actually observed

| Source / selection | Result and practical limit |
| --- | --- |
| #317 independent saved-scope/provenance selection | 91 passed; scoped correctness controls, not provider or accuracy acceptance |
| #317 Linux full QA, job `135388977649` | 22,955 passed, 50 skipped, 6 xfailed; 1,976.14 s; ordinary Ruff passed |
| #317 Windows full QA, job `135388977899` | 22,877 passed, 129 skipped, 5 xfailed; 3,526.35 s; Windows package, frozen smoke, ZIP and NSIS install/launch/uninstall steps passed |
| #317 repeated Qt | All five job instances passed: four Linux shards at 20 repeats and Windows at 5 repeats |
| #317 Linux package | Passed; downstream Linux smoke jobs were still incomplete at this checkpoint |
| #317 live adapters | Inspected current Ghidriff/raw cache, unified, rz-diff and BinDiff jobs passed for their defined fixtures; no broader L1/L2/L3 accuracy claim |
| Selective security ports | 608 passed, 2 native Windows skips; source-bound receipt retained |
| Raw/search affected selection | 1,060 passed, 1 unchanged host timing failure; isolated baseline #317 also failed the same cold budget |
| Root combined stable selection at `45d460ca` | 145 passed; 12 focused feature/control modules; ordinary Ruff and diff hygiene passed |
| Independent stable reviewer at `d436a7ec` | 77 focused checks passed before identifying the additional strings race |
| Native environment harness source `f6c0146f` | 66 authored harness/workflow controls passed; root and GUI reviewer each independently ran 21 controls. Real native host outcomes remain pending |
| Pilot/CVRF source `cd96aa91` | 2,009 affected tests passed, no skips/errors; ordinary Ruff and pilot schema check passed. Independent reviewer: 44 current-input/report/GUI checks passed |
| Root final combined selection at `96f2f103` | 201 passed in 65.91 s across 15 feature/boundary modules; includes pilot/raw/search/profile/strings/no-force/native-harness controls |
| Help source `7056c2d8` | 319 help/spec controls passed; CLI help checked |
| Interrupted local repeated Qt / profile review | Incomplete (-9 / exit 130), not PASS |

Python 3.12.14, PySide6 6.12.0, pydantic 2.13.5, protobuf 7.36.2,
pytest 9.2.0 and Ruff 0.17.5 were available in the isolated prepared interpreter.
Worktree commands use `PYTHONPATH=src` so the base editable installation cannot
silently redirect imports. Raw commands and source hashes remain in the individual
receipts. A root command initially named nonexistent workflow test files and ran
no tests; only the corrected subsequent command is qualification evidence.

## Earlier merge and cleanup checkpoint (superseded by outcome above)

No main merge is asserted by this checkpoint. #317 must finish both Linux smoke
jobs before a guarded merge. The stable combination needs its own exact-candidate
hosted checks; #318 remains a repair PR into a blocked broad stack. No release,
tag, deployment, remote deletion or protection bypass occurred.

The 129 already-integrated topic heads are cleanup **candidates**, subject to a
fresh equality/ancestry check and owner-directed cleanup. Heads contained only in
pending candidates and partially recovered mixed branches are not cleanup-safe.

## Remaining work and exact continuation

1. Refresh `main`, #317, #316 and #318 using GitHub REST. Read all current check,
   status and review pages, including downstream workflow jobs. Confirm source
   heads before reusing this report.
2. The strings no-force repair and bounded #314 recovery are implemented and
   independently reviewed; 201 combined controls passed. The added #308 forced
   cancellation cleanup regression is repaired by `14f0e2c9`, integrated as
   `6edcb34a`, with six independent controls passing. Preserve the inherited
   forced publication/OSError-cleanup defects and broader #307/#316 blockers.
   Finish the running full local suite and exact-candidate hosted gates.
3. Publish the stable reviewed tree with its exact source/tree mapping and all
   five audit records. Require the new Linux/Windows native H7 child and cache
   receipts as well as all existing gates.
4. #317 is merged as `fdc2696c23bdbfe7668348f25e3b336ce33039f7` with the
   expected head guard and `[no release]`; its tree and parents are verified.
   Complete the refreshed per-branch comparison and inspect new main push
   checks. The 12 contained PRs closed automatically; retain their branches.
5. Merge the stable combination only on fresh exact-source green gates and
   independent review. Use a merge commit/head guard; do not force-push or
   delete source branches. Revalidate main and append operation/results here.
6. Continue bounded repairs to #318/native provisioning and the separately
   tracked inventory/publication work where evidence permits. Keep strict scan,
   unavailable native tools, macOS, clean-machine/manual Windows and accuracy
   gates explicit. Do not erase historical failed receipts.

The complete defect list is [outstanding bugs](outstanding-bugs.md); gate and
dependency details are [merge blockers](merge-blockers.md). Full consolidation
and release acceptance remain incomplete until those concrete gates are resolved.

## Independent combination review update

The native harness and current-evidence/CVRF source were independently reviewed
without a new blocker. H7 checks actual child absence before entering the real
engine, forwards the same environment object and engine arguments, and requires
a fresh run followed by an identical raw-cache hit. The pilot stage correction
is specifically a failed-creation cleanup fix, not a general post-creation
pathname ownership guarantee.

Supplementary security scanning preserved 66 runtime S findings on #317 and 68
on `96f2f103`, plus a separate broader 147-finding `src tools` scan. These are
scanner observations with different scopes, not vulnerability counts or a
passing security gate. The strict 80-count runtime gate on #316/#318 remains red.

## Final local assembly before hosted publication

Runtime/test source through local `4cdee5a2` includes the scoped no-force
repair and the independent force-cancellation correction. The latter restores
the main/#317 exception boundary without removing Linux forced replacement.
Six new controls failed before the fix, 53 affected export/CLI/publication
controls passed afterward, and a separate reviewer ran the six controls with
all passing. The inherited force success and OSError cleanup substitution
races remain open. See [force cancellation receipt](../qa/strings-force-cancellation-20261119/README.md).

The full local `QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q`
run started on that source with JUnit and raw output retained; it is pending
until a terminal result is appended. No pending run is counted as passed.
An independent final reviewer checked all 317 inventory rows and verified all
13 archived member hashes, source mappings and the stated review totals.

## Broad-stack dependency repair update

PR #318 is now `2e301a74649e59e27b19a83bc283d646109ccd09`, parent
`202bda41ea84784f2871289f36b9f5341c366a80`, exact tree
`34ebf67473a48d19ab30472b3979afe8c17e11f3`. This equals reviewed local
`d2a77717a4b2953e6fa64be7a7fa1308c8427141`. It provisions verified Windows
LLVM/Rizin dependencies and retains the selected compiler resources; 116
focused controls passed. Actual new-head native/Windows outcomes are pending,
and strict security qualification remains blocked.

## Supplementary scan boundary review

Independent review of the two new runtime scan sites at `96f2f103` found
no input-derived SQL token at the fixed-column metadata query (S608), and
verified that the explicit XML parser target rejects recognized DTDs (S314).
The relevant boundary selection passed 195 controls. This does not establish
a hard in-parse time/memory bound or waive the 68-finding scan. Exact raw scans
and root/independent results are in the [final review archive](consolidation-20261119/final-review-evidence.zip)
and [manifest](consolidation-20261119/final-review-manifest.json).

## Complete inventory refresh after the merge

All 318 remote heads were re-compared against `fdc2696c`. There are now
**144 already-integrated topic heads** (128 by ancestry, 16 by patch equivalence),
**11 dependency-blocked topics**, and **162 topics requiring review/retention**.
Fifteen topic heads changed from pending to integrated. The newly created #318
branch accounts for the extra retained topic. All 317 topic merge simulations
completed: 164 conflict, 153 do not, no execution errors. The frozen initial
report and its original hashes remain unchanged in their archive.
[Refreshed report and exact contained-PR status table](consolidation-20261119/post-foundation-inventory.md).

## Local interpreter boundary correction

The running full local suite uses the prepared shared interpreter and
`PYTHONPATH=src`. Normal imports resolve this worktree. Review identified seven
isolated (`-I`) module-import checks that instead used the shared interpreter's
base-checkout editable installation. A dedicated interpreter now resolves the
stable source in both normal and isolated mode, with unchanged prepared
dependencies. All seven exact isolated cases were rerun there: **7 passed**,
no skips/errors or source corrections. Source hashes and both positive and
shared-environment counterproofs are in the post-foundation evidence archive.
The full run and corrective seven-case run remain separately reported; neither
is represented as one pristine independently installed-package test run. Hosted
CI installs the actual candidate and remains the exact-source platform gate.

## Candidate assembly and current blockers at publication

The publishable candidate is isolated in branch
`consolidation/patchtrace-reviewed-20261119`, based on the exact foundation
tree now merged into main. It additionally carries the checked native symbol
setup runner (`410b9c3d`) and verified Windows corpus provisioning/resource
repair (`06428a98`, `1d04f54b`). Production `src/` is unchanged from the
reviewed stable product source `4cdee5a2`; this separate worktree kept the full
local run's source fixed while CI repairs were assembled.

The setup audit confirmed a real CI false-success path: seed or symbol-enabled
Ghidriff failure was overwritten by unconditional `LASTEXITCODE=0`. The new
CI-only runner requires both child exits to succeed and preserves the later
intentional negative cached-PDB reproduction. Author 97 controls and independent
7 controls passed; root combined new-setup/H7/Windows-dependency selection:
**33 passed in 3.04 s**, ordinary Ruff and whitespace clean. Actual hosted
Windows setup and both H7 native receipts remain required.

The local full suite stopped making progress near 5%, after the output-limit
case and while entering or leaving the authored BinDiff timeout case. It was
interrupted after more than 16 minutes without progress and returned **137**;
no completed JUnit/full-suite verdict exists. The timeout test specifies a 3 s
child limit and a less-than-60 s elapsed assertion. Its heartbeat stopped near
that 3 s deadline, so a product supervision defect is not inferred from the
progress stall alone. Bounded isolated reproduction is in progress. This is
**ABORTED**, not a full pass, and is explicitly retained as a candidate
qualification blocker alongside fresh hosted gates.

The [candidate receipt archive](consolidation-20261119/candidate-workflow-and-incomplete-full-evidence.zip)
and [manifest](consolidation-20261119/candidate-qualification-manifest.json)
retain the raw incomplete output and completed 33-control result.

## Core finding revalidation and bounded stall follow-up

All five original #120 findings have concrete repairs already present in the
new main; their relevant source blobs match the independently reviewed stable
source. #121 backup/prune admission, per-query iteration deadline and artifact
content-verification repairs are also present. The focused core selection
passed **135 tests**. The environment-default and checked native setup changes
remain candidate-only until qualified and merged; broader resource and release
gates are still open.

The two cases around the local full-run stall passed once, unchanged, using the
dedicated interpreter: **2 passed in 6.23 s** (8.76 s wall). Their 60 s outer
bound did not fire and no process kill was required. The full run remains
ABORTED; this isolated result does not assign a host or product cause. Exact
source comparisons, core controls and stalled-progress/heartbeat observations
are preserved in the [core and stall archive](consolidation-20261119/core-review-and-stall-evidence.zip)
and [manifest](consolidation-20261119/core-review-and-stall-manifest.json).
