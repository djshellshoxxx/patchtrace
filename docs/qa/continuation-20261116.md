# PatchTrace continuation — 2026-11-16

## Baseline and scope

Starting main: `7401078490eb7a447f5ec7274339cb08b051f395`.
Integration branch: `codex/release-integration-20261116`.
Six specialists used isolated worktrees; separate reviewers inspected security,
secondary evidence, research and KB work. The lead reviewed CLI implementation.
The assignment is not release-complete. This checkpoint consolidates the current
production branches and fixes defects found during integration and review.

The checkout contained 297 remote-tracking refs. Ancestry and feature review
selected main rather than the older large integration branches. Historical
branches remain intact. This is not an exhaustive audit of all historical code.

## Branch disposition

| Source | Disposition | Evidence |
|---|---|---|
| #259 / #287 unified soundness | Already on main; no duplicate port | Four regression files and unified source match main |
| #286 live harness | Already on main | Workflow/harness content comparison |
| #296 Windows path test | Already on main | Starting main commit |
| #290 security | Integrated with new TB-09/TB-10 fixes | Security report and independent regressions |
| #291 KB/CVE | Integrated after K3 and report review repairs | Default held-project loader regression and bounded snapshots |
| #292 CLI | Integrated project/compare/profile/doctor | Lifecycle, cancellation, help and registry tests |
| #293 rz-diff | Integrated refusal; legacy quarantine and source-identity repair integrated | Native stdout fixture hashes, parser/cache and source identity tests |
| #294 L1 runner | Integrated with six correctness/integrity repairs | Synthetic runner and independent review; no real accuracy claim |
| #295 test reliability | Integrated | Serial and xdist pathguard tests, explicit PyYAML dependency |
| #289 large integration | Preserved, not merged wholesale | Diverged 331-file delta; selective recovery from focused branches |
| #282 research prototypes | Preserved as research | Not product-wired or qualified |
| Analyst accessibility branch | Not integrated in this checkpoint | Unique work remains for feature-level review |

## Feature queue

| ID | Feature | State | Remaining work / acceptance |
|---|---|---|---|
| CLI-CORE | Project, compare, profile, doctor | Implemented locally | Final combined and hosted platform checks |
| CLI-RUNTIME | Inspect/install offline runtime | Implemented locally | Native/frozen Windows and final combined checks |
| CLI-REST | Corrections and review commands | PARTIAL/MISSING | Recover unfinished spec/code, implement and independently test |
| SEC | Hostile input, ZIP, PE, process boundaries | Implemented locally | Final combined/platform checks; no global vulnerability-free claim |
| RZ | Ambiguous ownership and legacy evidence | Implemented locally | Final combined and native gates |
| KB-K3 | Held-project desktop loader | Implemented locally | Native Windows and measured large-project latency |
| KB-REPORT | Lineage, aliases, advisory reports | Implemented locally | Final combined suite |
| L1 | Frozen offline qualification runner | Mechanics implemented | Real independently sourced inputs and defensible study design |
| NATIVE | Ghidriff/BinDiff/rz-diff qualification | BLOCKED | Pinned runtimes, original pair, Windows host |
| RELEASE | Windows standalone and clean-machine acceptance | BLOCKED | Exact-head hosted package and manual acceptance |

## Findings fixed during this continuation

| ID | Finding | Resolution / regression |
|---|---|---|
| TB-09 | Signal process group after leader reaped | Observe without reaping; reject unsupported POSIX before spawn; ownership/error controls |
| TB-10 | Forged ZIP entry count bypasses allocation preflight | Stream real directory headers with count and 128 MiB directory cap |
| RZ-CACHE | Pre-policy cache bypasses singleton refusal | Versioned parser cache identity |
| RZ-LEGACY | Old stored ambiguous results contribute current evidence | Non-destructive quarantine, refusal provenance identity and newer-safe supersession; independent tests passed |
| L1-ABSENCE | Missing CVE passes a no-KB case | Require source evidence before no-KB pass |
| L1-REVISION | Failed later import ignored | Cases blocked on failed relevant imports |
| L1-BOUND | Product labels treated as independent trials | Suppress unsupported inferential bound |
| L1-DEPTH | Manifest recursion escapes typed errors | Bounded failure path |
| L1-BYTES | Hash and scored bytes can differ | Private bounded snapshots |
| L1-WRITE | Partial final receipt on failure | Fsynced staging and exclusive atomic publication |
| KB-LOCK | Worker reopens held desktop project | Owner-thread immutable snapshot; no worker service/store handle |
| KB-LIMIT | Snapshot loads unbounded payloads on GUI thread | Preflight row/byte and project traversal bounds; deferred decode |
| KB-RACE | Old filter response replaces new report | Cancel both task channels before reload |
| KB-REPORT | Missing pair/failed producer/unknown KEV overstated | Explicit uncertainty and preserved baseline report fields |
| CLI-IMPORT | Interrupted preparation leaves staged raw output | Attempt-owned rollback, exclusive publication and persisted-commit retention |

Reviewers reproduced and returned findings to implementers, then independently
retested repairs. Review approval applies to the inspected changes only, not
external professional certification or the entire application.

## Evidence

- Baseline main hosted QA/Windows workflow `43785230157`: success for starting SHA.
- Local combined CLI/secondary test selection: 311 passed before later integration.
- Test reliability: 7 passed serial and 7 passed with two xdist workers.
- KB/security merge conflict retained both regression groups: 209 passed.
- Local dependency consistency, protobuf 7.36.2/upb, Ruff and diff checks passed.
- Schema regeneration produced no drift at the checked integration state.
- First whole-suite attempt stopped at collection: a timestamp in a gzip parameter changed test IDs across workers. Fixed with `mtime=0`; 33 tests passed under four workers. No whole-suite pass is inferred.
- The next whole-suite attempt lost one worker, recorded failures, then stopped progressing at 99%; interrupted without a pass claim. One confirmed failure was the CLI seam budget, repaired by extracting secondary orchestration rather than weakening its guard.
- A full diagnostic run with per-test names and 120-second faulthandler traces follows the second integration batch. Latest exact-head results are maintained in [PR #297](https://github.com/djshellshoxxx/patchtrace/pull/297).
- Published checkpoint `f403f81b58a0cdc2d3869810294681527f8268a2` (tree `24c3afe2c2abf5231c7743e169e8e40a05097ff7`) passed hosted rz-diff on Windows and Linux (`43837495435`), BinDiff acceptance (`43837495493`), and dependency-wheel checks. These are workflow fixture qualifications, not the original Windows pair or a release acceptance claim.

Detailed security evidence: [security integration](security-integration-20261116.md).
Detailed installed-tool and native blockers: [native qualification](native-qualification-20261116.md).

## Second bounded batch

- Diaphora: reject views/triggers/virtual tables before result processing; permit only approved table/column reads, retaining mixed-case compatibility. Independent 70-test selection plus compatibility regression passed.
- BinDiff: cap function/schema/algorithm counts, row bytes and aggregate names before unbounded model allocation; preserve exact-limit acceptance; classify post-exit filesystem errors; reject missing CLI input before project mutation. Lead diff review and bounded/golden regression selections passed.
- Runtime CLI: inspect Windows/Linux archives without execution; install only on supported host with explicit confirmation and exact SHA. Track only newly owned directories for cleanup and preserve published installations on interruption.
- Linux bundles: producer retains safe executable bits; installer restores only safe modes and refuses missing launcher metadata. Independent runtime/offline selection: 128 passed.
- Secondary CLI facade: extract existing orchestration to `secondary/cli_import.py`; preserve the CLI seam guard and no-Qt/import-order behavior (38 focused tests passed).

## Continuation

Before changing or merging, fetch current refs, inspect the integration PR and
exact-head CI. Preserve all original source branches. Merge only when every
required test job is green and no blocking finding remains. Do not promote
synthetic, offscreen, historical or mocked evidence to current native acceptance.
The old production task cards and unfinished diffs remain on
`claude/sleepy-fermi-y3z4yj` at `160a60e838742b21f70effedb8e7bb48886d9266`.
