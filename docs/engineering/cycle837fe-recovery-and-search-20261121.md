# Interruption-safe project storage and Search header help

## Source and ownership

This parallel candidate starts at PR #348, `6b6fcd3597a604212032ffc453477aeb6edc69ff`.
The final reviewed application/test checkpoint is **`b880c317add4de3ac22c87cd842abb0e7ccc615d`**,
tree **`74a4ee3714ea492e84c2a2a3aaf41fa54849e404`**, on
`codex/patchtrace-recovery-search-20261121-837fe`. Publication records must identify
their own complete tree separately from this tested checkpoint.

The separate 95FE-C3 coordinator retains recorded stack/main, CODEX-6, CODEX-14
and Pages ownership. This candidate leaves that worktree and its refs intact.
The initial PR base is `codex/patchtrace-integration-20261121-2bad` at PR #348's
exact head. Reconcile onto the owning coordinator's latest integration after
handoff; preserve newer ledger fields and refresh the target before merging.

## Completed behavior

### Committed state survives a post-commit interruption

`ProjectStore.save()` can commit SQLite before deferred history maintenance
raises. Previously, `ProjectService._commit()` retained its older in-memory
project. A subsequent annotation could omit an already saved note from the
current snapshot. Authored temporary projects and real SQLite confirmed this;
earlier history/backups could retain the note, so loss of every copy is not claimed.

Save and backup now share a nonrecovering read of the actual committed snapshot
when an operation raises, then propagate the original exception. They never
install an uncommitted candidate or claim rollback after a completed commit.
Reconciliation does not write another snapshot or recover running jobs. If its
read fails, snapshot edits and backup refuse further work until reopening.

Fresh review found and closed two paths in the initial repair:

- **SVC-R1:** backup's recovery read bypassed the uncertainty guard and could
  write recovered state or prune history. The shared guard now precedes that
  read and all staging work.
- **SVC-R2:** a healthy backup could commit running-to-failed recovery and then
  be interrupted, leaving stale memory. Shared reconciliation now covers the
  complete backup operation, so a later edit preserves the committed failed state.

Healthy recovery and reopening remain supported. Export and prepared-import
disposal already read with `recover_interrupted=False`. Persisted schemas are unchanged.

### Backup cleanup preserves the original outcome

`ProjectStore.backup()` cleans staging only after construction/publication
failure. A cleanup `OSError` preserves the primary exception and adds a fixed,
path-free diagnostic that incomplete staging may remain. CLI cancellation
retains exit 5 and `status: cancelled`; its existing cancellation envelope is
unchanged, so the attached exception note is not a new visible CLI warning.

Successful publication never inspects or removes the consumed staging name.
Independently recreated data at that path is preserved. Failed publication
preserves an independently occupied final destination and the source project.
The repair does not claim to suppress every non-filesystem cleanup exception
or comprehensively re-audit the unchanged publication helper.

### Six Search headers explain their existing fields

Side, Kind, Match, Where, Change and Why now use distinct registered header
help. The text distinguishes counterpart sides from actual matches, describes
the first evidence item/address fallback, and preserves uncertainty. Review
corrected an overpromise about showing every recorded reason in the details pane.

The real-host audit activates Search before inspecting header roles. Removing
only the Why mapping makes that audit fail for exactly its ID. No exemption
was added. Labels, cells, row identity, sorting, queries, clipboard and navigation
remain unchanged. `ToolTipRole` supplies help; native screen-reader acceptance
and `WhatsThisRole` support are not established here.

## Source-specific verification

Selections overlap and must not be summed.

| Source | Actual outcome |
| --- | --- |
| Final combined `b880c317` | **450 passed**, no failures/skips, 37.43 s; whole-tree Ruff, dependencies, whitespace and isolated source binding passed |
| Earlier combined `276fa894` | 444 passed before the two additional service paths were repaired |
| Final service `1ce478b3` | Author 262 maintained cases passed; independent reviewer 155 cases passed |
| Final combined `b880c317`, service reviewer | 34 independent/service/backup cases passed |
| Backup `4d3a60f8` | Author and reviewer independently passed 169 maintained cases; reviewer also passed five independent controls |
| Combined `276fa894`, backup reviewer | Five independent controls passed; reviewed implementation/CLI/test/spec blobs matched |
| Search `b51b1761` | 140 affected cases passed; reviewer separately passed 140 maintained and three independent controls |
| Search wording correction `0069d0d2` | 68 affected cases passed; independent semantic replay closed S-H1 |

Retained failures include the original audit's four failed/one passed controls,
service author's six failed/three passed baseline, backup author's eight
failed/one passed baseline, independent backup four failed/one passed baseline,
Search's four initial failures and exact-registry inventory failure, and the
independent SVC-R1/R2 failures. Assertions, native gates and exemptions were not weakened.

### The local full aggregate is unsuccessful

The full offscreen run on earlier Search source **`b51b1761`** ended with SIGKILL
(`-9`, wrapper exit 137) after **1,417.602 seconds**, at approximately 83%.
It produced no terminal summary/JUnit and logged one failure. Source remained
clean. It predates the storage repairs and final wording correction.

Fresh collection identified the failure at case 11,212 of 24,106:
`tests/test_network_consent_guard.py::test_a_local_unix_socket_is_not_network`.
AF_UNIX construction is denied before NetworkGuard is entered. Plain Python
`-I -S` reproduces the denial without PatchTrace/site imports or bind/connect.
The isolated case also fails identically on final `b880c317`. The next collected
case at termination, `test_ui_bundle_setup.py::test_verify_full_success_and_hash_failure`,
passes alone on both sources; this does not establish a cause for the kill.

The supervisor used `Popen`/`wait()` without a timeout or kill call; original
CPU/address-space/data limits were unlimited. Cgroup memory counters and kernel
logs are unavailable. No OOM, timeout, Qt or host-policy cause is established,
and the earlier socket failure is not causally linked to SIGKILL. No limits,
skips or assertions changed. Final-head hosted full/Windows/native gates remain required.

## Prior PR qualification refreshed

PRs #345–#348 have successful QA/Windows/package and native runs on their exact
published heads. PR #345's successful attempt 2 preserves the original NSIS
HTTP 503 failure. Release jobs were intentionally skipped.

PR #348 Linux full QA: **24,043 passed, 53 skipped, 6 xfailed**. Windows:
**23,916 passed, 181 skipped, 5 xfailed**. Ruff, five Qt jobs, five native jobs,
Windows package/installer and Linux package/smoke checks passed. These results
belong to PR #348, not this candidate.

- [PR #348 QA/Windows](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44858504288)
- [PR #348 native](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44858504326)
- [Exact-head receipts](evidence/cycle837fe-20261121/baseline-hosted-results.json)

PR #346's unique code is already selectively retained through #347/#348.
Do not merge the older sibling wholesale or duplicate its shared GUI recovery.

## Branch accounting and remaining research

The refreshed census contains **364 live heads, 338 PR records and 59 tags**.
Every live head has complete technical metadata: exact objects, merge bases,
divergence, unique nonmerge commits, changed paths and PR joins. 337 PRs join
a live branch name; 303 joins match the exact captured SHA. Merged disposable
PR #8's former branch/head is absent locally; its metadata is retained.

Technical coverage does not prove semantic equivalence or replace the existing
unmatched/patch-equivalent backlog. Three additional behavior scopes are
SUPERSEDED while their whole branches remain partially reviewed: PR #119
persistence feedback, PR #148 protected report export, and `feat/enrichment-cache`.
The implementations already exist, so no port is needed. See the exact
[semantic receipt](evidence/cycle837fe-20261121/historical-semantic-dispositions.json).

CODEX-1 research resolved **11 Action references used 176 times in 21 workflows**
to verified upstream commits/version tags, peeling annotated tags. Pins are
prepared, not applied; workflow ownership remains with 95FE-C3. The Pages
upload composite retains a nested mutable Action reference, and Codex's npm
downloads are separate. This does not close CODEX-5 or a fully immutable dependency chain.

## Evidence and integration gate

The [manifest](evidence/cycle837fe-20261121/manifest.json) hashes retained failures,
author/reviewer results, complete reference snapshots, lossless compact inventory,
research and a verified source-history bundle. The bundle restores the owned
implementation history with PR #348 as prerequisite. No counts transfer between trees.

Use the existing [task ledger](task-ledger.json) and
[scoped handoff](../engineering-handoffs/cycle837fe-20261121.md). Qualify the exact
published head, refresh ownership/target, reconcile the active integration, and
merge only with a fresh expected-head REST guard and no blocker. CODEX-1/5,
active CODEX-6/14 acceptance, historical semantics, full raw input/index retention,
Windows manual/trust/accessibility and separate L1/L2/L3 release gates remain open.
PatchTrace is not declared complete or release-ready by this candidate.
