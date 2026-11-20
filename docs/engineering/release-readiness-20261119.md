# Release readiness after the multi-generation integration

## Current generation 30–31 checkpoint

The [current handoff](../engineering-handoffs/generation-30-31-20261120.md) records independently reviewed receipt identity, Search cancellation and stored Strings source-admission repairs. These are bounded candidate improvements, not release qualification. Combined/current-head hosted gates and the existing forced-export, native Qt, raw-input membership, Windows/trust/manual and accuracy blockers remain open. The [official Qt refresh](qt-disposition-refresh-20261120.md) found no verified 6.12.1-family wheel update. Earlier results below remain historical and source-specific.


**Blocked: reviewable engineering candidate only.**

The [task ledger](task-ledger.json) records exact source and verification state.
The [feature inventory](feature-status-20261119.json) and
[handoff](../engineering-handoffs/generation-9-through-14-20261120.md) describe
implemented paths and unresolved scope. This assessment does not authorize a release.

| Area | Disposition | Required evidence or correction |
|---|---|---|
| Recovered workflows and portable repairs | Independently reviewed named scopes | Combined tests and current hosted/native checks, distinct from focused receipts. |
| Combined suite | Partial hosted qualification | Original local unsplit run ended SIGKILL. Initial PR324 source later passed hosted Linux full QA: 23,699 passed/51 skipped/six xfailed. Windows/remaining Qt were still running at refresh. Later PR325 source has 1,737 affected passes/one native skip and needs its own full hosted gates. |
| Linux forced replacement | Confirmed residual defect | Final named-source substitution can expose foreign bytes before refusal; no rollback guarantee exists. |
| Native Qt | Remediation/disposition open | No 6.12.1 binding wheels at official refresh; seven earlier assessed ranges plus QXmlSimpleReader component advisory need artifact-specific assessment. Version matching is not reachability proof. |
| Windows desktop/package/trust | Source-pinned acceptance required | Held-handle replacement, catalog/WinVerifyTrust, frozen/portable/installer, clean-machine and manual accessibility evidence. |
| Adapter compatibility | Per-tool qualification | Earlier rz-diff receipts and actual PR324 Windows Ghidriff fixture acceptance are retained with source/artifact identity. Later follow-up requires its own hosted qualification; authored fixtures do not prove general accuracy. |
| Binary-analysis accuracy | Separate L1/L2/L3 gates open | Frozen L1 has six failures; L2/L3 require verified labels and independent projects. Never pool layers or score unverified facts. |
| Acquisition provenance | Reviewed bounded persistence implemented | Original proposal/window, normalized delivery rows, consent and verified receipts persist and recover. Full raw entry/index retention, resolver reconstruction, live providers and native acceptance remain open. |
| Local native fixture/toolchain acceptance | Local environment blocked; initial hosted cases passed | Thirty-two locally skipped fixture cases and AF_UNIX all passed on the initial PR324 Linux runner. This machine still lacks LLVM tools/the managed installer and denies AF_UNIX construction. No policies or acceptance assertions changed; later source requires separate qualification. |
| Historical consolidation | Unfinished | 154 heads need semantic review at the frozen census; retain sources until all unique work is accounted for. |

No main merge, tag, release or deployment occurred in these slices. Draft PR324
and an actual enabled hourly successor are recorded in the ledger. The reviewed
acquisition/QA follow-up is kept separate so PR324's original-source CI can finish.
Draft publication and scheduled continuation do not constitute release qualification.

## Generation-15 source admission and source-pinned CI update (2026-11-20 UTC)

The isolated draft successor `codex/patchtrace-index-source-identity-20261120-audit1`
adds a fail-closed admission check for matching Winbindex plain/gzip records
with the same newest data date and for aliased index paths. Its original
synthetic failures are reproduced, and eight isolated method controls pass,
but full checked-out-source pytest/Ruff, hosted CI and independent review are
**not yet accepted**. It is not raw index retention or resolver membership
reconstruction; these and the other release blockers above remain open.

For PR #324 source `3862cb5d`, Linux and Windows full QA, four Linux
Qt shards, the Windows Qt shard, ten native Ghidriff scenario jobs and
Linux package had all reported success in the last read after 01:19 UTC;
two downstream Linux smoke jobs were still queued. These facts qualify only
that original head at those named gates. PR #325 head `4dfc0e49` had
most full QA/Qt jobs queued and native jobs underway, with one native
scenario successful. The later generation-15 code has no corresponding
hosted qualification at this checkpoint. No main merge or release is eligible.

## Generation-16 offline index read-bound qualification (2026-11-20 UTC)

The isolated successor after draft PR326 uses a bounded held-stream read
(`MAX_COMPRESSED + 1` sentinel) and clears stale `skipped_rows` when a
previously partially parsed Winbindex record is removed. Original stale-stat
and stale-gap failures were reproduced in a standard-library mirror; the
repaired mirror reports the expected limit and zero missing-source gaps.
The actual repository regression tests and source-pinned offscreen pytest,
whole-tree Ruff, independent review and hosted QA/Qt/native checks are
**pending**. This is not raw index retention or a closure of source-name
replacement races. No release, main merge or deployment is eligible.
See [generation 16](../engineering-handoffs/generation-16-20261120.md).

## Generation-17 held-source admission candidate (2026-11-20 UTC)

Stacked in an isolated branch after draft PR327. A matching newer index pathname
that is a directory or other non-regular object is now refused instead of
allowing an older record to become the selected source. An `O_NOFOLLOW` capable
host refuses a final-component symlink introduced after the scan; the opened
file descriptor must be regular and is opened nonblocking where supported.
Two baseline behaviors were reproduced and four amended controls passed in
**isolated standard-library algorithm mirrors**, not repository pytest, Ruff,
Windows/native, or empirical-accuracy acceptance. Full CI and independent
review of this newer exact source are still pending. This does not fix ordinary
file substitution, ancestor-path attacks, the distinct Linux force-publish
race, or missing raw Winbindex index/resolver membership persistence. Release
readiness and main-merge eligibility remain **false**.


## Generation-18 selected-source directory replacement classification

Successor adversarial review reproduced a source-error classification gap in
the generation-17 held reader: an admitted regular file replaced by a directory
can raise POSIX `EISDIR` before descriptor `fstat`, yielding `PT-KBC-INPUT`
instead of the nonregular-object contract `PT-KBC-SOURCE`. Contract-first
correction and two repository regression tests are isolated in the
generation-18 candidate. A separate standard-library mirror has five passes;
**actual repository pytest, Ruff, new exact-source hosted QA/Qt/native/package
and independent worker signoff remain pending**. There is no Windows native
directory-classification claim and no closure of ordinary-file substitution,
raw-index retention, resolver input membership or the Linux forced-export
race. No release or main merge is eligible.


## Generation-19 Winbindex body-loss accounting and inherited CI failure (2026-11-20 UTC)

Separate isolated draft candidate `codex/patchtrace-winbindex-body-gap-20261120-g19` makes unreadable version/KB body loss visible in resolver coverage and plain-text Winbindex import; the JSON receipt now contains a distinct `skipped_bodies` field and two fixture expectations increase from 2 to 3 rather than weakening a gate. Four real repository tests were added but have not run locally; only a separate stdlib mirror reproduced the original counter omission and verified the amended formula. Independent source review and all exact-source hosted QA/Qt/native/package checks are pending.

Fresh PR328 source-specific Windows QA proved 23,636 pytest passes, 162 skips, five xfails, then failed Ruff I001 on inherited `test_kbc_winbindex_held_admission_20261120.py`; the successor fixes only the import-block spacing. Another PR328 native Ghidra leg failed during a download transport reset, before native testing. Both original failures remain recorded in the [generation-19 review](winbindex-body-gap-review-20261120.md). No historical CI result qualifies this candidate. Raw entry/index persistence, resolver membership, Linux forced-export race, native Qt, Windows trust/manual, accuracy layers and historical semantic review remain blocking. **Not release ready or merge eligible.**

## Generation-20 whole-container coverage accounting (2026-11-20 UTC)

The isolated successor of draft PR330 closes a narrower, independently observed
loss-reporting path: a top-level Winbindex entry with accepted file identity but
missing or nonobject `windowsVersions` was previously emitted as zero rows with
**zero** parser loss units. The contract-first candidate now counts one source
container gap, preserving explicitly empty object semantics and the separate
candidate parser. Synthetic real-repository regression tests are committed but
not yet executed in a checked-out repository; eight local standard-library
**algorithm-mirror** controls passed only. Later source-specific hosted QA,
Ruff, Qt, native/package qualification and external independent review remain
pending. No native accuracy, authenticity, or release-readiness claim results.

This does **not** capture full raw Winbindex index contents, reconstruct exact
resolver membership, fix the Linux forced-export source replacement interval,
dispose of Qt advisories, complete Windows trust/manual testing, or satisfy
layer-specific L1/L2/L3 accuracy gates. `release_ready` and main merge
eligibility remain false. See [generation 20](../engineering-handoffs/generation-20-20261120.md).

## Generation-21 offline index gap isolation and confirmed PR330 hosted failures

Generation-21's isolated branch `codex/patchtrace-index-gap-isolation-20261120-g21` is stacked on PR331 at
`3359c846f8608522b90225dbcdab2c66a8754afe`. The spec-first
implementation binds parser and downstream rejection counts to the same record
read, removing re-entrant mutable state. Three repository regressions are authored;
no source-pinned repository pytest, Ruff, Qt, native or package gate has been
reported against this new code. A standalone algorithm reproduction gives the
original mismatched count 0 and intended count 1; it is **not production-source
verification**. External independent reviewer signoff is pending.

Real PR330 hosted Linux and Windows full QA **failed**, four tests each. Linux
QA job [136104316334](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44681066815/job/136104316334)
reported 23,748 passed/51 skipped/6 xfailed and four failed. Windows job
[136104316166](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44681066815/job/136104316166)
reported 23,636 passed/164 skipped/5 xfailed and four failed. These assertions
compared old top-level `skipped` counts with a new total including an observed
unreadable body: refresh 2 vs 3 (both plain/gzip), existing synthetic pair 3 vs 4,
and adapter fixture 2 vs 3. The exact original failures remain retained in
CI; this isolated successor updates those *assertions* to the previously amended
SPEC-31-D semantics, not application thresholds or parser logic. This does **not**
make PR330 green or the generation21 source qualified. PR331's separate QA remains
in progress at the last source-specific inspection. All original release blockers
remain, particularly missing raw index/resolver membership, Linux forced export,
Qt disposition, Windows trust and L1/L2/L3 evidence. No main merge or release.

## Generation-22 malformed BASE metadata loss (2026-11-20 UTC)

An isolated child of draft PR332 adds a specification-first parser correction: missing or nonobject `BASE.windowsVersionInfo` no longer fabricates an undated baseline and is counted as one unreadable body. Nine synthetic repository pytest cases are authored and an eight-case standalone algorithm mirror passed. The actual repository tests, Ruff, Linux/Windows QA, Qt/native/package, independent review and complete raw index/resolver membership remain **pending**. Parent PR331's four real full-QA fixture failures per host are preserved; PR332's correction has not yet been accepted on this new child. Release readiness and main merge eligibility remain **false**. See [generation 22](../engineering-handoffs/generation-22-20261120.md).

## Generation-23 offline Winbindex import-source admission (2026-11-20 UTC)

A new isolated draft child of PR333 addresses the importer-specific pre-read
FIFO blocking path. A bounded standard-library child reproduced blocking in
the original `open(source, 'rb')` sequence; nonblocking open and held-descriptor
`fstat` distinguished a FIFO without reading it. SPEC-31-D was amended before
three regression tests and a narrow `save_winbindex_record` change. This is
**not** repository-source pytest or hosted QA. There is no complete checkout
in this runtime (github.com DNS resolution failed), and Ruff is not installed.
The repository regression cases, full offscreen pytest/Ruff, exact-source Linux
and Windows QA, Qt, native Ghidriff, Windows packaging and independent adversarial
review have not been accepted. No CI results from PR332/333 qualify this child.
No source provenance or accuracy gain is asserted. Release readiness, main merge
eligibility, full raw index/resolver membership, Linux force-export, official Qt
advisory disposition, Windows trust/manual and L1/L2/L3 gates remain open.
See [generation 23](../engineering-handoffs/generation-23-20261120.md).

## Generation-24 held local advisory-file admission (2026-11-20 UTC)

Separate isolated draft successor of #334. The shared CVRF/CSAF
`cli_index.read_input_file` is also used by the investigation service and
still used blocking `open(path, 'rb')` before checking source regularity.
A bounded POSIX FIFO control exited 124 on a timeout; a nonblocking
held-descriptor control rejected the FIFO before reading. SPEC-31-F was
updated first, five repository regression cases were authored, and the
source now verifies the opened regular descriptor and preserves the
existing capped read and valid symlink inputs. Five local algorithm-copy
controls passed; these are not repository-source tests. GitHub DNS checkout
and Ruff availability remain blocked locally. Exact-source hosted Linux/
Windows QA, Qt, native, package and independent review are not accepted.
Predecessor PR332 had successful Linux/Windows QA, Qt and native checks,
with downstream smoke pending; PR333 still had one Qt shard in progress,
while PR334 checks were queued or running at inspection. Predecessors do
not qualify this source. Raw Winbindex index/resolver membership, Linux
forced export, Qt advisory disposition, Windows trust, historical reviews
and verified L1/L2/L3 remain blocking. No main merge or release eligible.

## Generation-25 resolver-window acquisition-source correction (2026-11-20 UTC)

A new isolated draft successor of PR335 addresses a source-provenance mismatch:
when one SHA has both BASE and KB bodies, the former SHA-only first-match
selector could place the BASE body in evidence for the KB-targeted newer
build. The contract now requires the newer row to match the resolver's
`index:<version_key>:<KB or BASE>` anchor, with native-body precedence over
an explicit `other_versions` copy. A missing target is refused before
provider planning. This changes which normalized row is included in consent
and may require new consent; it does not infer older predecessor row identity
or retain the complete raw index/timeline.

The pre-repair control reproduced BASE selection for a KB target. Fifteen
isolated algorithm-copy replays and Python compile succeeded; these are
not full repository tests. New actual repository-source regression tests were
committed, but local GitHub DNS resolution and absent Ruff prevent executing
checked-out-source pytest/ruff. Exact-head hosted QA, Qt, native, packaging,
independent review and release acceptance remain pending. The earlier #333,
#334 and #335 checks qualify only their own sources. No main merge or release.

## Generation-26 older source-body ambiguity safeguard (2026-11-20 UTC)

An isolated draft successor to #336 updates SPEC-31-F before tests/code and
rejects multiple **distinct** older normalized Winbindex source entries sharing
one SHA-256 and basename. The original first-match selection could label an
older BASE as an unrelated KB body or vice versa solely from list order.
Exact repeated mappings and uniquely identified older rows remain usable.
Eight repository test cases were authored including a no-network service
preview; six isolated source-algorithm mirror controls passed, **not**
checked-out-source pytest. Whole-repository offscreen QA, Ruff, relevant
schema/dependency checks, independent review and exact-source hosted/native
qualification remain unverified. Full raw index capture/older membership,
Linux forced-publish exposure, native Qt disposition, Windows trust, accuracy
layers and historical consolidation remain blocking. No main merge or release.

## Generation-27 selected newer source ambiguity and inherited I001 (2026-11-20 UTC)

On a separate successor to draft PR337, SPEC-31-F now requires that the
native-first matching newer source tier contain only equal normalized source
mappings. Distinct native or, in the absence of native, copied source bodies
for the resolver-selected KB/version must refuse `PT-KBC-INPUT` before any
plan, consent, fetch or project creation. Four red isolated selector cases
reproduced order-dependent admission; six green cases passed after the repair.
Eight actual repository test cases were authored but not executed in a checkout.
This is not authenticated source evidence, a raw Winbindex snapshot, exact
predecessor membership or empirical L1/L2/L3 accuracy.

PR336's Linux QA on exact `c02e316a` logged **23,792 passed, 51 skipped,
6 xfailed** and then failed Ruff `I001` at
`tests/test_kbc_acquire_row_membership_20261120.py:2` because of a redundant
empty line after the import block. The isolated successor makes the narrow
formatting correction without changing the test assertion. Full current-source
pytest/Ruff, hosted QA/Qt/native/package and independent review remain
outstanding. This evidence does not qualify the later candidate. No main merge,
release or deployment is eligible.

## Generation 28 — real predecessor CI qualification blockers (2026-11-20 UTC)

PR337 exact head `30a9c9da` [Linux QA](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44735573991/job/136285974702) finished **23,800 passed, 51 skipped, six xfailed** before Ruff **F401** in `tests/test_kbc_acquire_older_ambiguity_20261120.py:6` (`ready` is a pytest fixture imported for registration rather than referenced as a Python variable). Its I001 in the prior row-membership test was addressed in PR338. PR338 exact head `9897ae5b` [Linux QA](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44743849199/job/136313974974) finished **23,807 passed, 51 skipped, six xfailed, one failed**. The failing test is `test_acquire_preview_refuses_conflicting_newer_source_without_transport_or_project`: the fixture inserted a different row matching only SHA, not necessarily the selected version/KB; the returned error was `PT-KBC-CONSENT`, not `PT-KBC-INPUT`. Neither result is a passing full gate.

The new isolated generation-28 **test-only** candidate obtains the resolver's exact newer target from the unmodified fixture, then injects a disagreement in that target tier. It also uses explicit self-alias imports for two pytest fixtures so the lint contract recognizes their intentional registration. No production, consent, security gate, package or schema behavior is changed. New-source tests, full offscreen suite, Ruff and independent review remain required; Qt/native/package/trust and broader release blockers are unchanged.

## Generation 29 — PR339 hosted test acceptance, Ruff import repair (2026-11-20 UTC)

PR339 exact `a5c6ff87` full Linux QA completed **23,808 passed/51 skipped/six xfailed** and Windows QA completed **23,694 passed/166 skipped/five xfailed**. Both then failed strict Ruff with the same two `I001` import-format errors in newly authored older/newer acquisition ambiguity test fixtures, so PR339 is **not** a green combined candidate. Five PR339 Qt gates succeeded; downstream Linux package/smoke skipped. New isolated generation-29 test-only correction splits the fixture self-alias imports per Ruff's exact patch suggestions, preserving names, test bodies and every security/acceptance rule. Test-code commit `981d41e3`, tree `aa8a96bd55e8`; final documentation head and its own CI must be resolved independently. New-source full QA/Ruff, native/Qt/package, independent review and all historical release blockers remain outstanding. Release-ready and main-merge eligible remain **false**. See [generation 29](../engineering-handoffs/generation-29-20261120.md) and the [hosted receipts](hosted-fixture-qa-20261120.md).
