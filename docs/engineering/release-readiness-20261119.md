# Release readiness after the multi-generation integration

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
