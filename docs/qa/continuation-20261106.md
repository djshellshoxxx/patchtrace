# PatchTrace continuation: product workflow and qualification repairs

This continues the [branch merge plan](../plans/branch-merge-plan-20261106.md)
from #244 `f393bb68ddc11eabb95a6598aa6f86650bd9aa37`. The existing
#205/#218/#235/#244/#245 source refs remain separate qualification records.

## Windows recovery prerequisite

Unchanged #245 `4465a0492367d08f324e80b290a594791921691c` passed
[Windows QA](https://github.com/djshellshoxxx/patchtrace/actions/runs/42169559762/job/127733918608):
**19,671 passed, 90 skipped, 5 xfailed, 1 warning in 2,750.13 seconds**.
Ruff, standalone build, frozen EXE smoke/self-test, portable ZIP execution
outside the checkout, installer construction, and install/launch/uninstall
all passed. Its Windows repeated Qt gate subsequently passed too.

The tested merge ref `9e0bfefa3d036d080efef30f62ead1a5578ed6f5` has the
expected base/head parents and the same tree as the repair:
`6db3490e96da2a8f0a200d834f8816bc41421f57`.
[Frozen evidence](continuation-20261106/pr245-windows-review.json).

[Windows candidate artifact](https://github.com/djshellshoxxx/patchtrace/actions/runs/42169559762/artifacts/13485625163):
`PatchTrace-windows-x64`, 130,974,130 bytes; artifact ZIP SHA-256
`22a1321a848127dc8ab1f2293c9d07f02b7e082cef804f762f566775fdcb334b`.
It belongs to #245 and does not contain the later #244/continuation features.
This is candidate qualification, not a release-completion claim.

## Preserve the active Python environment

[PR #246](https://github.com/djshellshoxxx/patchtrace/pull/246),
`c804e4d94430368c0eafe1da899493a8cf6520aa`, retains `sys.executable`
instead of resolving virtual-environment symlinks in two subprocess tests.
Both production worker launchers already use this entry point. The only
test-code changes are two assignments and explanatory comments.

Both original failures reproduced on main `d02b94bc`. Both complete affected
files then passed **116 tests in 42.16 seconds** in the same environment.
Independent review found no issue; its separate original-control replay
passed **2 tests**. All assertions, positive controls, environment filters,
limits and cleanup checks remain unchanged. Sonar and Snyk pass; CodeRabbit
and Qodo reported no actionable findings on the published head.
[Diagnosis](subprocess-venv-20261106.md) and
[independent review](continuation-20261106/subprocess-venv-review.json).

Published tree `cf59135e03b1c4a84ff628b29b4abb9d308a2b7d` exactly matches
local reviewed commit `e52047ae1b1bbb19a42680b8d9881338f2595f93`.
The complete local Linux result and hosted qualification remain separate
from this focused evidence.

### Historical #128 disposition

PR #128 at `10856edf05afae8166291f09fb3ead92f297360d` already preserves
the BinExport interpreter entry point using `.absolute()`, introduced by
`0271f1869ccba0697c5bf6f797432bb7c6ec54d4`. #246 independently supplies
that behavior using `sys.executable` directly and also fixes the rules-worker
launcher. No additional launcher regression exists in #128 to port. This is
narrow behavioral overlap pending acceptance, not an ancestry merge or
acceptance of its broader research workflow. Its source ref and PR remain intact.

## Bound failure formatting while retaining exact byte equality

Reviewed local `37efbb7d32ea01c2efafca3c6117a679e9057ac0`, published as
`064f1c0075a4cfe5ec1eba2f9a04d3f1058ecf0c`, replaces three large recovery
byte assertions with a test-only helper. Every byte is still compared directly.
After inequality is established, the diagnostic reports the first differing
offset, lengths, SHA-256 values and a small byte window. Hashes do not decide equality.

The [old #235 Windows run](https://github.com/djshellshoxxx/patchtrace/actions/runs/42133327940/job/127615155412)
has **20,207 passed, 7 failed, 93 skipped and 5 xfailed**, with JUnit duration
4,329.154 seconds. All failures concern the unchanged N-way recovery files.
Two byte-diff cases recorded **919.855 and 925.435 seconds** and tens of
thousands of repeated diff lines: 42.6% of the failed run. These observations
implicate failure rendering; no normal-path speedup is claimed. The production
recovery correction remains #245.

[Compact evidence](continuation-20261106/pr235-windows-failure-summary.json)
retains exact source IDs, counts, and the original artifact/XML digests. The
downloaded ZIP and XML were independently hashed against that receipt and
GitHub's artifact digest. Their oversized contents are not duplicated here.

The affected recovery/helper selection passed **49 tests in 9.79 seconds**;
independent helper verification passed **2 tests in 1.42 seconds**. A real
pytest child with long tracebacks and `--showlocals` verifies one equal pass
and seven intended mismatch failures, zero errors/skips, and console/JUnit
output each below 10 KB. A forced-equal-digest control still rejects unequal
bytes. Whole-tree Ruff and diff hygiene passed. These selections overlap.

## Start from a stored product without a KB/CVE

Reviewed local `570f86b8be7038c0841e318693ed5ee0f414b8c2`, published as
`0b7d858149db0c88ffcf8f3e6ba474d99f39afeb`, adds an explicit local product
starting mode to the existing desktop investigation. Both commits have tree
`8aa7d16fd78136780f58e281240c02b6f8fd520d`. SPEC-31-C/F describe the
contract before the corresponding implementation.

The analyst lists or filters products from active stored advisory documents,
explicitly selects one, previews two local files, and creates a separate
comparison. The catalogue caps the displayed list at 200 and reports truncation.
Even a single match requires selection. Unreadable source documents refuse
product listing/admission because silently dropping them could revive a
superseded product. Existing partial KB/CVE lookup remains unchanged.

An immutable request captures the full selected ProductScope and SourceDoc
snapshot. A single admitted index validates them and constructs saved
provenance. Existing hash, architecture, component, destination, revision-CAS
and cancellation rules apply. The project saves its actual pair lead, selected
scope, source coverage, analyst decision, source digests and raw sidecars.
Selecting a product does not establish binary membership, KB/CVE attribution
or a fix boundary. It creates no CVE cards, CWE profiles or hypotheses. Both
advisory and metadata network grants are revoked in product mode.

### Pending-attachment compatibility

Product-start attach journals add an optional persisted `selected_product`
member containing the full ProductScope. Repair rebuilds context from exactly
the journaled source subset and requires the same full product interpretation
and source set before writing attachment rows. Missing/corrupt originals or a
changed alias interpretation refuse repair while retaining the project.

This is an **internal journal-format addition**. Public schemas, SQL version
and CLI grammar are unchanged. The older `f393bb68` reader accepts and retains
the extra member but ignores it during repair: a real compatibility probe
reported repair success with **zero source digests**. A pending product-start
attachment therefore requires a build that implements the new journal
semantics; downgrade repair is not qualified.
[Compatibility receipt](continuation-20261106/product-start-legacy-reader.json).

### Review and focused qualification

Missing-feature controls first produced three failures on the base. A second
set produced three unreadable-source failures before conservative admission;
three repair cases failed, with one unchanged-source control passing, before
journal-bound repair. Final product/recovery/service/end-to-end/workflow
selection: **139 passed in 14.38 seconds**, including 59 new product cases.
The earlier expanded selection passed 391 tests in 96.60 seconds before the
repair addition; these overlapping counts are not additive.

Independent exact-source review found no blocking issue and passed **16
additional acceptance cases in 2.37 seconds**. Its first run had one probe
expectation mismatch (`VERIFY` versus `STALE`), corrected without production
changes; both runs are retained in the review record. Six distinct cases were
then committed as repository regressions at local `59c4f637`: real competing
revision writes, export/reopen after workspace source loss, explicit selection
after one-result filtering/relisting, cancellation after real creation, and
repair after a newer advisory retains or removes the chosen product. These six
plus the author's 59 passed **65 tests in 3.55 seconds**. A second read-only
review of that retained-test commit found no issue.
[Source review](continuation-20261106/product-start-review.json);
[retained-test receipt](continuation-20261106/product-acceptance-review.json).

Whole-tree Ruff, diff hygiene and KBC schema generation passed with no schema
drift. An offscreen Qt screenshot was inspected at 920 by 760 pixels: all
controls were visible and the network actions disabled. This is Linux layout
evidence, not native Windows accessibility or release qualification.

## Latest hosted prerequisite checkpoint

At 08:18 UTC, #245 Linux full QA had also passed and all five native Windows
Ghidriff jobs had passed on both #245 and #244. #245's Ubuntu Qt shards remained
one running and three queued. #244's Windows full QA was running and Linux full
QA queued. These are exact-head prerequisite results, not tests of the new
product continuation. No failed jobs appeared in that snapshot.
[Job/status receipt](continuation-20261106/pr244-pr245-hosted-status-0818Z.json).

## Integration boundary

The continuation preserves the diagnostics and product implementation as merge
parents and published #246 as an ancestor. Only the append-only QA/task ledgers
conflicted: every destination byte was retained and each new receipt appended
once. The acceptance tests add no production changes. Combined-source full
qualification and hosted gates are recorded separately from focused evidence.

Main promotion still requires the #245 prerequisite, propagation through
#205/#218/#235, applicable checks and normal review, and the outstanding
parent Sonar dispositions. A passing delta scan does not resolve a failed
parent scan. Native #222/#224 and paid-agent automation remain separate.
