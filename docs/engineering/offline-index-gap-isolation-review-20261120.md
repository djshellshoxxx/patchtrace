# Generation 21 — offline index same-read gap accounting, adversarial findings

Baseline: draft PR331 head `3359c846f8608522b90225dbcdab2c66a8754afe`.
New isolated branch: `codex/patchtrace-index-gap-isolation-20261120-g21`. The parent and existing CI are untouched.

## Root cause, uniqueness, and original failure

In `WorkspaceFileIndex.rows`, the reader formerly invoked `rows_for`, which updated
`self._skipped[file_name]`, then converted mappings with `index_rows` and added the
mutable gap counter. If a same-name `rows_for` interleaved between read and
conversion, the first record's mappings could be returned with the other read's
skip count. Specifically an original record with 1 rejected body may appear to
have 0 gaps if the second current record has none. The generation16 stale-record
repair resets *sequential* counts; it does not bind an entire call's accounting.

The same shared counter pattern was checked in current main, PR329/330/331,
and retained donor `work/winbindex-publication-20261105`. This is a bounded
semantic comparison, not review of all 154 outstanding historical heads.
A deterministic standalone reentrancy mirror produced `older / 0` (wrong)
versus call-local `older / 1` (required); it does **not import production
source**. The authored repository test monkeypatches conversion to re-enter the
same adapter after changing the source file and checks the first and second
counts independently. A second test requires additive downstream conversion
rejections; a third requires no-record zero gaps. Neither test is claimed run.

Contract-first `08b0c7bd43d989a575cbe7d9ce4be79e76d08c3b`, test-before-code
`4e09e22557f67f2df512f0126f3345c2efcd14ec`, narrow source repair
`ac75fa4013498397e361de2ec9a9f67aade150ee`. The code removes shared
`_skipped` state, adds private `_read_rows` returning (mappings, source gaps),
and preserves public `rows_for`/ `rows` return signatures, selected-record
admission, bounded reads, error classes and consent. Source/head parent confirmed.

## New source-specific hosted QA failures in predecessor

PR330 source `e428a5bdb21e9d3501e08166b9c1c673e3842193`:

- Linux QA job [136104316334](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44681066815/job/136104316334): **4 failed, 23,748 passed, 51 skipped, 6 xfailed**.
- Windows QA job [136104316166](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44681066815/job/136104316166): **4 failed, 23,636 passed, 164 skipped, 5 xfailed**.

Both hosts failed the *same four* tests, so this is not evidence of transient
Windows/Linux load. Failure #1/#2: plain and gzip refresh asserted the total
resolver gap equals the old top-level entry count `result.skipped=2`, although
`result.skipped_bodies=1` was also recorded and total was correctly 3.
Failure #3: mixed native/WoW64 fixture had four source gaps, old expectation 3.
Failure #4: index port fixture had three, old expectation 2. Contract already
requires addition of unreadable bodies; no tests, product thresholds or strict
gates are suppressed. Follow-up fixture correction commit
`b362d5286bb610310db5bfee10793a1c5887510b` changes only three
assertion sites (one parameterized test accounts for two failures). CI logs
remain the reproducible original red evidence; **later source passing is not
established**. An additional request to count rows only within the requested
`winbindex_key` would misrepresent the existing all-key index adapter contract.

## Adversarial review boundaries and next independent checks

The implementing coordinator separately inspected (1) missing filename
returning zero, (2) open handle still checked regular before bounded read,
(3) re-entrancy and conversion reject addition, (4) `rows_for` compatibility,
(5) older fixture coverage counts, and (6) no new network/PE execution. The
production patch appears narrow, but **an independent reviewer/worker did not
sign off**. Challenge nested recursion, every caller and exact-source Windows
native behavior in addition to mocked/filesystem fixtures. The compiler/source
runtime environment lacks GitHub DNS and Ruff, so no full checked-out
`QT_QPA_PLATFORM=offscreen python -m pytest -q`, Ruff or focused production
import was executed. Previous PR324/325 successes are **not** this branch's
acceptance. PR331 native had five successes with Qt and QA running at the last
check; no PR331 or PR330 QA pass inferred from them.

No claim of raw Winbindex entry/index preservation, resolver membership replay,
Linux forced-source publication race closure, vendor authenticity, native Qt
advisory disposition, Windows trust or L1/L2/L3 empirical accuracy. Full
release and merge remain blocked.
