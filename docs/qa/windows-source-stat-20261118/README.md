# Windows source and dependency receipt observations

Final source **`80df2735ea9001b7ba5f9aacf95614f280e51948`**, tree `dee6041e11fd30fd036877af3f504798f51d89ce`, is based on
`c7d3f25858cfefbacbd8ea4022b3d13e1e2aed2a`. The seven attributed specification, regression and source commits
are retained in the evidence archive. This QA checkpoint changes no production
code and does not remove the `[no release]` hold.

## Result

The final author gate passes **240 checks with eight explicit native Windows
skips**, zero failures/errors, in **1.34 seconds**. Independent replay passes
**44 preserved external/peer controls** with zero skips in **0.41 seconds**;
the independent affected gate plus 12 additional boundary controls passes
**252 checks with the same eight Windows skips** in **1.58 seconds**. Counts are
overlapping invocations, not additive coverage or accuracy measurements. All
source imports and Git snapshots are pinned; normal full Ruff and whitespace
checks pass. Actual Windows execution remains unverified.

## Supported observation mismatch and hosted limits

The exact retained CPython v3.12.10 implementations show that Windows pathname
stat substitutes creation time into `st_ctime_ns` and synthesizes execute bits
from `.exe`, `.com`, `.bat` and `.cmd` suffixes. Descriptor stat reports the native
change time and physical mode. Comparing their complete tuples as though these
fields had identical meanings falsely refuses otherwise stable files.

Primary files and their license are preserved with URLs, sizes and SHA-256:
[posixmodule.c](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c)
and [fileutils.c](https://github.com/python/cpython/blob/v3.12.10/Python/fileutils.c).
This source evidence is distinct from native execution.

The retained PR316 preview `5ed108355f2626c9867782832c76b1c438c51281`
has the same tree as published head `14efc52369146f4a638b7d688208736a05321bc0`.
Its Windows BinDiff and two Windows dependency-profile jobs fail at the source
guard before native compilation or scanning. Those logs do not identify the
offending path or individual stat fields. The supported API mismatch is a
credible explanation, but the exact hosted failing field was not observed.
All five original hosted artifacts, logs, API observations and their independent
byte review are retained; the strict static result at that older tree remains
**80 diagnostics, exit 1**. No historical failure is relabeled as passing.

## Corrected boundaries

The first repair compares only compatible cross-view identity: device, inode,
physical mode without suffix-derived execute bits, size, modification time,
explicit creation time and attributes. It retains complete same-API descriptor
and pathname checks, bounded canonical Git blob hashing, parent identities and
the commit hold. Missing or malformed required regular-file observations refuse.

Independent review then reproduced an adjacent final-pass gap. A same-inode,
same-size rewrite with restored modification time, after a file's hashing
descriptor closed but before the final all-files pass, escaped the Windows
pathname-only comparison. The original peer probe and a separate real-local-Git
probe are preserved, each with **one failure and two positives**. They model the
primary implementation's Windows observations over real inert file operations;
neither claims native Windows execution or that the compatibility patch created
the preexisting final-pass limitation.

The final repair retains an opaque immutable snapshot of original pathname,
compatible-open and full descriptor states. A shared `source_unchanged` helper
reopens one Windows regular file at a time in the final pass, binds it to the
captured identity, compares its full descriptor state including ChangeTime,
closes the descriptor, then rechecks the pathname. Both `checked_source` and
dependency `checked_tree` use that helper. It does not hold one descriptor for
every tracked file. POSIX retains its complete final pathname comparison;
symlink targets are not opened by this helper.

A second independent boundary affects dependency evidence itself: `read_json`
and `digest` rejected stable Windows observations because `read_bytes` compared
pathname and descriptor change-time fields directly. The original **two failures
and two positives** remain. Receipt reads now use the compatible comparison at
open and complete same-descriptor stability across reading, plus the original
final pathname, byte limit and strict JSON checks.

Three authored malformed attribute cases previously raised `TypeError` before
the intended typed refusal. Validating required observations before interpreting
attribute bits fixes this deterministic error boundary. No supported CPython
route producing those non-integer fields was established, and they are not
reported as three reachable vulnerabilities.

## Preserved chronology and independent review

| Source/phase | Actual result |
|---|---|
| Original compatibility spec before source | 11 failed / 8 passed / 3 Windows skips |
| First corrected focused gate | 98 passed / 3 Windows skips |
| Dependency neighbors | 122 passed |
| First clean complete portable source `f8c8877b` | 220 passed / 3 Windows skips |
| Initial independent external controls | 31 passed / 3 malformed-observation typed-error mismatches |
| Independent real-Git late-write control | 1 failed / 2 passed |
| Independent dependency receipt controls | 2 failed / 2 passed |
| New spec before final source `974d54cc` | 9 failed / 30 passed / 8 Windows skips |
| Final author source `80df2735` | 240 passed / 8 Windows skips |
| Final original external/peer replay | 44 passed / 0 skips |
| Final independent affected/boundary gate | 252 passed / 8 Windows skips |

The initial coordinator preflight refusal and import-order Ruff finding remain
as explicitly labeled summaries where raw console files were not captured.
All test-run raw commands, logs, JUnit, imports and exit receipts are retained.
Original red observations were not overwritten. All 41 payloads of the initial
independent packet remain byte-identical in the corrected packet. A separately
named exact-source replay changes only the commit-hold test's SHA literal;
the original file and substitution receipt remain.

The 12 additional independent controls cover single-descriptor closure on
success/refusal, ChangeTime and inode changes, reparse attributes, unavailable
metadata, the final pathname, POSIX and dangling-symlink behavior, duplicate JSON
and oversized receipts. The reviewer read both complete consumer changes and
found no remaining blocker within that bounded portable scope.

## Remaining acceptance

The eight unexecuted native Windows checks are four final-source cases across
the two consumers, one dependency receipt case and three rewritten-source suffix
cases. These use inert authored data, never target execution. They must actually
run on the candidate's Windows runtime. No portable test qualifies a Windows
filesystem, SDK/native engine, dependency vulnerability audit, frozen package,
installer or canonical release. The final source check is a point-in-time
observation; it does not freeze later files or defeat arbitrary forged metadata.
Main and publication acceptance remain separate gates.

## Immutable evidence

The adjacent [archive](evidence.zip) contains **67 verified payloads**,
**1,010,834 bytes**, SHA-256 **`bf60137ec749fc934419bfb2c5a8900927e459f3bf83b19fcf4a3667f4e5d011`**. The
[manifest](manifest.json) records all payload hashes, exact sources, original
independent archive hashes and the coordinator verification. It includes complete
author receipts, both independent archives, primary sources/license, source and
test snapshots, full source diff/history, hosted evidence and replay helpers.
