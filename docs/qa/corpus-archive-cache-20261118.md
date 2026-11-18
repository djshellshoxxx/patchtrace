# Corpus engine archives: unconditional verification receipt

Workflow-only production `693d0bc79762cec84f10764cdb9713568aa2792b` follows
spec/tests `29686c72bbc0ee352bb1ef937baac88750dfb2e8` and
`e5f105ad0fe8722d6a9a9ed88f5d89acb5c7d1a0`. Final qualified test tree is
`451e463d25e625c55344ac232fd9de90275b9013`, tree
`3f46165b40a04b3562cabed3884fb2b1768d3031`.

The only workflow behavior change is in the Linux Tier R shard. It caches original
Rizin/Ghidra archives under new archive keys, checks pin syntax and regular-file
admission, verifies SHA-256 on both cold and restored archives, then exclusively
creates a fresh extraction directory. A corrupt cached archive, link/nonregular
entry or preexisting runtime fails without executing the extractor or proceeding
to Ghidriff installation/shard execution. Valid archives remain cached. Existing
engine-choice conditions, pinned upstream URLs/digests and environment paths stay
unchanged. There is no engine, target, package install or network execution in the
portable verification: curl and the Ghidriff pip command are fixed inert stubs;
real Linux bash/hash/tar/unzip process tiny authored archives only.

## Preserved chronology

| Invocation | Exact result | Scope |
| --- | --- | --- |
| `cache-spec-red`, 29686c72 | 11 failed / 2 cold-positive, 0.67 s | Actual missing archive/cache-hit/runtime refusal behavior plus unchanged CODEX-6 assertion |
| `cache-types-red`, e5f105ad | 4 failed, 0.59 s | Directory/link restored-cache controls before production change |
| `cache-final-focused`, 693d0bc7 | 1 failed / 111 passed, 1.15 s | All cache behavior passed; additional Tier R policy test still required `@v` |
| `tier-action-policy-corrected`, f6cc9a18 | 1 passed, 0.51 s | Isolated stronger 40-hex assertion; exact existing MSVC pin retained |
| `cache-final-affected`, 451e463d | 495 passed / 2 xfailed, 3.04 s | Fifteen affected workflow/policy/source-smoke files; no native target execution |
| Unchanged original four, 451e463d | 2 passed / 2 failed, 0.20 s | Action/cache probes green; dependency hash and Linux full CLI smoke remain real failures |
| Required full Ruff at 451e463d | Passed | `ruff check src tests tools`, no suppression |

The first focused failure was an action-policy neighbor missed by the earlier
13-file action gate. Its original failure and corrected-node receipts are retained
here. Test-only commit `f6cc9a18b1bcaf851faa5fe36032412f3c6f2626` is separately
portable with the action milestone. The sealed action archive SHA-256
`06102fd31bbcb169981f05040dae25f6d043a9198e9e119f3b6f435041ddff76` is unchanged.
The final test-only commit fixes the synthetic ZIP timestamp so recreating the
same authored payload is byte-deterministic; no assertions were weakened and no
prior failure bytes were rewritten. Counts are invocation outcomes, not additive
feature coverage. Two remaining xfails are CODEX-5 and CODEX-14.

## Bounds

The shell probes model the actual two existing cache/engine conditions and reject
unrecognized expressions. The non-Linux suite explicitly leaves these Linux shell
executions unrun; this Linux invocation skipped none of them. There is no mocked
Windows/FDI/native acceptance claim. The archive hash-to-extraction handoff assumes
a cooperative CI workspace; an active local writer replacing files between
commands is outside this correction. Hosted cache restoration, authentic engine
execution, frozen packages and release gates still require exact-source evidence.

Archive: `corpus-archive-cache-20261118.zip`; 54 members, 132528 bytes. SHA-256 `e564d269009b90a1684a97d9f2fbb6fac50977c18a5006ca2aa897f2457a367e`.
