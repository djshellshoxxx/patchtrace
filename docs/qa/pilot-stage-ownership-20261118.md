# Pilot staging cleanup ownership

## Result and exact source

`pilot/store.py:stage` now starts cleanup ownership **after exclusive directory creation returns successfully**.
If `mkdir` fails because its generated name is occupied, the exception propagates and the existing directory,
earlier staged result, regular file, and child evidence remain untouched. Once creation succeeds, sidecar write
errors and interruptions still remove that newly created directory and preserve the original exception.

| Item | Exact identity |
| --- | --- |
| Base | `36e14051a4d36f5c66df0186f037a4905b01bf05` |
| Specification and tests first | `e6e6ca13ec64f05b33edf6adea1286655d4ca25c` |
| Source repair | `43ac4829f4e196d7001714bff3622229f5c64d00` |
| Branch | `codex/pilot-stage-ownership-20261118` |
| Worktree | `/workspace/scratch/c7a9e8d98848/pilot-stage-ownership` |
| Runtime | `/workspace/scratch/3a6632a6e5ff/venv/bin/python` |

The source patch is two inserted lines and one removed line: `staged.mkdir(parents=True)` moves outside the
sidecar-write cleanup block, with one ownership comment. It changes no assessment schema, source identity,
ranking, provider, database, publication order or scanner policy. The existing exception still reaches the caller;
there is no retry that reuses an occupied directory.

## Reproduction and red evidence

The original implementation put `mkdir` inside a `try` whose `except BaseException` unconditionally called
`shutil.rmtree(staged, ignore_errors=True)`. That cleanup could delete a directory this operation had failed to
create. The diagnostic was found while reviewing S108's project-relative `tmp-` path. The concrete defect is
cleanup ownership; the probe does not claim an attacker can predict the random token.

The unchanged external probe is retained as `test_pilot_stage_collision_external.py` alongside its original
`pilot-stage-collision-red.log`, XML and source/import context. It uses an actual authored sample project,
creates another operation's directory and evidence, and fixes only token selection to deterministically hit that
occupied name. Original result at the base source: **1 failed / 1 healthy positive in 0.68s**. The positive proves
that a later failure while writing a directory this operation really created should still clean it up. Root
independently reproduced the same occupied-directory failure on its combined candidate before review.

The new regression file was run before changing product source: **3 failed / 8 passed in 0.76s**, with no setup
errors. The failing cases were:

1. An occupied directory containing nested evidence must survive failed creation.
2. A first successful real `stage` result must survive a later deterministic name collision.
3. Another creator winning before the attempted `mkdir` must keep its directory and marker.

The positive controls preserve an occupied regular file, verify normal stage output, and inject `OSError`,
`KeyboardInterrupt` and `SystemExit` after each of the two actual sidecar writes. They verify the exact original
exception is re-raised, only the newly created directory is removed, and sibling evidence remains byte-identical.
The specification explicitly records when this ownership begins and ends.

## Verification

| Check | Result |
| --- | --- |
| Focused candidate: new regressions, store, durability and unchanged external probe | **65 passed in 1.73s** |
| Exact committed source: eight affected test files plus unchanged external probe | **219 passed in 26.29s** |
| Configured repository Ruff (`src tests tools`) | Passed |
| `git diff --check` | Passed |
| Strict S108 scan with isolated config and `--ignore-noqa` | Still exits **1**, with the original S108 path diagnostic |

The exact-source affected files cover stage ownership, store publication/retention, flushed writes, headless
pilot CLI, current input capture, CVRF context freshness and the offscreen Leads UI. The full command, exact
source/file hashes, test path, external probe hash, exit and JUnit result are in `exact-affected.context.json`,
`exact-affected.process.json`, `exact-affected.log` and `exact-affected.xml`.

The parent process and subprocess environment use absolute worktree `src`/`tests` paths in `PYTHONPATH` and
`QT_QPA_PLATFORM=offscreen`. No target binary or native analyzer was executed, no network request was made,
and no frozen corpus or prior outcome was changed. Authored parsing/UI/storage tests do not establish native
engine accuracy or Windows filesystem behavior.

## Static diagnostic mapping remains explicit

This repair is part of a separate review of the **36 remaining original diagnostics** from the preserved 79-row
strict scan. At the base source the current scan reports **37** for those rule families: the previously repaired manifest
parse now has both a guarded `XMLParser` call and `fromstring` call, each flagged S314. The one original manifest
row therefore maps to two current scanner locations (156 and 161). All other 35 original rows map one-to-one.

`residual-diagnostic-map.json` retains that mapping and source hashes, and the original/current raw scan copies
and command are included. The additional parser warning is not silently discarded or presented as a second
demonstrated XML defect. The reviewed manifest DTD repair has its own source and evidence receipt. This staging
repair leaves the S108 finding visible and does not change rules, inline annotations or exclusions. No blanket
static/security qualification is claimed.

## Practical ownership limits

This repair covers the observed failed-creation seam under cooperative project filesystem use. Before `mkdir`
returns successfully, the stage cannot claim the path; after successful return it owns cleanup for its write
attempt until success hands the directory to publication. Parent directories created along the way may remain.

It does not establish nonce predictability, arbitrary same-user path-replacement resistance after creation,
atomic pathname-conditional deletion, or cleanup after process kill/power loss. Those cases require a broader
filesystem protocol and are not inferred from these deterministic collision tests. Existing publication and
orphan-aging behavior remains independently scoped.

The adjacent manifest enumerates every retained payload and SHA-256 in `pilot-stage-ownership-20261118.evidence.zip`.
Scratch originals are under `/workspace/scratch/c7a9e8d98848/qa/pilot-stage-ownership`; the original external probe
and first red results remain unchanged under `/workspace/scratch/c7a9e8d98848/qa/security-boundaries-review`.
Root owns independent replay/review and integration; no remote mutation occurred.
