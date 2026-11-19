# Callgraph cap truth — source and QA receipt (2026-11-18)

**Outcome:** the first bounded callgraph repair preserves per-origin omission
truth through neighbourhood queries, CLI/JSON/DOT and the Calls desktop state.
The exact final source/test tree passes **464 affected cases, zero skips**, and
a separate actual headless CLI / real MainWindow journey preserves the project
database byte for byte. Path-query budgets and lazy CSR traversal are separate
unrepaired scope; their original failures remain in this archive.

## Source history and scope

| Role | Exact commit |
|---|---|
| Qualified comparison base | `ac789497597fba3cb87696990d171a7a27024fca` |
| Spec and new regression controls | `c2d93503af025456f6fcd75adf147a0e6e0669e7` |
| Five-file production implementation | `4236e5b89e2cf916a8363164d7a9bf479cb3813b` |
| Existing snapshot assertion aligned to the approved contract | `2c69c4ad1c08112e29aa2403b036ae66dc1c650d` |
| Final source/test tree | `8715f6198ae6a9c6479a186ac0add4e7bb4917df` |

Branch: `codex/callgraph-cap-truth-20261118`. No remote mutation occurred.
The implementation changes only `callgraph/query.py`, `export_json.py`,
`dot.py`, `view_model.py` and `panel_qt.py` (+26/−8). It keeps the exact
neighbour/node/edge caps, identities, navigation, worker/epoch ownership,
publication behavior and persisted schemas. It leaves `algo.py`, `csr.py`,
`paths.py` and `limits.py` unchanged.

The earlier semantic batch is retained at commit
`8148ff0fada34e3adff893a3d68f0bce1ffc6e0f`; this follow-on is a separate branch
from the qualified base, not a wholesale checkpoint merge.

## Behavior and preserved limits

Per-node omissions now set `GraphView.truncated`. Focus IDs are deduplicated
in first-occurrence order before the root cap, so repeats do not hide a distinct
root. `MoreMarker` retains exact per-origin omitted-neighbour counts; overlap
does not become an invented global count. The fixed warning says that some
nodes or edges **may** be omitted.

The CLI uses its existing `partial`/exit 3 for capped views and preserves its
existing `complete`/exit 0 for uncapped views. Paired JSON combines source and
side limitations in stable deduplicated order. DOT adds a fixed partial comment
and graph label only when truncated; existing complete-output goldens pass.
The desktop combines Changes and neighbourhood cap states, so later Changes
delivery cannot erase a current query warning and narrowing can clear it.

## Original failures and correction chronology

| Run | Pinned source | Result | Interpretation |
|---|---|---|---|
| Original nine unchanged historical cases | `ac789497` | 7 failed; 2 passed in 0.66 s | Four cap/focus failures plus three path-work failures; below-cap and shortest-order positives. |
| Original separate path-budget control | `ac789497` | 1 failed in 0.38 s | 202 adjacency examinations for a caller budget of 40. |
| Spec/new-test red | `c2d93503` | 11 failed; 3 passed in 1.35 s | Actual query, independent CLI export, aggregate reasons, and offscreen desktop failures. |
| Implementation preview | Uncommitted implementation on `c2d93503` | 14 passed in 1.09 s | Focused preview only; final qualification is the committed gate below. |
| First full affected selection | `4236e5b8` | 1 failed; 463 passed in 21.22 s | An existing snapshot test explicitly expected `not view.truncated` after omitting two neighbours. |
| Final affected selection | `2c69c4ad1c08112e29aa2403b036ae66dc1c650d` | 464 passed; 0 skipped in 19.83 s | All 24 selected graph, UI, schema and tooltip files. |

The old snapshot failure is preserved in `affected.log/xml`. The append-only
test correction retains its exact 65 visible nodes and marker count 2, requires
`truncated=True`, and adds a cap-reason check. It changes no production source.
Below-cap, duplicate-claim and complete-output positives remain in the gate.
The original historical controls were extracted unchanged from `c13d3257`;
the archive records their exact Git source and SHA-256. The three path failures
are not claimed fixed by this first slice.

The first standalone journey harness incorrectly expected `ok` for an uncapped
CLI result. The existing contract returns `complete`; this was a harness
assumption, not a product failure. The initial script/log and four original
CLI stdout/stderr pairs remain under `journey/`. The corrected script and
independent new project/outputs are under `journey-final/`. No original result
was overwritten or relabeled as passing.

## Current-source evidence

`affected-final-command.json` records exact argv, source/tree, clean Git status,
absolute current-worktree `PYTHONPATH` and `QT_QPA_PLATFORM=offscreen`.
`static-checks.json` records passing whole `ruff check src tests tools` and
`git diff --check` at the same source. The 14 focused cases are included in the
464-case gate; they are not additional coverage counts.

`real-journey.json` records five actual `python -m patchtrace graph` subprocesses
against an authored synthetic project. A startup import guard rejects Qt
imports in each child. Capped neighbours and both JSON/DOT export commands
return exit 3/partial; the shown view contains 65 nodes, 64 edges and an exact
per-origin omitted count of 2. Uncapped neighbours and DOT return exit 0/complete
without the cap warning. Raw JSON stdout, stderr and exported files are retained.

The same project is then opened through real `ProjectService` and `MainWindow`,
using the production Calls controller. The three captured states are:

1. TraceMessageHub: capped, with the conservative omission warning and no `64 of 64` claim.
2. A later real Changes task: the cap remains visible.
3. Caller000: uncapped, with no stale cap warning in the state or visible DOT export.

The database SHA-256 is equal before and after the CLI/GUI journey. Two offscreen
screenshots were inspected and are retained in the archive; this is source Qt
evidence, not native Windows or manual accessibility acceptance. All data and
PE bytes are explicitly synthetic; no target or native engine was executed.

## Receipt archive

[Raw evidence archive](callgraph-cap-truth-20261118.zip): **88 files**,
**468,426 bytes**, SHA-256
`f98fbc98351f6550b1d180d430cebebd81ad320510534054ac3a415786eec217`. `evidence-manifest.json` enumerates every other member with size
and SHA-256. Archive integrity and every listed hash were checked. `source-files.json`
records exact Git blobs and SHA-256 for all 13 changed source/test/spec/module
files at the final source/test head. Raw command receipts, scripts, original
failures, synthetic retained project, CLI files and offscreen PNGs are included.

## Review and open gates

Root independently reviewed the five production diffs, export/GUI propagation,
spec/test additions and corrected retained assertion without a blocking finding.
The same 24-file gate passed independently at exact `2c69c4ad1c08112e29aa2403b036ae66dc1c650d`:
**464 passed in 19.35 s**, zero failures/skips. The unchanged original historical
cap-control file passed separately: **6 passed in 0.31 s**. These overlap the
author suite and are independent replay evidence, not additional unique test
coverage. Original root command JSON/log/XML, root's earlier 1-fail/463-pass run
at `4236e5b8`, and the initial zero-test missing-filename preflight are included
under `independent/`. No independent path-budget repair is claimed.

Shared path budgets/lazy CSR, native/manual/Windows execution, full repository
qualification and frozen packages remain outside this slice. Existing graph
export publication behavior is unchanged. No historical checkpoint branch
closure, release readiness, main merge or native compatibility is asserted.
