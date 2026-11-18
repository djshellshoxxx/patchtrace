# Callgraph shared path budget — accepted source and QA (2026-11-18)

**Outcome:** all path-query phases now share the actual adjacency-work budget,
using the existing CSR without whole-graph or row copies. A fully reconstructed
canonical shortest path is retained if later work exhausts the budget. Root
accepted the exact source after independent code review, a **490-case passing
gate**, and **17 unchanged historical controls** in a separate run.

## Source history

| Role | Exact commit |
|---|---|
| Accepted cap-truth source/QA base | `c1d1951b7972c92811aa333b4d3b3a24f3f2b6b5` |
| Path spec/tests before implementation | `7bff6d9e9d1c703d4b01447868e3f840288c0c9c` |
| Accepted path implementation | `f0b0eb02617a87aea4cfe4b06079528d934d6285` |
| Source tree | `1bedb65d1bdef9f2f81625dcf546243cfac98d1c` |

Branch: `codex/callgraph-path-budget-20261118`. This is a separate follow-on
to [cap truth](callgraph-cap-truth-20261118.md); that handoff is unchanged.
Production changes are confined to `callgraph/algo.py`, `csr.py`, `paths.py`
and `limits.py` (+138/−55). Source/test/spec/module blob and SHA-256 identities
for all eight changed files are in `source-files.json`. No remote mutation,
target/native execution, acquisition, dependency or persisted-schema change occurred.

## Invariants implemented

- Each forward or reverse adjacency is charged before it is fetched, including
  revisits and rejected memberships. The existing 200,000 default applies across
  shortest discovery, reverse reachability and enumeration; a smaller caller
  budget also constrains the prepasses.
- CSR forward/reverse iterators are lazy. The path wrapper reuses stored listed
  membership and admits requested endpoints; whole-program mode uses no membership
  filter. There is no filtered-graph rebuild or adjacency-row copy.
- Cancellation is checked before any edge read and at the existing 4,096 interval
  while scanning, including filtered-out neighbours. Zero-edge identity queries
  still honor an already-set cancellation request.
- The completed shortest witness follows ascending-node lexical ties. Forward
  FIFO parents preserve full-prefix order; reverse ties choose the smallest next
  hop. Only a fully established witness within the requested length is retained
  on later exhaustion. Already emitted ordered paths take precedence.
- The five-path/twelve-edge defaults and existing valid caller limits remain.
  Work exhaustion yields a partial result with `Path search reached its work
  limit; more paths may exist.` Existing CLI exit/status and empty-result semantics
  remain intact. Standalone SCC/reach and shortest-distance behavior is retained.

## Preserved failures and exact-source checks

| Gate | Source | Result | Scope |
|---|---|---|---|
| Original historical mixed cap/path controls | `ac789497` | 7 failed / 2 passed | Original batch receipt retained unchanged; cap portion was repaired separately. |
| Original budget boundary | `ac789497` | 1 failed | 202 adjacency examinations despite budget 40. |
| Path spec/test red | `7bff6d9e` | 20 failed / 5 passed in 1.16 s | Real accounting/copy/cancel/witness/CLI failures plus two controls for the newly specified internal `allowed` keyword. |
| Focused implementation preview | Uncommitted path implementation on `7bff6d9e` | 25 passed in 1.24 s | Preliminary; committed qualification is below. |
| Author affected gate, 26 files | `f0b0eb02617a87aea4cfe4b06079528d934d6285` | 489 passed / 0 skipped in 24.72 s | All graph, GUI, schema and tooltip tests. |
| Independent affected gate plus new oracle | `f0b0eb02617a87aea4cfe4b06079528d934d6285` | 490 passed / 0 skipped in 20.78 s | Root's same 489 plus one additional varied-graph differential control. |
| Unchanged historical path file, separate invocation | `f0b0eb02617a87aea4cfe4b06079528d934d6285` | 17 passed in 0.90 s | Exact historical source file, not an edited reconstruction. |

The author's finite permutation oracle checks all **4,096 loop-free directed
graphs on four nodes**, across five budgets, against independently enumerated
simple paths. It tests returned canonical prefixes, not native accuracy. The
independent control adds **200 varied 3–8-node graphs**, allowed sets, length
limits 0–5, result-count limits 1–5 and eight budgets. Existing controls also
cover cycles/self-loops, both search orientations, source-equals-destination,
rejected memberships and a 60,000-node/447,000-edge synthetic graph.

The historical `tests/test_callgraph_path_budget.py` matches
`c13d3257c88140c23fb585a8a59a4dce81e81928` and the sealed batch-one archive:
SHA-256 `e7b2deeb816c8fde372272e52d67be83ee9fd4c89bbadb1fb0c3623118c5a563`.
Root's first invocation included both current and external historical files with
the same module basename, so pytest stopped at collection (one collection error).
The original `independent/callgraph-path-root.*` receipt is retained. The corrected
invocation omits the external historical file and executes it separately; no
source change was needed. Successful logs/commands/XML and the independent oracle
script are in `independent/`.

An initial spec-test Ruff B905 finding requested explicit `zip(..., strict=False)`
in the independent permutation oracle. Its original output is retained; it was
corrected before the spec/test commit. Whole `ruff check src tests tools` and
`git diff --check` pass at the accepted implementation source.

Counts are not additive: focused and historical tests overlap the affected gate,
and the independent affected gate replays the same author cases. The purpose of
separate runs is independent evidence and preserved failure chronology, not an
inflated completion score.

## Actual headless CLI journey

`real_paths.py` creates two explicitly authored synthetic projects through the
current project service, then invokes actual `python -m patchtrace graph paths`
children with Qt imports forbidden. Five calls verify:

1. The normalized hub query returns exit 3/partial and retains `src → z → dst`.
2. Repeating it under another `PYTHONHASHSEED` produces byte-identical JSON.
3. A smaller graph returns the same valid path with exit 0/complete.
4. Its reversed, unreachable query returns exit 4/complete and no paths.
5. A source-equals-destination query returns exit 0/complete and the identity path.

Both SQLite hashes are unchanged after the journey. Raw stdout/stderr, commands,
fixture input/project bytes and the source-pinned `real-paths.json` are retained.
No target was executed and no native backend or network acquisition ran.

## Receipt archive and limits

[Complete receipt archive](callgraph-path-budget-20261118.zip): **67 files**,
**187,478 bytes**, SHA-256
`8d5282d6f43321811ca9ab20ce30b9f19a8c121082cc3815aa45bf0b15bb4399`. `evidence-manifest.json` enumerates every other member by size
and SHA-256; archive integrity and every recorded hash were verified.

Root reviewed the four production files and spec before accepting the exact
source; the independent source/command receipts are retained in this archive.
Full repository, native/manual/Windows and frozen-package qualification are still
separate gates. This synthetic/offscreen evidence does not establish native
compatibility, whole-program completeness or release readiness. Root owns
focused integration and all remote operations.
