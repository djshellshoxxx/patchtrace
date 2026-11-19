# Workspace connection handoff: sealed correction evidence

Archive: [kb-workspace-handoff-cleanup-20261118.zip](kb-workspace-handoff-cleanup-20261118.zip); manifest: [kb-workspace-handoff-cleanup-20261118.manifest.json](kb-workspace-handoff-cleanup-20261118.manifest.json).

- Corrected source: `a7a4fb1625a0ed89cbd0cb5f54574345caa1fe8e`.
- Archive: 213 members (212 payloads plus manifest), 1,809,982 bytes; 168 canonical Git snapshots.
- Archive SHA-256: `4ecf90bd80e35730a212234f3f822170045850a899cb1a720c8a40cab5d9752b`.
- Manifest SHA-256: `fca56d0fa065d302a8bb9641a370d732e001f2c11be912459c3428719c2c37a4`.
- Every payload and the inner/outer manifest bytes verified.

This is an append to the immutable c470/d31 source/QA packet. Root final independent review remains separate from the author’s 354-pass exact-source replay.

---

# Existing-workspace connection handoff: independent finding and correction

## Outcome and exact chain

The confirmed final-handoff cleanup gap is repaired at
`a7a4fb1625a0ed89cbd0cb5f54574345caa1fe8e`. The only production change moves
`self.db = db` into the existing protected admission body in
`src/patchtrace/kbcorrelation/store.py`. The ordinary constructor path, default
behavior, layout/version/URI policy and cleanup error mapping are unchanged.

| Stage | Commit | Evidence |
|---|---|---|
| Original implementation | `c470a31acec624410a0412e7c803cc38732235a9` | Original 46/344-pass author gates do not cover the subsequently confirmed final-handoff boundary. |
| Original sealed QA | `d31c524ab2bdf119a1172de926569a3b8ece6b3b` | 216-member packet remains byte-for-byte unchanged. |
| Additional specification/tests | `edf4f3ba605eca51e3c7402781b56101e2ba3950` | Clarifies the protected region and adds seven real-connection controls before source. |
| Narrow production correction | `a7a4fb1625a0ed89cbd0cb5f54574345caa1fe8e` | One statement relocation, one added/deleted line. |

All focused commits carry `[no release]`. This packet appends to the original;
it does not replace its observations or claim that its earlier passes qualified
the missing boundary. Root final independent review/replay remains required.

## Confirmed independent failure

Root's unchanged external probe uses a real `sqlite3.Connection` subclass that
counts actual closes. It locates the sole `self.db` assignment by AST and uses
a tightly targeted Python line trace to raise the original `KeyboardInterrupt`
or `SystemExit` immediately before that statement. On `c470a31a`, the assignment
lay outside the cleanup `try`, so both failures preserved the original exception
but left close count zero and the actual connection answering `SELECT 1`.
The neutral successful ownership control passed; the database bytes remained.

The original result is **2 failed / 1 passed**, no errors/skips, with 31
canonical imports and no import drift. The probe SHA-256 is
`f1df7f0522d815bd9be70beaf703d50f22b8daa7e9bd370051976ceb1f3177c0`.
Original command, logs/XML, guard/import receipts and three JSON observations
are retained under `root-original/`; the failed temporary workspace remains
`/tmp/patchtrace-workspace-handoff-red-kiibccvw`. The original runner is retained
without modification as well. No original probe or observation is rewritten.

## Spec-first controls and correction boundary

The new committed controls use the same real-connection ownership property,
with separate authored cases for both primary interrupts and three close
outcomes: success, secondary `RuntimeError`, and secondary `KeyboardInterrupt`.
They check exact primary exception identity, one production close, actual
closed-connection behavior, a fixed bounded cleanup note when necessary, and
unchanged database bytes before test-only fallback cleanup. The success control
proves the returned store owns a live connection until its caller explicitly
closes it; the repair must not eagerly close a successfully admitted connection.

The protected region now includes acquiring the returned connection,
version/layout/root checks and the final attribute assignment. It preserves
the primary exception and uses the existing single cleanup attempt when one of
those operations fails. This does not make Python object construction atomic
against every asynchronous event. A partial failure inside SQLite connect, or
an interrupt after the protected method returns during later constructor/caller
handoff, is outside this guarantee. No generic constructor/ordinary-mode cleanup
policy is expanded and no retry, deletion or ownership inference is introduced.

## Exact current-source evidence

| Receipt | Source | Result |
|---|---|---|
| `spec-red.*` | `edf4f3ba` (unchanged production `c470a31a`) | 6 failures / 1 positive, no errors/skips; 52 exact canonical imports, no drift or instrumented network/child attempts |
| `affected-green.*` | `a7a4fb16` | **354 passed**, no errors/skips; 113 exact canonical imports, no drift or instrumented prohibited attempts |
| `original-probe-replay.json`, `final-original-observations/` | `a7a4fb16` | The exact original external three-case probe passed as part of the 354; original probe and all old observation hashes verified unchanged before/after |
| `ruff.*`, `diff-check.*` | `a7a4fb16` | Full normal Ruff over `src tests tools` and complete base-to-source whitespace check passed |

The final 354 comprise the same original 344 selected cases, the seven new
authored controls and the three original independent cases. Earlier gates are
overlapping and are not added to this denominator. Exact node selection and
eight previously excluded subprocess functions are in `affected-selection.json`.
The wrapper only invokes the unchanged test file and directs its designed
observation environment variable to a fresh directory; no assertion, trace,
constructor, fixture or expected result is injected or replaced.

Every command, source/tree, runtime, test log/XML and per-module Git blob/hash
record is retained. The separate external probe hash is checked explicitly.
The inherited recorder's prior virtual-Qt-origin failure/correction stays in
the original packet; that recorder is reused byte-for-byte here. The new source
proof verifies the entire `_open_existing` AST differs only by the one assignment
relocation, all other existing store methods match, and the original 46-control
file and new specification/test bytes remain unchanged across their source
commits. Full canonical import snapshots are retained for both red and green.

## Immutable prior evidence and remaining scope

The original archive is retained verbatim as `original-c470/evidence.zip`,
SHA-256 `e41b28255cf86d3edc8c2dcbd47305cf65288c826e58164f560bb15f960bf13e`.
Its original manifest and reviewable Markdown are included. That packet in turn
retains the separate ordinary `create=False` two-red/two-positive design
counterexample; its behavior is intentionally unchanged and is not relabeled
as fixed by this mode.

This Linux qualification does not establish native Windows, hot-journal
forensic immutability, arbitrary hostile namespace safety or universal
asynchronous Python construction guarantees. It adds no package route, schema
v2, durable intent/provenance, recovery authority, core/native changes or remote
mutation. Package admission and reconciliation still require the separately
reviewed durable safeguards and acceptance gates.
