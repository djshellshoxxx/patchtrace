# N-way EXTERNAL-address persistence QA handoff (2026-10-16)

Status: **P2b code pre-existing; NEW INTEGRATION REGRESSION AUTHORED, CI PENDING.** This note is a continuation aid, not a test-result claim.

Repository: `djshellshoxxx/patchtrace`. Integration branch: `claude/instance-d-gui` at `53f366e8b50ac60a95bdb3734b815daac82cd63d` when inspected; PR #64 is active. This change is isolated on `chatgpt/nway-external-note-qa-20261016`, proposed against the integration branch, with no changes to that branch or any other worker's branches.

## What is already implemented (do not repeat)

`src/patchtrace/nway/graph.py::_read_address_matches` skips each raw address-match record containing an `EXTERNAL:<hex>` source or target and counts that **record once**, avoiding a bogus 1:1 link from a partially discarded target list. `external_limitations` converts the count to a note. `src/patchtrace/nway/series.py::read_raw_matches` receives that note from SHA-256-verified preserved raw JSON. `compute` saves notes in `PairRef.notes` via the existing `nway/1` series contract. Parser-level regression `test_nway_external_skips_are_counted` already exists. SPEC-09 amendment A-05 and SPEC-28 amendment A-06 are present.

The earlier `tasks/todo.md` unchecked P2b row therefore describes completed code. An append-only [NW-P2B] tracker update explains this without rewriting concurrent workers' entries.

## New verification

`tests/test_nway_series.py::test_external_raw_match_skips_survive_series_persistence` uses real synthetic on-disk adjacent pair projects imported through ProjectService. Pair 0 supplies one valid 1:1 raw address link, one EXTERNAL source, and one partially EXTERNAL target relation. Pair 1 supplies a normal synthetic modified match. The test asserts:

1. `series.json` retains the correct count of **2** skipped input records in the first pair's notes.
2. Only valid functions become the expected three-build chain; no partially EXTERNAL relation leaks into it.
3. Recomputing the same series yields identical stored bytes.

No external programs, downloaded binaries, target execution or network access are required. This is new integration coverage for existing behavior; it is not a new analysis engine or production fix.

## Verification and next action

The test and tracker change are committed, but have **not** yet been executed in this session. Run `python -m pytest -q tests/test_nway_graph.py tests/test_nway_series.py` with Python 3.12 and an installed editable PatchTrace package, then `python -m ruff check src tests tools`. Require current-head Linux/Windows PR CI and inspect failures before merging. Do not confuse previously passing parser-only tests with this new end-to-end test.

If a test fails, reproduce and fix the actual underlying issue with a red-first focused test, preserving `nway/1` storage, notes, read-only project behavior and the no-target-execution invariant. After review and passing checks, merge this small branch into `claude/instance-d-gui`; update the final tracker status to verified. Do not duplicate this work with the active LBL-31/LBL-32 branches.

Parallel independent Java-probe work is documented in `docs/handoff/java-probe-qa-chatgpt-20261016.md` on PR #80; it must reach #76 before that mainline PR can merge.
