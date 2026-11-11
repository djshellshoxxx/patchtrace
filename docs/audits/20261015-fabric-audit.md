# Fabric audit, 2026-10-15 (FAB-0 to FAB-5 code vs FAB-integration-plan s5-s9)

Scope: `src/patchtrace/fabric/**` against `docs/specs/program-e/FAB-integration-plan.md` (s7 contracts, s7 "Store as
built", s7 "Pins as built", s8 CLI, s9 slices). Branch `claude/instance-d-gui` at `da7d2db`. Baseline: 594 fabric tests
passing. After the fixes below: 596 passing (`tests/test_fabric_*.py`, the twelve files), `ruff check` clean.

Each finding has an id, severity (High, Medium, Low), a location, the evidence read from the code, and the fix. A "Fixed"
finding has a red test that failed before the change and passes after it.

| Id | Sev | Location | Status |
|---|---|---|---|
| FAB-A01 | Medium | `fabric/store.py` `_anchor` | Fixed |
| FAB-A02 | Low | `fabric/ids.py` `make_anchor` | Fixed |
| FAB-A03 | Medium | `fabric/pins.py` `_latest`, `pins` | Open (decision needed) |
| FAB-A04 | Low | `fabric/store.py` `_saved_project` | Open |
| FAB-A05 | Low | `fabric/pins.py` `PinEvent._consistent`, `_event` | Open |
| FAB-A06 | Low | `fabric/pins.py` `_append` | Open |
| FAB-A07 | Low | `fabric/contracts.py` `clean_line`; `fabric/ids.py` `_facets` | Open |
| FAB-A08 | Low | `fabric/origins.py` `components` | Open |
| FAB-A09 | Low | `fabric/store.py` `retract` | Open (accepted, plan s7) |

## FAB-A01 (Medium, fixed): stored witnesses were not checked against the origin registry on read

- Location: `src/patchtrace/fabric/store.py`, `_anchor` (read path, called from `_read`).
- Evidence: publish runs `check_origins` (`memory.py` `_accept`), so a witness's origin tags must equal the registry tags
  of its source. The read path ran `verify_anchor` and `check_orientation` only. A row whose witness carried inflated tags
  (for example `D_ghidra` on a `capa` source) and whose `origins_digest` matched was therefore read as an independent
  witness. That breaks "shared-origin evidence counts once" and "unknown provenance must never add independence".
- Red test: `tests/test_fabric_store.py::test_a_witness_whose_origin_tags_the_registry_does_not_give_its_source_is_skipped`
  (failed with `(2, 0) == (1, 1)`).
- Fix: `_anchor` takes the registry and calls `check_origins`; a failing anchor is skipped and counted.

## FAB-A02 (Low, fixed): too many witnesses raised an input error instead of a limit error

- Location: `src/patchtrace/fabric/ids.py`, `make_anchor`.
- Evidence: F-03 (16 witnesses per anchor) is a count, and `limits.py` says counts are enforced by the stores with
  `PT-FAB-LIMIT`. `make_anchor` let the `Anchor` shape check fail, which gave `PT-FAB-INPUT` reason `anchor-witnesses`.
- Red test: `tests/test_fabric_ids.py::test_more_witnesses_than_the_contract_allows_is_a_limit_error_not_an_input_error`
  (failed with `PT-FAB-INPUT`).
- Fix: `make_anchor` raises `PT-FAB-LIMIT` reason `witnesses` before building the record.

## FAB-A03 (Medium, open): a pin state ignores an unreadable newer event

- Location: `src/patchtrace/fabric/pins.py`, `pins` (line 232, `set_now`) through `_latest` (line 175) and `_event`
  (line 166).
- Evidence: `_events` drops unreadable events before `_latest` picks the last event of each anchor. If the newest event
  for an anchor is unreadable (a newer `fabric-pin` contract, or an `unpin` written by a newer version), the older readable
  `pin` is still reported as set. The plan requires an unreadable event to be counted in `skipped`, "never hidden".
  The count is correct, but the listed state can be the wrong one.
- Fix (needs a decision): either an anchor whose latest raw event is unreadable is listed as unknown (its id is in the
  row name, so the anchor id can be recovered only when the body parses), or `pins()` lists the anchor as `stale`. This
  is not a local change, because the rule depends on what a future contract stores. Open for the integrator.

## FAB-A04 (Low, open): a missing revision is stored as 0 without a flag

- Location: `src/patchtrace/fabric/store.py:173`, `_saved_project`.
- Evidence: `row[1] if isinstance(row[1], int) else 0`. A snapshot without an integer revision gives every batch
  `revision=0`, which silently drifts from the project's revision.
- Fix: refuse the snapshot with `PT-FAB-STORAGE` reason `project-revision`, or keep 0 and document it. Open.

## FAB-A05 (Low, open): key grammar is not re-checked for a pin event on read

- Location: `src/patchtrace/fabric/pins.py`, `PinEvent._consistent` (line ~89) and `_event` (line 166).
- Evidence: `PinEvent` checks the role for the kind and the `anchor_id` derivation, but not that `key` and `subject` satisfy
  the key grammar of `kind` (`ids._key_ok`). A hand-written pin event with a malformed key that still hashes to its own
  `anchor_id` would be pinned and shown. Writes are checked (`pin` calls `verify_anchor`); reads are not.
- Fix: call `ids.check_anchor`-equivalent key checks in `_event`. Open, low risk.

## FAB-A06 (Low, open): a new pin's sequence number ignores unreadable events

- Location: `src/patchtrace/fabric/pins.py`, `_append` (line 250).
- Evidence: `seq = max(readable seq) + 1`. When an unreadable event has a higher sequence, the new event can carry a lower
  number than a stored event. Reads order by `(seq, id)`, so nothing breaks now, but the "highest sequence is the state"
  rule (plan s7) does not hold across contract versions. Open with FAB-A03.

## FAB-A07 (Low, open): untrusted text is processed in full before its cap

- Location: `src/patchtrace/fabric/contracts.py:69-76` (`clean_line`), `src/patchtrace/fabric/ids.py:361-364` (`_facets`).
- Evidence: `clean_line` runs `str()`, two `replace` calls and a regex over the whole value, and `make_witness` sorts the
  whole facet iterable before `Witness` rejects more than 16 facets. Output is bounded, and the cost is linear in the input
  size, but a multi-megabyte advisory string is copied and scanned before it is cut.
- Fix: truncate the input to `limit * 4 + 3` characters before sanitising (a sanitised text is never longer than the
  input), and check the facet count before sorting. Open, no correctness impact.

## FAB-A08 (Low, open): a non-text origin tag raises a type error, not the documented value error

- Location: `src/patchtrace/fabric/origins.py:70-78`, `components`.
- Evidence: `sorted(set(tags))` runs before the `isinstance(tag, str)` check, so a non-string tag such as `1` raises
  `TypeError` from `sorted`, not the documented `ValueError`.
- Fix: move the type check before the sort. Open, trivial.

## FAB-A09 (Low, open, accepted): retract deletes the row with SQL, not through the storage API

- Location: `src/patchtrace/fabric/store.py:338`, `EnrichmentAnchorStore.retract`.
- Evidence: the row is removed by a direct `DELETE`, not by `EnrichmentStore._delete`, so no retention backup or
  `retention_version` mark is written. The plan (s7 "Store as built") says a retraction deletes one row with no backup, so
  this follows the plan. The `ensure` and read-only guards still run. Listed so the integrator can confirm the decision.

## Plan drift checked and found consistent

- Error codes and exit codes (`limits.py`) match s7 and s8. Limits F-01..F-15 match the table in s7.
- `anchor_id`, `witness_id` and `anchors_digest` formulas match s7.
- Orientation reasons, `resolve` side semantics and `find` subject semantics match s7.
- No `absent` verdict exists; missing evidence resolves to `unknown`.
- Unknown or unreadable data is skipped and counted, not treated as a negative vote.
- Persisted contracts: the `anchor-batch` and `anchor-pin` bodies are strict and additive (new kinds, no new required fields).
  Stored unknown fields make a single anchor or pin skipped, as s7 requires.

## Plan status

The status line of `docs/specs/program-e/FAB-integration-plan.md` is updated with this audit's result.
