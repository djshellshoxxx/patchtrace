# Recovery batch 6: attempt retention and preserved evidence

## Result and scope

This is a newly authored correctness repair after a retained-history audit. It
addresses the malformed-row/post-write retention exception left open by the
history-diagnostics recovery and two directly reproduced cap-path defects.
The independent branch starts at
`3cde10aec12418f92b34a0f5a90c79c1785c88d9`; the batch 5 acquisition commit
remains on its separate preserved branch.

Changes are confined to `enrichment/storage.py`, a new storage regression file,
the two-case post-write UI fixture setup, the H1 specification amendment and this
report. There is no schema, migration or new cleanup operation. Original malformed
rows are retained in place. Genuine write errors and unexpected post-write
exceptions retain their propagation and uncertainty semantics.

## Existing implementation and retained-branch disposition

The vulnerable retention scanner was introduced by
`cb25132b0ebd12abb2f15bdc60324b8d177bef25`. No repaired implementation was
found in the inspected fetched history:

- Of 161 frozen retained heads, 120 contain the same scanner/pruning methods,
  27 predate those methods and 14 lack the storage path.
- A deduplicated cross-check of 322 fetched origin ref entries, including the
  `origin/HEAD` alias, found the same `_run_rows` AST on all 275 entries containing
  it; 32 predate the method and 15 lack the file.
- Main `fdc2696c23bdbfe7668348f25e3b336ce33039f7`, PR #319
  `a56ab13aaf9916fc12bea70ba1494075991b7f09`, and PR #320
  `188b4962e527c82b29e599f75cd952029b749348` share storage blob
  `419b518a9cc19f112513359bab5c7cb3f8b208d5` and the vulnerable scanner.
- The integration base has storage blob
  `dbb7158af9b659518a018427634d1f19b18800fc`, including other reviewed storage
  work, but the same vulnerable retention methods. Those unrelated changes are
  preserved.

The frozen census was not rewritten. These counts describe inspected fetched
objects, not a new remote branch census or completion of retained work.

## Reproduced failures

### A malformed reference can raise after an attempt commits

`secondary.store.publish_run` commits an `engine-run` row and then calls
`prune_runs`. The old scanner called `.get('run_id')` on decoded secondary bodies
without checking their shape. An authored `[]` body raised `AttributeError`, while
the new attempt row was already present in real SQLite. This confirms why the
existing UI must retain **Attempt storage unconfirmed** for unexpected publication
exceptions; an exception does not establish that no write occurred.

### Malformed attempts can be selected for deletion

Malformed engine-run bodies were assigned an anonymous `(None, None, None)` group
and treated as unreferenced. A storage-only replay with three authored `[]` rows
and `keep=1` deleted two original malformed rows. The old scan also ignored stored
body hashes and permissively decoded metadata used for grouping and reference
protection.

### Explicitly protected attempts were still reclaimed

The engine-run portion of `make_room` ignored its caller's `protect` set. A replay
protecting `r0`, `r1` and `r2` still deleted `r0` and reported 685 bytes freed.
Two regression cases reproduced deletion of a protected oldest attempt and
failure to refuse when every attempt was protected. The corrected loop skips
protected IDs before counting bytes or selecting deletions.

### NULL IDs caused exceptions and incorrect cap accounting

SQLite permits NULL in this existing TEXT PRIMARY KEY declaration. NULL/BLOB
metadata IDs could raise when sorted with text IDs. Exact text checks now occur
before sorting or exact-row reads for both relevant kinds. Original malformed IDs
remain unchanged.

The NULL cap control then exposed an independent accounting defect before the
retention scanner was reached. `WHERE id != ?` excluded NULL-ID rows from the
used-byte sum. The authored replay contained 5,371 bytes, counted only 4,405,
configured a 5,372-byte cap, and accepted a new attempt bringing the actual total
to 6,062 bytes. Both used-byte sums now use `WHERE id IS NOT ?`, counting every
other row while excluding only the exact row replaced by an upsert. Exact-cap
replacement controls cover ordinary and NULL-containing stores.

## Bounded repair and caller audit

`_run_rows` now obtains metadata first, rejects non-text row IDs, and admits each
relevant row through the existing `entry(..., max_bytes=MAX_ROW)` reader. That
reader enforces the existing 32 MiB body limit before materialization, checks the
stored SHA-256 and decodes strict JSON. The scanner then validates the existing
`EngineRun` or supported `SecondaryMatchSet` model, live project ownership and
stored/model identity. It derives references only from admitted records.

Any indeterminate row yields no engine-run eviction candidates for that scan.
There is no anonymous fallback group and no inference that an unreadable
reference is absent. Both current and legacy valid secondary sets remain usable;
healthy engine/pair retention and reference protection continue normally, subject
to the existing verified pre-retention backup.

The only caller of `_run_rows` is `_evictable_runs`; its only callers are
`prune_runs` and `make_room`. Ordinary history, match-set and cache readers are
separate and unchanged. Best-effort pruning skips an indeterminate scan. The cap
fallback may still use independently eligible derived generations under its
existing rules, but uncertain engine-run rows cannot supply space. Insufficient
safe space returns the existing recoverable `PT-ENRICH-LIMIT` before publication.

The original two-case UI regression still keeps its malformed-row fixture and
all publication/uncertainty assertions. Its setup now deliberately raises
`AttributeError` from pruning after asserting that the attempt row exists and the
write transaction has committed. This preserves the important post-write control
after malformed input itself no longer raises accidentally. No UI runtime changes
were made.

## Verification and receipts

All fixtures are authored, use real local SQLite and synthetic project inputs,
and execute no compared binary. Fixture teardown checks the original project
snapshot and artifact/run files remain byte-identical.

| Stage | Observed result |
| --- | --- |
| Initial 32-control meaningful baseline | 26 failed, 6 passed in 2.93 seconds |
| First repair with seven affected test files | 123 passed in 20.48 seconds |
| Added BLOB-ID boundary controls | 2 failed, 2 passed in 1.59 seconds before the guard |
| Added explicit-protection controls | 2 failed in 1.52 seconds before the skip |
| Broader run exposing NULL cap accounting | 1 failed, 170 passed in 21.11 seconds |
| Exact-cap/upsert controls | 1 failed, 3 passed in 1.64 seconds before null-safe accounting |
| Final 46 controls plus nine affected files | 175 passed in 18.92 seconds |
| Whole-tree `ruff check src tests tools` | Passed |
| `git diff --check` | Passed |

An earlier setup-only attempt used an invalid algorithm label in the authored
positive fixture; all 32 cases stopped at model construction. The fixture was
corrected before the meaningful baseline above. Its receipt remains separately
identified as `attempt-retention-fixture-initial`, with no production-fix credit.

The final selection was:

```text
tests/test_engine_run_retention_integrity.py
tests/test_secondary_runs.py
tests/test_enrichment_retention.py
tests/test_enrichment_storage.py
tests/test_prune_backup.py
tests/test_audit2_fixes.py
tests/test_evidence_attempt_storage.py
tests/test_secondary_store.py
tests/test_evidence_panel_service.py
tests/test_evidence_view.py
```

Runs used the source-isolated census environment with `python -I -B`,
`QT_QPA_PLATFORM=offscreen`, `-p no:cacheprovider`, dedicated `/tmp` fixture roots
and durable workspace log/JUnit receipts. The `verification/attempt-retention-*`
receipts preserve the meaningful red, intermediate, ID, protection, cap and final
runs. The storage-only observations are retained as
`retention-review-observations.json`, `retention-protect-observations.json` and
`retention-null-cap-observations.json`; the independent NULL-ID review is in
`retention-null-id-peer.log`. Completed passing fixture directories were removed;
failed reproduction inputs and receipts were retained.

This is not an atomic-save redesign or universal hostile-database hardening.
Concurrent noncooperating mutation between admission and deletion, aggregate
hostile database row/materialization budgets and unrelated reader defects remain
outside this slice. No complete-suite, native Windows or live-engine acceptance
is claimed for this branch. No remote refs, issues or pull requests were changed.
