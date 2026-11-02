# Backup completion before first prune (2026-11-02)

Source: `4bfc2c0442fad9dd0d670952e1b0657ae20b0d90`; exact baseline:
`1f284a19754f6822ff73ba1852d523cd48094d31`. This is the bounded follow-up to
PR #151 Qodo comment `4441152273`, independently of earlier post-link mutation
and directory-enumeration repairs. Independent review is pending for this source.

## Reproduction and contract disposition

The retained probe uses real `ProjectService.sample` SQLite databases and the
actual enrichment-retention and history-save callers. Only removal of a
`.sqlite3.part` name raises an injected `PermissionError`.

On the exact baseline, retention returned 8 and reduced 40 live rows to 32.
The final SQLite copy passed `integrity_check` and contained all 40 rows,
including every deleted row. Its staging name survived, and discovery refused
the final after clearing the process cache. This proves inconsistent completion
authorization, **not data loss**. The history caller independently rechecked
trust, kept all 5 prior rows plus its new save, and did not mark its session
blocked. Its surviving backup was likewise not discoverable.

The SPEC-07h amendment requires a trusted backup before deletion and describes
staging cleanup failure as unfinished publication. The clarified contract now
requires owned-stage removal and observed absence before returning success.
Ownership mismatch, metadata-read failure, failed unlink, or a replacement
observed after unlink raises `BackupError`. The final file and foreign staging
bytes are never removed. Existing best-effort cleanup before publication still
preserves the original error. All previous byte hashing and SQLite checks remain.

An absent stage after successful unlink but an unreadable absence check still
fails this attempt conservatively. A later normal discovery may validate that
now-unmarked, fully verified copy under the existing policy. This is not a lock
against arbitrary later filesystem mutation or a power-loss durability claim.

## Verification

Final regression file copied unchanged to a separate checkout of the baseline:
**7 failed, 10 passed (1.24 s)**. Failures cover success after unlink failure,
actual retention deletion, history session blocking, foreign-stage substitution
before and after unlink, and unreadable stage identity before/after removal.
The initial smaller red selection also had 5 expected failures.

Final bounded selection: **76 passed (5.77 s)** with the shared Python and
`QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests`:

```text
python -m pytest -q \
  tests/test_verified_backup_publication_admission.py \
  tests/test_verified_backup_byte_integrity.py \
  tests/test_verified_backup_reuse_filter.py \
  tests/test_verified_backup_stat_api.py \
  tests/test_prune_backup.py \
  tests/test_enrichment_retention.py \
  tests/test_history_bound.py \
  tests/test_enrichment_storage.py
```

Whole `python -m ruff check src tests tools` and `git diff --check` passed.
The narrower 38-pass selection overlaps these 76 checks and is not additive.
One intermediate author test assertion counted the unrelated pre-extension
backup while checking retention's two failed attempts; the assertion was
corrected to the retention label before the final baseline replay.

The regressions also verify that retrying after cleanup recovers creates a new
completed backup and permits normal retention, failed bytes remain unchanged,
history saves commit while all rows survive, and a failed history attempt is
not retried in the same session. Existing tests cover prior valid backup reuse,
foreign final preservation, timestamp collisions and normal successful cleanup.

## Evidence and limits

[`backup-completion-20261102.tar.gz`](backup-completion-20261102.tar.gz) contains
the probe, original JSON, original SQLite projects/backups, final regression
copy, baseline failures, bounded passing output, and a SHA-256 evidence index.
No full suite, native Windows, throughput, remote mutation or broad issue-closure
claim is made.
