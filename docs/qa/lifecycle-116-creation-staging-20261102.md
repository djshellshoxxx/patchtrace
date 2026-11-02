# Issue 116 creation staging repair — November 2, 2026

Source: `86c5b23f9441d4f6d947fc4a59fe6e3ac53c06ac`, tree
`d5f565653fc884eade6da87d7390d140d846a157`, with initial checkpoint
`0e04915213139ba8cdb8d0f4d9b5a7f5b5e234e1`, based on
`ce6002ec36732f2d27e8e6233b8fbe305eeb6112`. The earlier profile/inspection
repair has its own receipt. Original issue:
<https://github.com/djshellshoxxx/patchtrace/issues/116>.

Fresh original-source reproduction with malformed older/newer synthetic PE
inputs left a lock/artifacts directory (and an older artifact for malformed
newer), so corrected input still failed the real NewProjectDialog nonempty-root
check. The desired-behavior controls were red before this repair. A later
publication-collision control also failed: the ingestion check followed by
`os.replace` overwrote a foreign file introduced at final publication, and
creation unexpectedly succeeded. All input bytes in these tests are synthetic;
none were executed.

Generic creation now prepares both immutable copies and saves a validated first
snapshot in a private temporary project before opening the destination. The
destination is touched only after that preparation succeeds. Publication uses
exclusive final artifact creation; existing artifacts are reused only after
identity, exact content and PE verification. The first destination snapshot is
saved after publication. The normal identical-input result remains unchanged.

Later-failure cleanup runs while the project lock is still held. It checks the
root, lock, database and artifact identities, refuses cleanup of any committed
snapshot, and removes only completed files created by this attempt whose content
version still matches. Foreign entries, pre-existing artifacts, replaced paths
and unverified incomplete bytes remain. Only private staging is recursively
removed. The persistent lock file remains under the existing lock contract.
Cleanup failure releases the lock and existing snapshotless-database service
retry remains supported. An exception after a committed first snapshot preserves
a reopenable project.

Independent review of the first checkpoint found a constructor failure path that
closed the lock before deleting the destination database. Five fresh controls
were red: a competing lock could be acquired during unlink; an initialization
interrupt was not cleaned up; replaced database/root bytes were deleted; and an
unlink failure replaced the intended storage error. The follow-up closes SQLite,
then verifies the owned root, lock and database plus snapshotless state before
unlinking, and releases the kernel lock in `finally`. An additional review
observation exposed a named-lock identity that could differ from the held
descriptor; its desired-invariant control was also red. Both constructor and
publication now anchor lock identity to the held descriptor.

Author validation (shared Python, offscreen Qt, `PYTHONPATH=.:src:tests`):

```text
pytest -q tests/test_creation_116.py tests/test_service_storage_audit.py
  tests/test_core.py tests/test_ingestion_core10.py
  tests/test_acquisition_quarantine.py tests/test_acquisition_workflow.py
  tests/test_ui_kb_create_cancellation.py tests/test_ui_kb_current_project.py
```

**120 passed in 4.61s** at the final source. Whole-repository Ruff and
`git diff --check` passed. The initial checkpoint had **111 passed in 4.98s**;
these overlapping runs are not a combined total.
Controls include malformed older/newer corrected GUI retry, absent/existing-empty
destination preservation on each staging failure, interruption, collision,
pre-existing/replaced artifact and root preservation, injected root/lock identity
changes, held-lock cleanup, cleanup failure/retry, incomplete-byte retention,
after-commit failure, private cleanup failure, constructor interruption/cleanup
failure, replaced constructor paths, newly committed/foreign database content,
and held-descriptor lock binding. The native root-rename control
can be explicitly blocked on platforms that prohibit renaming an open project;
the injected identity controls remain mandatory. This author run had no skips.

Independent review at `86c5b23` reported no remaining blocker: **123 passed in
5.10s** (the author's 120 plus three independent controls), then one actual Linux
pre-capture lock rename/replacement control passed in **0.26s**. The reviewer
confirmed held-lock constructor cleanup, same-inode/same-size/restored-mtime
foreign artifact preservation, reopenability after postcommit KeyboardInterrupt,
and refusal of actual lock replacement before publishing artifacts. Ruff and
diff checks passed. The coordinator owns the hash-bound independent receipt;
these results are not native Windows acceptance.

This receipt does not claim the broader issue is closed. Later publication failures may still
leave a failed-attempt directory rejected by the unchanged GUI nonempty-root
guard; a strict explicit GUI recovery contract is separate work. No full combined
suite, native Windows, native engine, performance or release acceptance is claimed.
No remote mutation was performed by this worker.
