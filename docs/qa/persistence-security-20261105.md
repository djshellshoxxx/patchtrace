# E1/E2 project lock identity admission — 2026-11-05

Isolated branch `work/persistence-security-20261105`, worktree
`/tmp/pt-independent-security-20261105`, starting at published PR #218
`afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Scope: `ProjectLock`, its SPEC-01
guarantee, and authored filesystem regressions. No qualification worktree,
process, log, native build or frozen PR #205 source was changed.

## Verified defects and repair

The prior constructor opened `.patchtrace.lock` and wrote its 4 KiB ownership
payload without verifying regularity, link count or the opened handle against
the current pathname. A preexisting hardlink to an unrelated file was accepted
and the ownership write replaced that file's bytes. A pathname replaced just
after `os.open` was accepted even though the acquired kernel lock then protected
a different inode. A FIFO reached buffered IO before refusal.

The initial four controls produced **3 failed / 1 passed**: hardlinked foreign
file, open-time pathname substitution and FIFO admission failed; ordinary
exclusive writer/reopen behavior passed. These failures occurred before the
production change. The tests use only authored files, with no native execution.

Admission now checks `fstat` and non-following pathname metadata for the same
regular, singly linked inode before buffered IO, then checks again after kernel
lock acquisition and before writing ownership metadata. Opening uses
`O_NONBLOCK` where available. Raw descriptors are closed when admission fails
before ownership passes to the buffered stream. Existing persistent-inode
release and kernel locking remain intact. SPEC-01 was updated before code.

Additional controls cover a link created during kernel acquisition, descriptor
closure on identity refusal, and ordinary persistent inode reuse/exclusion.
The descriptor refusal control requires no symlink/hardlink capability; POSIX
FIFO/flock cases and unsupported filesystem operations have explicit skips on
hosts without those capabilities. Linux execution reported no skips.

## Completed checks

Source binding checked with `PYTHONPATH="$PWD/src" python -c
'import patchtrace; print(patchtrace.__file__)'`; it resolved this worktree.
No shared editable installation was changed.

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_persistence_security_20261105.py tests/test_core.py tests/test_core_review_regressions_20261029.py tests/test_audit_core.py tests/test_gui_creation_retry.py tests/test_audit116_create_rollback.py tests/test_backup_sidecars.py`

**83 passed in 14.11 s.** Earlier overlapping selection: 53 passed in 8.87 s.
`python -m ruff check src tests tools` and `git diff --check` passed. No
serialized model/schema changes, new modules, dependencies or network calls.

## Remaining gates and limits

Independent security review is required before publication. Exact-head full
qualification remains owned by its existing coordinator; no competing full
suite was launched. Native Windows lock/filesystem and release acceptance were
not run here. A noncooperating process can still replace the pathname after
the last metadata check; this cooperative lock does not provide atomic
conditional pathname writes or a filesystem sandbox. The already documented
creation-cleanup pathname race and artifact-publication hardlink dependence
are unchanged.
