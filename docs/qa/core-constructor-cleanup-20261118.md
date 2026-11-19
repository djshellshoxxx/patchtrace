# Store constructor interruption and cleanup precedence — 2026-11-18

## Exact source and result

Corrected source **63ebc42746fbfbded311084288a339f26ed08d8c** passes **562
affected checks**, with zero failures, errors or skips, in 10.13 seconds. The
receipt verifies 463 parent imports against the exact source and records no
drift or prohibited execution. Five inspected headless commands use the same
interpreter and absolute checkout source pin. Full normal Ruff and source diff
checks pass. Independent final review and integration remain root-owned gates.

| Role | Commit |
|---|---|
| Previous source / immutable original QA | `441c47c2262603555aa77c11e63fedcce11ba502` / `fa4bebbb7a5a7095d4764066ffb73cd73cf85499` |
| Additional specification and regressions | `f40d14c1970bf45efba4de448c00c8c49b463ae7` |
| Constructor cleanup correction | `63ebc42746fbfbded311084288a339f26ed08d8c` |

Only the existing exception handler of `ProjectStore.__init__` changes in this
follow-up: 14 inserted and 10 removed lines. The prior optional creation ID and
open/load checkpoint implementation, all other persistence functions, generic
`close()`, discard helper, schema, KB/package/native interfaces and ownership
policy remain unchanged. The original 136-payload checkpoint archive remains
byte-identical with SHA-256
`89970d49ed048ee63c22c88601831c0a39aca96f0147edcfd7398944cfcc43d6`.

## Independently reproduced boundaries

The root reviewer raised KeyboardInterrupt and SystemExit from an actual SQLite
Connection subclass at `PRAGMA quick_check`, after the constructor had acquired
its lock and connection. The original Exception-only handler did not run. The
primary exception survived, but the connection and lock remained acquired;
project/database/artifact bytes were unchanged. An ordinary neutral error was a
positive cleanup control. This occurs before `ProjectService.open` receives the
constructed store, so the previously repaired owned-open handler cannot act.

A separate six-case probe then raised PermissionError immediately before or
after an actual connection close. The original cleanup replaced both an
InputReadError and the established SQLite-to-storage-error mapping with that
secondary exception. Healthy cleanup preserved the intended result. These are
resource cleanup and error-precedence defects; neither reproduction admitted a
bad artifact, adopted a foreign project or deleted existing evidence.

## Correction and preserved authority

The constructor's existing protected initialization region now catches
BaseException. It retains the exact connection-close, positively owned
new-database discard, and final store-close ordering. A cleanup failure does not
skip the existing final cleanup attempt or create another deletion route.
Generic close and the discard helper are unmodified.

Non-SQLite primary exception objects, including neutral stops and interrupts,
propagate unchanged. A primary SQLite error still produces the same storage
ValueError and retains the original cause. If cleanup also raises, the outward
failure receives one fixed bounded note: resources or files may remain. The note
contains no secondary exception message/path and does not assert cleanup success.
The constructor may therefore retain an uncertain connection, lock or owned new
file when cleanup itself refuses; the note makes that uncertainty observable.

Real creation controls exercise new, preexisting zero-byte and current empty
databases. Normal cleanup removes only the positively owned new file; retries
preserve their original bytes and inode, then successfully create and reopen.
Committed project files and foreign analyst files remain unchanged. An injected
discard interruption preserves the owned file, completes the ordinary final
resource cleanup and retains the original operation refusal with a note. Unknown
database refusal retains its original no-reuse behavior and releases the lock.

## Preserved red and green evidence

| Run | Result |
|---|---|
| Root original at exact `441c47c2` | 2 failed / 1 ordinary-neutral positive, 14 exact imports, no drift |
| Additional probe plus unchanged root controls at `fa4bebbb` | 6 failed / 3 passed, 14 exact imports, no execution attempts |
| Committed spec-first gate at `f40d14c1` | 31 failed / 19 passed, zero errors/skips, 52 exact imports |
| Exact corrected focused gate at `63ebc427` | 50 passed, zero skips, 52 exact imports |
| Exact affected gate at the same source | 562 passed, zero skips, 463 exact imports |

The 41 new repository cases precede source code. They cover interruptions,
neutral/ordinary/SQLite failures before connection return and after SQLite
acquisition; creation/retry ownership and healthy subsequent admission; connection
and lock cleanup failures before/after actual close; discard interruption; and
unchanged foreign database refusal. Test cleanup bypasses only the injected
refusal after product behavior has been observed, preventing the probes themselves
from leaving live resources. Product assertions do not count that test cleanup
as successful application cleanup.

The root probe remains byte-for-byte unchanged, SHA-256
`e85126984ac9ddda43950387feee6cc4d7d1e79437595999cc3ee5831fb7428e`.
Its complete original command/log/XML/import/guard/observation records are copied
without changes under `original-root/`, with an exact source/copy ledger. The
six-case cleanup probe also remains unchanged from its first failure. All replay
observation directories are fresh; no original failure or assertion was edited.
The existing five acquired-open and fourteen held-input independent controls
are included unchanged in the 562-case gate.

## Reproduction, storage and limits

Raw receipts are under `qa/core-constructor-cleanup`. The exact 31-file invocation
is in `affected.command.json`. Use the shared venv interpreter, absolute checkout
`PYTHONPATH`, `QT_QPA_PLATFORM=offscreen`, `PYTHONDONTWRITEBYTECODE=1` and a fresh
receipt label. The retained runner differs from the original checkpoint runner
only by separate observation paths and the owned temporary-directory prefix.
Its child policy and audit limitations are unchanged: five inspected headless
children, parent audit only, no child-wide syscall or full import-manifest claim.

Failed-run temporary directories remain retained with their allocated sizes in
the receipts. The focused and affected successful directories were removed only
after source, pytest and audit checks passed. No failed fixture directory was
removed by this follow-up. The archive retains bounded observations and raw
receipts rather than duplicating the sparse affected fixture tree.

The guarantee is limited to the existing protected initialization region after
the project lock has returned. It does not change partial acquisition inside
`ProjectLock`, generic close failure policy, filesystem namespace races, or hard
preemption of SQLite/OS calls. This is portable authored PE/real SQLite evidence;
native Windows locking, package/FDI/process transfer, durable provenance/recovery,
frozen outcomes, target execution and network were not exercised. Durable package
admission and unknown-outcome reconciliation remain separately unimplemented.

## Sealed append packet

The [140-payload archive](core-constructor-cleanup-20261118.zip) contains 1,241,814 uncompressed bytes (313,930 ZIP bytes), including 49 canonical Git snapshots.
Archive SHA-256: `11e14a85ac5dbd4f02abd610d274c4cf3e7766b08c3c52223b38e574319d5d6f`. The [manifest](core-constructor-cleanup-20261118.manifest.json) records each payload hash and size.
