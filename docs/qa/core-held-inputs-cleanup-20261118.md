# Input cleanup preserves the primary operation failure — 2026-11-18

## Source and result

Corrected exact source **9740860928c7911e6fa975528db1f7fa5ca1940b** passes **318
checks**, zero failures/errors/skips, in 6.02 seconds. All **301 loaded PatchTrace
modules** match that Git source; no drift occurred. Full normal Ruff over
`src tests tools` and `git diff --check` pass. Independent review of the corrected
source is a separate root/peer gate.

| Role | Commit |
|---|---|
| Initial reviewed source / preserved first QA | `b85a0cf7bf135e9431677737613000707553b192` / `c791ed4e8a9019541c6789f3cd025d963b3ae8ec` |
| Cleanup specification and failing controls | `072c36965b3807547adb6895aff1259a1599caad` |
| Narrow correction | `9740860928c7911e6fa975528db1f7fa5ca1940b` |

The retained `codex/core-held-inputs-20261118` branch remains in
`security-residual-qa`. Only `src/patchtrace/ingestion.py` changes in production
in this follow-up: an import and the final temporary-stage cleanup handler.
No KB/package/native/jobs/schema or other core service/store behavior changes.

## Reproduced boundary and correction

The independent reviewer showed that a refused `.input-*` unlink in `finally`
replaced an active `InputReadError('cancelled')` with `PermissionError`. The
operation still refused and did not admit an artifact. This is exception
precedence and retained-cleanup evidence, not an unsafe admission or path
fallback finding. The old unguarded unlink predates the neutral interface; the
new original-reason contract exposes that behavior.

The correction captures the active exception before attempting the same cleanup.
If that attempt raises OSError, a pending primary exception continues unchanged
and receives a fixed bounded note: temporary bytes may remain. The note contains
no raw secondary exception text or path. An unlink failure without a primary
exception still raises; ordinary input/storage error mapping is preserved.
Cleanup touches the same attempt's existing stage path and acquires no additional
cleanup authority. It does not report removal as successful, delete foreign
files, retry unrelated paths or claim arbitrary namespace-race protection.

A valid-copy unlink failure remains observable. If exclusive artifact publication
already occurred, the original ownership ledger still records that destination
for the existing caller rollback. Successful cleanup adds no false retention
note. Cancellation, limit refusal, ordinary failure and KeyboardInterrupt keep
the same primary object when cleanup is refused. The portable tests assert
retained temporary files, unchanged foreign evidence, closed borrowed readers
and no returned/admitted artifact on failure.

## Immutable red and green evidence

| Run | Result |
|---|---|
| Original independent review of b85 | 1 failed / 51 passed; unchanged original packet retained |
| Spec-first replay at clean `072c3696` | 6 failed / 15 passed, 49 exact imported modules, no drift |
| First uncommitted correction, exact source bytes retained | 21 passed |
| Clean committed `97408609` affected gate | 318 passed / 0 skips, 301 exact imported modules, no drift |

The seven new controls precede the source correction. The independent fourteen
controls are copied byte-for-byte; their SHA-256 remains
`b7b5ad118cfd8b4b15fd6e1276d3dff0136c21f7b8df555b21db386fda49c1ed`.
Original peer log/XML/receipt, report and its complete sealed evidence archive
remain in `original-peer/`, with hashes checked against the untouched external
originals. The initial core 56-payload packet also remains unchanged. No original
failed assertion or receipt was rewritten.

The exact affected selection includes all 297 initial core neighbors plus the
seven new cleanup controls and fourteen unchanged independent controls. The
source pin, full argv, imported paths/hashes, original and current XML, and all
source/spec/test snapshots and diffs are retained. The first-green source equals
the corrected committed source. Red and final test bytes are identical.

## Limits and reproduction

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, absolute
`PYTHONPATH=<checkout>/src`, `QT_QPA_PLATFORM=offscreen` and the exact repository
root on sys.path for existing test imports. `affected.command.json` records the
21-file invocation; `affected.imports.json` checks each loaded project module
against canonical source bytes. Raw receipts remain under
`qa/core-held-inputs-cleanup`. The runner inherited the corrected exact-root
setup from the already sealed first packet, without modifying that original.

These are authored PE, POSIX descriptor and real SQLite controls with injected
cleanup refusal. No native Windows cleanup/share-mode behavior, package worker,
held rooted reopen, KB propagation, durable package facade, frozen corpus,
target execution, network or release was exercised or qualified. The first
neutral slice's cooperative syscall/COMMIT and later aggregate read-work limits
remain unchanged. Root independently reviews and selectively integrates the
append chain after this handoff.

## Sealed packet

The [archive](core-held-inputs-cleanup-20261118.zip) contains 40 verified payloads
(413,068 uncompressed bytes; 134,849 ZIP bytes).
Archive SHA-256: `5ffd0899d92cd847205dc70ab6902131ce56514a0ee56bd1307c795619a0eb37`. The
[manifest](core-held-inputs-cleanup-20261118.manifest.json) records each payload hash and size.
