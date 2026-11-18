# Core creation identity and checkpointed reopen — 2026-11-18

## Exact source and result

Source **441c47c2262603555aa77c11e63fedcce11ba502** passes **512 checks**, with
zero failures, errors or skips, in 10.12 seconds. The affected run records 462
source-pinned parent imports with no drift. All five inspected headless child
commands use the exact checkout's absolute `PYTHONPATH`. Full normal Ruff over
`src tests tools` and the source-chain diff check pass. Root independent review
and integration remain separate from this author receipt.

| Role | Commit |
|---|---|
| Integrated base | `7b5f558fb1a51d45427648c39c15995ab3697e2c` |
| Original read-only design | `3e4abd88df010c8dde95ec1661b0a877e9e39e82` |
| Attributed design port | `1102f1baba94a8ce3dd5bc12df52e69a2595e995` |
| Specification and failing controls | `cb26b38de018612e76f87c544fb8b1dfe70acbf2` |
| Two-file implementation | `441c47c2262603555aa77c11e63fedcce11ba502` |

Production changes are limited to `ProjectService.create/open` in `service.py`
and `ProjectStore.load` in `persistence.py`, plus their imports: 38 inserted and
12 removed lines. No schema, migration, KB, package, native, CLI, worker, scanner
or recovery-policy source changes are included. No module is added. The
existing registered core held-input specification and architecture specification
describe the new optional behavior before implementation.

## Behavior and ownership

An explicitly supplied creation ID is validated through the existing strict
`Record.id` contract before store creation, source access or held-reader checks.
The actual project model and first committed snapshot receive that identity.
Omission keeps default UUID generation and old injected call shapes. Historical
bounded string IDs remain supported; this is not a canonical-UUID migration.
A chosen ID never grants reuse, adoption or deletion authority over an existing
committed project. The existing complete hash, PE, aggregate, path and ownership
checks remain in force. First-save cancellation preserves existing retry rules;
exceptions after commit preserve the committed project and its copies.

An explicit open/load callback is the original operation's checkpoint. It checks
before store acquisition and around snapshot/aggregate validation, then reaches
existing artifact/raw/PE verification and interrupted-run recovery save. Existing
positive reads charge their actual bytes, and verification cache hits check with
zero additional positive-byte charge. Read-work accounting remains separate from
decompression output allowances. No callback is retained on the project/service/
store or invoked after a successful recovery save commits.

`maintenance=False, recover_interrupted=False` leaves a healthy project's
snapshot, history and raw evidence unchanged. Both flags are required: the
existing default recovery behavior remains enabled. The lock-holder record is
still written; this is not a physically read-only SQLite mode. Omitted options
preserve existing `load()` and `_verify_files(project)` injection shapes.

Once `ProjectStore` has returned successfully, a failed open closes that acquired
store on ordinary exceptions, neutral cancellation/limit errors, KeyboardInterrupt
or SystemExit. If close also fails, the original exception object survives with
a fixed bounded note that resources may remain open. The note exposes no raw
secondary message or path, and does not claim successful cleanup. No creation
rollback or deletion is introduced. An ordinary successful service's explicit
close still exposes its own errors. An interrupt inside the store constructor
before it returns is outside this handler and outside these closure assertions;
root is examining that existing adjacent boundary independently.

## Red, intermediate and final evidence

| Run | Exact result and meaning |
|---|---|
| Original external probe at `1102f1ba` | 4 failed / 1 passed; actual acquired SQLite connection and lock leak on BaseException, and secondary-close exception masking |
| Committed specification-first gate at `cb26b38d` | 41 failed / 6 passed, zero errors/skips; 55 pinned parent imports, no drift or execution attempts |
| First uncommitted implementation | 47 passed; both source files and invocation retained, without a complete import manifest |
| Initial full normal Ruff | I001 import-format failure only, retained unchanged |
| Corrected import formatting | Full normal Ruff passed; source ASTs equal the first-green source, with service import formatting explicitly different |
| First affected gate at `441c47c2` | 510 passed / 2 runner-policy refusals; the two existing headless-import children were blocked before running |
| Corrected affected gate at the same source | 512 passed / 0 skipped, 462 pinned parent imports, no drift or prohibited attempts |
| Exact committed normal Ruff and diff check | Both pass; commands, source and outputs retained |

The 42 authored integration cases precede production code. They cover actual
preallocated create/reopen, denied selected-source pathname access, strict early
ID refusal, default UUID/injection compatibility, existing-project refusal,
new/empty/zero-byte first-save cancellation and retry, and unknown committed
outcome preservation. Open/load controls cover queued/running non-recovery reads,
actual read accounting and cache checks, no callback retention, neutral reason
identity, acquired connection closure, primary/cleanup precedence, corrupt-copy
refusal, pre-COMMIT recovery cancellation and no callback after recovery commit.

The unchanged five-case external probe is
`test_open_failure_boundary.py`, SHA-256
`715353bb34f604295abb1d04d1e286d144f01568143d5118ed75e4d663432c6c`.
The 14 prior independent held-input controls are also replayed unchanged;
their source SHA-256 remains
`b7b5ad118cfd8b4b15fd6e1276d3dff0136c21f7b8df555b21db386fda49c1ed`.
No assertion or original failure was rewritten. Red/final test-byte identity,
canonical Git source snapshots, imported module hashes, full argv and all five
JUnit receipts are verified by the accompanying seal receipt.

## Harness correction and retained files

The first affected runner permitted three existing CLI executions but omitted
two existing headless-import commands. Its two failures are harness refusals,
not failed product assertions. `run_affected.py`, its raw output/XML and original
receipt remain unchanged. `run_affected_v2.py` adds only those inspected exact
command strings to the allowed set and checks argv length before reading the
existing CLI verb. Every child still requires the same interpreter and absolute
checkout source pin. There is no network allowance or engine/target execution.
`runner-correction.json` records both runner hashes and exact additional bodies.

The audit records parent events only; it does not intercept child syscalls or
claim a full child import manifest. The children are the inspected existing
headless CLI and import tests, with their original assertions. This is a local
source gate, not a native backend, Windows or package qualification run.

The first failed affected run's owned directory remains at
`/tmp/core-admission-affected-95juu3ud` (37,916,672 allocated bytes; sparse logical
size 1,108,304,359 bytes). The successful corrected run removed only its own
temporary directory after pytest, source and audit checks passed. Earlier red
and first-green runners used their existing temporary-directory cleanup; their
raw failures, probe bytes, source and bounded observations remain retained.
The archive does not copy the large disposable fixture directory.

## Reproduction and limits

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, absolute
`PYTHONPATH=<checkout>/src:<checkout>`, `QT_QPA_PLATFORM=offscreen` and
`PYTHONDONTWRITEBYTECODE=1`. `affected-v2.command.json` contains the complete
28-file selection. A replay needs a new receipt label and an appropriately
explicit checkout path in the retained runner; do not overwrite the original
logs or probe observations. Raw receipts remain under
`qa/core-admission-checkpoints`. The original design packet remains separate.

The evidence uses authored PE bytes, operation-owned portable descriptors and
real SQLite. OS calls, SQLite and JSON validation remain cooperative checkpoint
boundaries, with no hard preemption guarantee. Legacy maintenance, enrichment
publication and unrelated reads do not gain checkpoint coverage. Durable package
intent/provenance, an expected-ID association check, held-origin recovery refusal,
unknown-outcome reconciliation and package exposure remain unimplemented here.
No new permission to reopen expired leases or delete a committed/foreign project
is added. Native Windows locking/FDI/process handoff, network, live backends,
frozen corpus outcomes and complete package acceptance were not exercised.

## Sealed packet

The [136-payload archive](core-admission-checkpoints-20261118.zip) contains 2,898,984 uncompressed bytes (1,195,401 ZIP bytes), including 54 canonical Git snapshots.
Archive SHA-256: `89970d49ed048ee63c22c88601831c0a39aca96f0147edcfd7398944cfcc43d6`. The [manifest](core-admission-checkpoints-20261118.manifest.json) records every payload hash and size.
