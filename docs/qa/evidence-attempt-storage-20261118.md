# Engine-attempt storage diagnostics — 2026-11-18

## Scope and source

The reviewed defect was a desktop evidence-retention omission. An engine could
fail, time out or be cancelled, and an actual SQLite write failure would silently
lose its `engine-run` record while the UI displayed only the original engine
failure. This did not admit a match set or turn the engine status into success.
A separate authored control confirmed that the next engine failure could say
“rz-diff result kept” even when the preceding successful engine's set was never
stored.

This repair changes only `src/patchtrace/ui_evidence.py`. The spec and twenty
authored Qt/SQLite controls are separate preceding commits. No backend, storage
schema, scanner configuration, rule exclusion or suppression was changed.

| Checkpoint | Commit |
| --- | --- |
| Baseline | `36e14051a4d36f5c66df0186f037a4905b01bf05` |
| Spec and authored regressions | `5f848aad` |
| Correct the new close-lifecycle test harness | `53821480` |
| Product source tested below | `7b4402a0d78dfd33852a79585a82374ce365104e` |

The source file SHA-256 is
`d72a7c806750abe131b545b339cfe0ce66bc370390d81c181c3f2ba3421108cf`.
`ui.py` remains unchanged at 3,071 LF-delimited lines, SHA-256
`1b5ea70d275441bd023d2178a8ea7b815add8bb00ff5ddc72014a5f9a92ef74e`.
The existing module index already assigns these callbacks to the evidence UI;
there is no new module or host seam.

## Behavior

Publication exceptions now produce a bounded class-only diagnostic, and stale
project/pair/run refusals also produce an explicit unsaved-attempt indication.
The engine row, Copy details and final run summary retain it after normal
aggregation, reload or scheduler-level failure. The original engine status,
error code, reason, timing and clipped stderr remain available. Controller
outcomes still discard full run and match-set objects. Diagnostics are at most
100 characters per secondary engine and are cleared on a superseding run or
project lifecycle reset.

The “result kept” suffix now depends on successful publication for the current
request. An `ok`/`cached` transient status is insufficient. Already stored sets
remain unchanged when another attempt fails, and unsuccessful outcomes still
strip any partial match set before publication. There is no automatic retry or
duplicate publication. Existing generation/request checks and owner-thread
storage calls remain in place.

The UI reports uncertainty about a successful engine's publication without
promising that a thrown exception rolled back every earlier write. This change
does not make the underlying multi-write publication atomic. The retained UI
details are transient and explicitly do not replace a durable attempt record.

## Reproduction and validation

The independent original probe uses a real sample-project SQLite connection
with `PRAGMA query_only=ON`, real `persist_outcome` and an actual `MainWindow`.
Its bytes remain unchanged:

| Probe | SHA-256 |
| --- | --- |
| `test_failed_attempt_retention.py` | `b8f3b937acbea15a5f89d604c4bf041bbb13f7d47acaa309e9e867a2a7c41781` |
| `test_result_kept_external.py` | `8154169950711fb48b89f919dfed0c346842c27d7ebe4c96098eec478f93db54` |

| Run | Actual result | Qualification |
| --- | --- | --- |
| Original independent failed-attempt probe at baseline | 3 failed, 1 positive, no setup errors | Failed/cancelled/timeout attempt retention failures were hidden. |
| Independent retained-result wording probe at baseline | 1 failed, 1 positive in 0.98 s | Unsaved successful output was called kept; actual saved output remained the positive. |
| Committed spec/tests plus both external probes on unchanged UI source | 16 failed, 10 passed in 5.15 s | Initial test-first checkpoint. |
| First repair iteration | 2 failed, 24 passed in 5.22 s | One missed immediate row refresh and one incorrect new test call to `set_service(None)`; not a passing run. |
| Corrected tests on detached pre-fix source `53821480` | 16 failed, 10 passed in 5.68 s | Correct close harness, unchanged behavioral oracles and unchanged UI baseline. |
| Focused repaired run | 26 passed in 5.20 s | All new controls and both unchanged external probes. |
| Exact committed source, affected gate | **156 passed in 22.49 s; no skips** | Evidence UI/host/service/view/table/performance, secondary evidence, global tooltip suites and both external probes. |

The close harness now closes the real service and invokes the existing
no-project lifecycle hook. `MainWindow.set_service` accepts an actual service;
passing `None` was a test error. The first raw test file, failed intermediate
log and the explicit harness-correction patch are retained. An earlier test
fixture import was changed to an explicit re-export to satisfy Ruff's F811
check; the preceding raw authored test file is retained as well.

The twenty new controls cover actual read-only SQLite refusals, healthy failed
attempt writes, project/pair/run mismatches, final aggregation and copied
details, prior stored-set preservation, misleading kept wording, class-only
exception text, scheduler failure, stale generations, missing requests, and
superseding run/project resets. Engine records and match sets are authored
data. No comparator runs in these new controls.

All pytest runs use Python 3.12.14 from
`/workspace/scratch/3a6632a6e5ff/venv/bin/python`,
`QT_QPA_PLATFORM=offscreen`, and absolute source-pinned `PYTHONPATH` entries for
that run's `src` and `tests` directories. The exact-source gate uses
`/workspace/scratch/c7a9e8d98848/evidence-attempt-storage`. This matters because
the shared virtual environment's editable installation points to an older
checkout. Existing affected tests include authored Python fake engines;
those are not native comparator or target execution.

Configured `ruff check src tests tools` and `git diff --check` pass. The separate
unsuppressed strict S110 scan still exits 1 with **12** remaining diagnostics.
The repaired silent catch is absent because it now reports the failure; the
remaining optional-settings catch in this UI file is still reported. This is
not a clean security-lane claim. The full residual static review and its
historical-to-current mapping are separate work.

## Retained evidence and limits

The adjacent `evidence-attempt-storage-20261118.manifest.json` enumerates and
hashes every payload in `evidence-attempt-storage-20261118.evidence.zip`. It
includes the original independent probe/receipts, source snapshots and patches,
test-first and intermediate failures, final logs/JUnit, command/source
provenance and unchanged strict-scan output. Raw working receipts are under
`/workspace/scratch/c7a9e8d98848/qa/evidence-attempt-storage` and the original
independent receipts under `qa/security-s110-independent`.

This packet establishes the authored-data desktop publication/diagnostic
behavior on Linux with offscreen Qt. It does not certify Windows packaging,
native engine behavior, matching accuracy, durable fallback storage, arbitrary
filesystem races or atomic multi-write storage. No target binaries, frozen
corpus/outcomes, remote branches or releases were changed. Independent root
review is still required before integration.
