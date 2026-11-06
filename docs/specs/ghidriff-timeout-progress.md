# Ghidriff timeout and progress diagnostics (SPEC-01a)

Status: **partial** — bounded observation, timeout guidance and execution receipts are implemented. Timeout-entry validation/presets and native Windows acceptance remain open in PT-TIMEOUT-1.

Scope: PT-TIMEOUT-1 from [the reported Windows timeout](../qa/ghidriff-timeout-20261106.md). This amendment is an additive process-observation contract. It does not change Ghidriff matching, argv, threading, raw-cache identity, the configured deadline, or publication acceptance. The expensive candidate processing and native Windows acceptance remain open.

## Process supervisor

`jobs.run_process` gains an optional `on_progress: Callable[[ProcessProgress], None]`. With no callback, existing callers retain their behavior. `ProcessProgress` is an immutable local record containing `elapsed_seconds`, `log_tail`, `stderr_tail`, `stdout_total`, `stderr_total`, and `last_output_elapsed_seconds` (null before any output). Each text snapshot comes from at most the last 16 KiB of its already bounded byte buffer; split UTF-8 uses replacement decoding. These snapshots are untrusted, unredacted child output for trusted internal observers only.

The supervisor thread delivers snapshots at most once per second during execution, plus a final snapshot after readers have drained. It never calls observers on a pipe-reader thread or while holding the output lock. Observers must return promptly and perform no blocking operations. Ordinary callback exceptions are isolated from supervision; cancellation, the fixed monotonic deadline, output limits and process-tree cleanup retain precedence. No unbounded event queue is introduced. Log activity never resets or extends the deadline. Interrupts still run cleanup.

`ProcessResult` adds `elapsed_seconds=0.0` and `last_output_elapsed_seconds=None` after its existing fields, preserving positional construction. Execution duration is measured from the existing supervisor deadline clock to the observed stop, before cleanup waits; pre-cancelled calls have zero duration. Output activity is expressed on the same clock and cannot be negative. Timing is operational evidence, not a change to analysis/cache identity.

## Backend observer and failure diagnostics

A pure `backend_progress.py` module classifies a bounded log snapshot into a small fixed vocabulary: starting Ghidra, importing binaries, analyzing binaries, matching functions, preparing match data, checking candidate function pairs (the upstream message says "Sorting functions"), and enhancing function/symbol details. Unknown output preserves the last observed stage. Select the latest recognized marker in the snapshot. Never emit arbitrary source lines, function names, paths, credentials or percentages through the progress channel. An observed marker is informational and cannot mark a comparison complete.

`backend.run_comparison` emits `JobEvent(stage='analysis-progress', message=...)` with a fixed-text summary of last observed stage, elapsed subprocess seconds, configured total limit and time since last output (or "no output yet"). Numeric progress stays null. Stage transitions may also emit a bounded fixed-text `analysis-stage` event for the log. The observer cannot fail the run or defeat cancellation. Existing bounded, fully redacted terminal log capture remains authoritative; there is no live forwarding of arbitrary child text.

Timeout errors retain the `PT-BACKEND: analysis timed out` prefix and include the effective seconds, observed elapsed seconds, last observed stage and the exact desktop recovery route: Analysis > Setup > Backend and desktop > Comparison timeout (seconds) > Save setup, then start a new run. Use a project-relative, run-owned diagnostics location. Never suggest an "unlimited" zero value or automatically change the budget. Per-function decompiler timeouts and whole-process termination remain distinct.

Before an actual Ghidriff launch, write a best-effort bounded `backend-execution.json` receipt in the new quarantine directory. Update it after the subprocess stops, before publication/cleanup can lose relevant state. Contract `patchtrace-backend-execution/1` records run ID, UTC start/stop timestamps, configured limit, monotonic execution duration, process exit/stop reason, last observed stage/output age, and known runtime versions. Versions are bounded safe identifiers; missing/unprobed versions remain explicitly unverified. A stopped subprocess is not a successful normalized comparison. No environment, absolute paths, raw log text or credentials enter this receipt. Receipt-write failure emits a fixed warning and cannot change analysis status or remove existing evidence. Cache hits and identical-input skips do not masquerade as a launched process. Prior committed results and quarantined evidence remain preserved.

UTC receipt timestamps bracket the launch attempt and supervisor return, including cleanup; the monotonic execution duration excludes cleanup. A supervisor exception without a returned result leaves process outcome/duration unverified.

## Desktop

Keep the worker-specific Qt relay in `ui_job_events.py`, preserving the existing `ui.py` seam-size ceiling. The relay owns no backend logic and forwards only events from the exact active worker on the GUI thread.

Treat `analysis-progress` as a status update: display its summary while the comparison worker is active, without appending each heartbeat to the log widget. Keep indeterminate progress, so an upstream substage's 100% is never shown as overall completion. Preserve Cancel/cancelling text. Reset progress-specific state at each job start and finish; unrelated jobs retain their existing elapsed display. `analysis-stage` and other events keep existing log behavior. Queued signals must not overwrite terminal error/cancel state after completion.

## Verification

Use real short-lived Python children to verify progress is delivered before exit, quiet children receive heartbeats, output snapshots remain bounded, activity does not renew the deadline, observer exceptions do not change exit/timeout, and descendants are terminated. Cover separate streams, output flooding, cancellation and no-callback compatibility. Test backend fixed-stage parsing, untrusted/split output, no secret forwarding, exact budget/receipt/error provenance, best-effort receipt failures, cache/identical behavior and old result preservation. Offscreen Qt tests must show progress while active, no heartbeat log growth, indeterminate percentages, correct reset, and cancellation/terminal precedence.

Full repository QA and hosted Windows checks remain separate gates. No synthetic child or fake Ghidriff test establishes that the owner's large comparison finishes or that its performance problem is repaired.
