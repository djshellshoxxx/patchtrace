# P1: recurring Windows Ghidriff comparison times out

Reported: 2026-11-06. Status: **OPEN — user-reported failure; investigation and Windows acceptance required.**

The owner's usual two-file comparison ended with `PT-BACKEND: analysis timed out; increase the configured timeout and retry`. Both initial binary analyses completed. The strongest performance lead is a structural correlator producing **2,161,955 entries**, followed by prolonged result processing. Extending the outer deadline is an available interim retry option; it does not establish that the underlying performance issue or incomplete decompilation is fixed.

This record is based on the supplied `failure.txt`, `analysis.log`, and `ghidriff.log`, and source inspection of PatchTrace `main` at `dc53b529560453e84cf45e356a40432ff3fc6725`. The owner's installed PatchTrace build and effective timeout were not supplied. No native reproduction or runtime repair is claimed by this documentation change. Keep this item visible near the top of [the delivery tracker](../../tasks/todo.md).

## Evidence and limits

The timestamps below are exactly as logged on **2026-11-05**; the logs do not identify their timezone. Line references refer to the original supplied attachments, which are not committed here.

| Recorded event | Time / value | Source | Meaning |
| --- | --- | --- | --- |
| Ghidra starts | 20:47:23.720 | `ghidriff.log:2` | Beginning of the observable backend timeline |
| Runtime and engine | Ghidra 12.1.4 PUBLIC; `VersionTrackingDiff` | `ghidriff.log:14,18` | Installed Ghidriff revision and actual Python/JVM versions remain unknown |
| Execution settings | `threaded: False`; one worker; `bsim: True`; `no_symbols: False` | `ghidriff.log:27–46` | Preserve deliberate sequential execution while investigating |
| Both targets load | `x86:LE:64:default:windows` | `ghidriff.log:57–58,123–124` | No target architecture mismatch is demonstrated |
| Older / newer analysis complete | 20:54:58.876 / 20:59:26.564 | `ghidriff.log:266,326` | Initial analysis finished for both files |
| BSim completes | 109.8506 seconds | `ghidriff.log:366` | Not the largest visible delay |
| StructuralGraphHash completes | 2,161,955 entries; 155.3472 seconds; `one_to_many: True` | `ghidriff.log:387–390,411`; `analysis.log:378–381,402` | Strong lead for excessive ambiguous candidate expansion and downstream processing |
| Generating matches JSON | 21:11:07.405 | `ghidriff.log:416` | Result preparation is already expensive |
| Sorting functions | 21:12:40.539 | `ghidriff.log:419` | Last stage message before a long quiet interval |
| Enhanced-symbol (`esym`) lookups start | 21:41:22.294 | `ghidriff.log:420` | **28 minutes 41.755 seconds** after the "Sorting functions" message; the installed revision and operation-level timing remain unverified |
| Enhanced-symbol (`esym`) lookups complete | 72/72 at 21:41:44.841 | `ghidriff.log:438` | **54 minutes 21.121 seconds** after Ghidra start; this substage's 100% is not overall completion |
| Outer timeout | No timestamp or effective limit supplied | `failure.txt:1` | Confirms a backend timeout; does not establish that this run used the 3,600-second default |

The recorded input names are:

- Older: `86926f78fad0d8c75c7ae01849bf5931f4484596d28d3690766f16c4fb943c19.bin`
- Newer: `3691adcefc6da67eedd02a1b1fc7a21894afd83ecf1b6216d303ed55a5f8d129.bin`

These identify the recurring pair from this run (`ghidriff.log:16–17`). They are different content-addressed filenames, not evidence of a same-byte comparison. Original filenames and the binary bytes were not supplied, so do not identify this pair as CLFS, 7-Zip, or another earlier fixture, or claim to have independently verified their SHA-256 values. The 2,161,955 count is an upstream correlator count, not two million validated distinct function correspondences.

Original attachment receipts (SHA-256 of the exact uploaded bytes):

| Attachment | SHA-256 |
| --- | --- |
| `failure.txt` | `3d496f5a55fd9105cccf5180511414448a290a5e84727905f199ad91874ba82b` |
| `analysis.log` | `9e8793323c3162ba4bcf4329548494f863f04722b9c8fc1c3c9a775bbc3e8f35` |
| `ghidriff.log` | `fea3aa5d2a9cf1cc72e89ef7da41be11c92799a4c903121c2e0a50b8971dddc7` |

## Timeout options available now

### Desktop: retry with a larger finite budget

1. After the failed run has stopped, open **Analysis → Setup** (or the Setup toolbar action).
2. On **Backend and desktop**, find **Comparison timeout (seconds)**.
3. Set **7200** for a two-hour diagnostic retry, or **14400** for a four-hour run when a longer budget is intentional.
4. Select **Save setup**, then start a new comparison. Retain the failed run and its logs for comparison.

Current source defaults to **3600 seconds** and accepts **10–86400 seconds** in this control. These are wall-clock limits for the Ghidriff subprocess, not guarantees of completion. The value is saved as `backend/timeout`, read into `BackendConfig.timeout_seconds`, and passed to `jobs.run_process`. Changing a saved setting does not extend an already-running subprocess. A value of zero is not an unlimited mode.

Source: [Setup and run configuration](../../src/patchtrace/ui.py), [backend configuration and invocation](../../src/patchtrace/backend.py), [process deadline](../../src/patchtrace/jobs.py), and [settings help](../help/14-backend-and-desktop-settings.md). The installed package must be checked against this source baseline if its controls differ.

### CLI and developer paths

- The existing **`series create ... --run --timeout 7200`** route accepts a per-pair Ghidriff budget and passes it into `BackendConfig`; use `14400` for four hours. It requires **3–8 builds**, so it is not a two-file desktop retry or resume command. Preserve explicit input orientation, runtime paths, and symbol policy. See [CLI registration and series execution](../../src/patchtrace/cli.py).
- **`backend selftest --timeout 7200`** also exists, but requires a usable bundled runtime, older/newer files and a real `--expect-function` value. It creates a new project; an explicitly supplied `--project-dir` must be new or empty. It disables raw-cache reuse and can fail its expected-function check even after analysis finishes. Do not substitute it for an ordinary retry. There is no general baseline **`patchtrace run --timeout`** command in this source; an existing-project comparison CLI would be a new feature. See [backend selftest](../../src/patchtrace/backend_cli.py).
- A direct API caller can set **`BackendConfig(..., timeout_seconds=7200)`**. The backend requires a positive integer. Do not globally raise the default just to hide this regression.
- The desktop setting does not control secondary-engine timeouts, a workflow runner's job timeout, provider HTTP budgets, or Ghidra's per-function decompiler timeout. Changing those unrelated limits will not extend this desktop Ghidriff run.
- Analysis profiles currently do not contain an outer timeout field. Editing ranking/profile JSON is not the route to increase this limit.

These are temporary diagnostic options. An extension may allow completion, but the logs do not prove that two or four hours will be sufficient.

## Required fixes and investigation

### PT-TIMEOUT-1 — Actionable deadline diagnostics and retry controls

- [ ] Include the effective budget, elapsed duration, timeout layer, last known stage, and retained-log location in timeout diagnostics. Persist run-start metadata and the probed PatchTrace/Ghidriff/Python/Ghidra/JVM versions before launch, then record stop time, elapsed duration and termination reason when the run ends.
- [ ] Make the active budget visible during a run and provide a clear route from the failure dialog to Setup. Consider 1/2/4-hour presets and an explicit per-run override while retaining a finite limit and working Cancel.
- [ ] Document or harmonize validation across entry points: desktop/selftest permit 10–86,400 seconds, while the API/series route accepts any positive integer. Surface invalid saved desktop values instead of silently falling back to 3,600 seconds. Do not recommend manual registry edits as a way around the supported control.
- [ ] Stream bounded, redacted stage messages and distinguish a quiet-but-running stage from a proven hang. Do not reset the total deadline on every log line, or introduce a short stdout-idle timeout that would terminate the observed 28-minute quiet interval.
- [ ] Label upstream percentages as substage progress. `Completed 72 at 100%` must not be presented as a completed comparison.

Current source already passes the configured deadline to the subprocess; no dropped-setting bug has been established. The desktop already shows elapsed seconds and indeterminate progress. The missing information is the effective deadline and live backend stage/activity: the existing failure text is too generic to explain this incident, and `backend.run_comparison` emits its collected log tail after `run_process` returns. Extend these diagnostics without changing success/publication semantics.

### PT-TIMEOUT-2 — Profile and repair candidate expansion / result processing

**Concrete source-backed hypothesis:** the repository pins Ghidriff to `4f5d895fcbb1eacd65efd81145922c15bb7e741d`. At that revision, the code after "Sorting functions" traverses matched pairs and calls `syms_need_diff`, resolving Ghidra functions and inspecting their bodies/references; it is not an actual sort. It repeats that predicate in another traversal **after** enhanced-symbol (`esym`) progress reaches 100%. Earlier conversion also resolves functions/symbols for each candidate. Millions of pairs can therefore cause repeated Python/JVM calls even when very few symbols need enhancement. Cache immutable per-function metadata and reuse predicate decisions as candidate optimizations to benchmark. This is not proof that the installed revision is the pin, or that the traversal itself is quadratic; candidate expansion and per-pair work are separate costs. Sources: [candidate conversion](https://github.com/clearbluejar/ghidriff/blob/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/version_tracking_diff.py#L250-L268), [predicate](https://github.com/clearbluejar/ghidriff/blob/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py#L1364-L1404), [first traversal](https://github.com/clearbluejar/ghidriff/blob/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py#L1608-L1632), [second traversal](https://github.com/clearbluejar/ghidriff/blob/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py#L1666-L1673).

- [ ] Reproduce with the recorded pair and capture correlator bucket sizes, candidate counts, accepted correspondence counts, per-stage timings, CPU use and peak memory. Inspect `StructuralGraphHash`, candidate conversion, the stage logged as "Sorting functions," JSON preparation and symbol enhancement. Determine which operations occupy the long quiet interval before choosing an optimization.
- [ ] Investigate ambiguous structural buckets, repeated predicate evaluation and function-metadata lookups, duplicate candidate materialization and cross-language calls. Evaluate indexed lookup, cached metadata, early semantics-preserving deduplication and bounded/lazy processing against an exact pinned upstream revision.
- [ ] If a resource budget requires skipping or truncating candidates, preserve ambiguity and report incomplete coverage explicitly; never present truncation as complete matching or silently discard valid correspondences.
- [ ] Follow the existing external-engine boundary: prefer a reviewed upstream fix or tested dependency upgrade. Any adapter contract change requires a specification update first; do not silently patch the user's installed Ghidriff or fork its matching implementation in the desktop.

BSim took about 110 seconds and completed. Disabling it alone is not a demonstrated fix for the much larger downstream delay. The logs contain no out-of-memory error, so raising Java heap allocation is not yet an evidence-backed remedy.

### PT-TIMEOUT-3 — Separate incomplete decompilation and warning coverage

- [ ] Track the separate `DecompilerParameterIdCmd` timeout for `FUN_100ca86c` at 20:54:06 (`ghidriff.log:228`). Initial analysis continued afterward. Show the affected function/coverage limitation; verify supported analyzer budget or targeted retry options independently of the outer timeout. Ghidriff's enhanced-function `--decompiler-timeout` is a different stage and is not an established fix for this analyzer message; PatchTrace does not currently expose arbitrary upstream flag passthrough.
- [ ] Report that both PDBs were unavailable (`ghidriff.log:199–202`) and that PDB processing was skipped for missing program metadata. `no_symbols: False` does not mean symbols were loaded. Offer identity-matched local PDBs when available and preserve offline operation; do not silently enable downloads or require them for success.
- [ ] Preserve and summarize the nonfatal `user32.dll` WEVTResource and embedded GIF/PNG parsing messages (`ghidriff.log:100,166,211–213,273–275`). Both binary analyses completed after these messages. They may limit coverage, but are not the demonstrated fatal cause or proof that the target binaries are corrupt.
- [ ] Record the actual selected runtime versions and compare this Ghidra **12.1.4** run with the supported/tested matrix. Multiple Python/Java directories in a library search path do not establish which interpreter/JVM ran or demonstrate an incompatibility.

### PT-TIMEOUT-4 — Retry efficiency while preserving Windows safeguards

- [ ] Document and test reuse of **completed, verified raw-cache entries** for repeated comparisons. Current raw-cache use is opt-in through `cache_dir`; it is not a checkpoint/resume mechanism for this failed attempt.
- [ ] Design any failed-run checkpoint retention separately: current scratch cleanup runs after timeout, and `retain_gzf` retains GZFs only after successful subprocess exit. Reusable analysis checkpoints need artifact/version/options binding, ownership checks, size limits and incomplete-state validation before reuse. Preserve logs and prior committed results regardless.
- [ ] Retain `--no-threaded` and per-run Ghidra settings/workspace isolation, including the mitigation introduced for the documented Windows lock failure. Any concurrency improvement needs isolated projects and native Windows lock/cancellation tests. See [the existing Windows lock investigation](ghidriff-windows-lock-20261017.md).

## Acceptance and closure

- [ ] Replay the exact recorded input pair on Windows with verified input hashes, installed package identity, runtime versions, effective timeout, elapsed time, phase counts, peak memory and final artifacts recorded. Capture cold and successful-cache repeat behavior separately.
- [ ] Verify GUI save/reload and CLI/API timeout propagation, default behavior, invalid values and a short real-child timeout/cancel path. Confirm all descendants stop and previous committed results plus failure logs remain intact.
- [ ] Add a high-collision structural-candidate regression or benchmark that catches the slow path while checking matching semantics, deterministic results, ambiguity preservation and explicit incomplete status for any cap. A synthetic test alone does not qualify the user's Windows pair.
- [ ] Verify separate reporting of per-function timeout, missing symbols and recoverable resource warnings. Confirm substage 100% never publishes a successful overall run.
- [ ] Record whether a larger budget merely permits completion or an actual performance repair materially reduces time/memory. Do not close this P1 item based solely on a larger timeout, mock tests, or the last `72/72` log entry.

Existing specifications: [backend architecture](../specs/architecture.md), [desktop workflow](../specs/ui.md), [settings registry](../specs/app-settings.md), [profiles and raw cache](../specs/enrichment.md), [launcher and symbols](../specs/ghidriff-launcher-symbols.md).
