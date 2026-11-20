# Retain native cache acceptance diagnostics

Base: `71b535cc5c1ca0ccc6762831a5d8a137644d14fc`.

## Problem and retained failure

The native cache harness creates both test projects inside a temporary
directory. Any assertion or analysis failure removes those projects during
cleanup. The workflow's existing uploader searched only `live-project`, a
different path used by the other native acceptance variants. Consequently,
the raw-cache variant could fail without a retained first/second-run receipt
or the Java probe output needed to investigate an unverified runtime.

The coordinator retains the original failed raw-cache gate at
[run 44770501981, job 136406567877](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44770501981/job/136406567877).
The cause of that native `java=unverified` result remains unresolved. A passing
counterpart is not evidence that the failure did not occur. This repair adds
observations for a later supported-runner execution; it does not claim to fix
the native cache miss.

The unchanged baseline harness was exercised with injected project and process
fakes. Its original uncached-second-run assertion still raised, after which
the new diagnostic-retention regression failed because `first.json` did not
exist. The preserved baseline is **1 failed in 3.17s**.

## Implementation

`--diagnostics-dir DIRECTORY` explicitly requests a new, create-only directory.
The harness refuses an existing directory before any project or process work.
Each attempted run writes a bounded JSON document with an allowlisted run
summary, event tail, digest/count observations, and existing Java-probe results.
A separate result document records the original final acceptance outcome.

The temporary observer forwards the existing version-probe arguments, result
objects, and exceptions. It restores the original process callable when the
scope exits. It starts no additional JVM probes, and the backend's Java
verification, retry/timeout sequence, cache admission, and all three native
acceptance assertions are unchanged. Ordinary harness use without the new
option retains temporary cleanup and failure behavior.

Output is redacted, bounded, and written exclusively. It excludes environment
mappings, credentials, target bytes, raw analysis bodies, and full project
copies. Diagnostic write failures are explicit on stderr and do not suppress
the original acceptance exception. The workflow adds the option and artifact
path to its existing `always()` upload step; no conditions, budgets, or gates
change.

## Verification and remaining acceptance

The affected selection completed **113 passed in 2.97s**, including retention
after an uncached second run, first-run failure, byte mismatch, ordinary
success, no-option cleanup, existing-directory refusal, bounded/redacted tails,
write-failure reporting, transparent process forwarding/restoration, and
artifact upload wiring. Existing Java-probe and backend-progress tests also
pass. Changed-file Ruff and whitespace checks pass.

Source/test hashes, exact commands, and raw result logs are retained in
[`evidence/live-cache-diagnostics-20261120/receipt.json`](evidence/live-cache-diagnostics-20261120/receipt.json),
[`baseline.log`](evidence/live-cache-diagnostics-20261120/baseline.log), and
[`affected-green.log`](evidence/live-cache-diagnostics-20261120/affected-green.log).

These are fake-based harness and process-observation results. No target binary
or native analyzer was executed. Fresh independent review and source-specific
native CI remain required; the unknown-Java cause, original failed gate, and
release blockers remain open.

## Independent and integrated verification

Fresh [independent review](evidence/generation33/cache-independent/review.md) accepted the frozen worker after 161 passes: 113 maintained affected cases plus 48 distinct controls. It verifies unchanged no-option outcomes across success/eight failure paths, exact probe forwarding/restoration, preserved assertions and write-failure handling. Those 113 maintained cases are included in the final 606-pass/1-native-skip combined run at `bbdef5a6`; counts overlap. The [final source review](evidence/generation33/final-source-integration-review-bbdef5a6.md) verifies exact accepted blobs and the two-field workflow delta. Native unknown-Java acceptance remains unresolved.
