# Live Intel version-probe diagnostic contract

This is an additive acceptance-harness contract for SPEC-29 tools T9. It does
not change application records, tool support, executable pinning, process
arguments, time limits, output limits or native acceptance predicates.

## Observed evidence gap

PR #349 at `11f51c105bf63946f59373ae605b937c4fee607a` reported a Windows capa
version failure with exit 0 and a FLOSS version failure with exit 1. The
[actual job](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397141/job/136743396511)
retained generic failures but no version-probe stdout/stderr. A separate adapter
repair handles an optional literal `.exe` banner suffix; it does not explain
or clear the observed FLOSS exit 1.

## Observation and artifact

The existing live acceptance test observes the `Execution` returned by each
existing `process.run_version_probe` call during its initial engine probe.
The observer delegates exactly once, forwarding the original executable,
argument object and keyword values unchanged. It returns the identical result
object, propagates the original exception, and restores the original callable
when its context ends. It never launches an additional process or observes
analysis runs.

Only the fixed probe argument vectors `--version`, `--help` and `-H` are
recorded. The command is the executable basename, never its parent path.
Environment mappings, configuration objects, input filenames and arbitrary
argument vectors are not recorded. Existing `patchtrace.diagnostics.redact_log`
credential rules apply before any text tail is shortened; the retained text is
diagnostic output, not an unredacted byte archive.

A `probe_diagnostics` object in the existing per-engine live-status JSON
contains `contract: intel-version-probes/1`, at most four probe observations,
and an omitted-observation count. Each observation records the command and
fixed arguments, exact return code, process reason, spawn-error information,
output-limit flag, elapsed milliseconds, and separate stdout/stderr tails.
Command text is limited to 128 characters; reason to 256; spawn-error text to
1024; each stream to 4096. Every text field has an explicit diagnostic-tail
truncation flag. Stream character counts describe the captured decoded text,
not bytes emitted by the original child. The existing `Execution.oversize`
value remains separate from diagnostic-tail truncation. The harness cannot
reconstruct bytes already omitted by process capture.

Observation failures are recorded by exception class and cannot replace the
underlying probe result or exception. No exception message, environment or
unrecognized argument is captured by that fallback.

The same object is attached to the existing failed, blocked or passed status
record. Supported and pinned predicates, golden comparisons, the DIE advisory
exception, and every existing failure/skip remain unchanged. A missing tool
still follows the existing pre-probe absent-tool path. A cached probe may yield
zero observations; the harness does not clear the cache or invent a subprocess
receipt. The existing workflow already uploads `build/live-status/` with
`if: always()`, so no workflow change is needed.

## Verification boundary

Controlled regressions exercise result/argument/exception identity, restoration,
text redaction and bounds, explicit omission, refusal to capture other commands,
and the actual live-test failed/blocked/success branches with authored results.
Those tests are labelled mocked and execute no tool binary or target. Native
capa/FLOSS compatibility requires the subsequent exact-source Windows run;
source tests and an advisory green workflow cannot establish that result.
