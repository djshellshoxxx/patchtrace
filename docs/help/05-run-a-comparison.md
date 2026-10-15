# Run a native comparison

A native comparison runs the configured Ghidriff and Ghidra backend against the project’s stored binary pair. Configure and diagnose the external dependencies in `Setup` first.

1. `Open` the intended project.
2. Check the older and newer artifact identities.
3. Finish or cancel any active job.
4. Select `Run comparison,` or press `F5.`
5. Follow the job status, elapsed time, and diagnostic log.
6. Wait for a terminal status before starting another operation.
7. Select a resulting function match and inspect both sides.

Progress can be indeterminate when the backend does not provide a measurable total. An indeterminate indicator alone does not establish that the process has stalled.

PatchTrace supervises the external process, validates its output, and normalizes accepted results. Failed, invalid, timed-out, and cancelled attempts preserve previously committed results and retain diagnostic information.

To stop, select `Cancel job` or press `Esc.` Cancellation is a request; wait for the final status. **Do not treat the first click as confirmation that every backend process has exited.**

A successful comparison can contain no changed functions, particularly for identical inputs. Clear filters before concluding that results are missing.

PatchTrace does not execute the target files. Backend process supervision is not an operating-system sandbox or an air-gap mechanism.

If analysis fails, retain the error code and sanitized log. Dependency diagnosis alone does not establish that the complete installed tool combination can perform a native comparison.

Sources: `README.md,` “Run a native comparison”; `docs/specs/ui.md;` `docs/windows.md.`
