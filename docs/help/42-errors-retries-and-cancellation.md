Handle errors, retries, and cancellation
An error describes an operation that could not complete. Read its code, message, and retained diagnostic details before retrying.
The shared error message states that earlier results are unchanged. A failed new attempt must not be treated as a replacement for the last committed result.
Use Copy details when offered. Preserve the application version, operation, relevant tool versions, error code, and sanitized diagnostic text.
Choose the next action according to the failure:
Failure	Next action
Invalid configuration	Correct the identified field
Missing dependency	Configure and diagnose the required tool
Timeout	Inspect the log and workload before adjusting the limit
Unreadable output	Check the producing tool and supported format
Panel creation failure	Record PT-GUI-FACTORY details and report the panel


Retry starts or repeats the feature’s operation. It does not establish that the underlying problem has been repaired.
Cancellation can be cooperative. After requesting it, wait for the terminal status before starting conflicting work. An interpretation request cannot recall context already transmitted.
A Cancelled message means the attempt ended without replacing earlier results. A Cancelling message means stopping is still in progress.
Do not delete project files, active locks, or runtime directories to force a job to stop. Use the supported cancellation path and retain diagnostic information if shutdown fails.
Sources: src/patchtrace/gui/state.py; README.md; docs/specs/ui.md.
