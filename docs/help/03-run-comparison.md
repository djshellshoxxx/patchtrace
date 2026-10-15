# Run a comparison

Open the exact older/newer project and configure the backend in Setup. Run comparison requires both artifacts, a usable backend, and no conflicting active job. Use F5 or the toolbar action. It starts external analysis tools that read the target files; it does not run either target.

Watch the job state, elapsed time, and diagnostic log. Indeterminate progress means the backend has not supplied a reliable total. It does not by itself indicate a hang. First analysis can require substantial time, and a successful dependency diagnosis does not prove a full comparison will complete.

Cancel job or Esc requests cancellation. Wait for a terminal status before starting another operation or closing associated tools manually. Report surviving analysis children after terminal cancellation with the application version and sanitized diagnostics.

Successful output is validated and committed. Failed, invalid, cancelled, or timed-out attempts preserve earlier committed results. Check the run identity when you return to the navigator so an older successful result is not mistaken for the failed attempt's output.

If no changed functions appear, clear filters and check whether the files are identical. Missing results do not establish unchanged behavior when analysis was incomplete. See [states](20-states-and-remedies.md) and [external tools](24-external-tools.md).

Source: [README](../../README.md), [Windows setup](../windows.md), and [workflow](../guide/11-workflow-compare.md). **UNVERIFIED:** native comparison, cancellation cleanup, timings, and backend compatibility were not run here.
