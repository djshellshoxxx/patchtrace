# Create and open projects

Choose New or Ctrl+N. Enter the project name, select Older PE x64 and Newer PE x64 explicitly, and choose an absent or empty destination. Use Swap older and newer before creation if necessary. File names and timestamps do not establish patch order.

Creation validates the PE architecture, records hashes, and stores project-owned copies while preserving your originals. The supported input contract described in the repository is PE AMD64. An extension such as .dll does not make an otherwise unsupported file acceptable. PatchTrace reads targets as data and never launches them or installs drivers.

Choose Open or Ctrl+O to resume the folder containing project.sqlite3 and its companion files. Recent projects remember paths. If a project is locked, close its other writer before retrying; do not remove a live lock to bypass ownership.

Keep projects outside the application distribution. Updating the executable should not replace your evidence. Use Project > Back up project to make a complete separate copy. An exported report is not a backup, and copying only the database omits companion artifacts and run outputs.

An orientation swap after creation can invalidate earlier interpretations. Review stale notices before following their evidence. See [state remedies](20-states-and-remedies.md).

Source: [comparison workflow](../guide/11-workflow-compare.md) and [desktop specification](../specs/ui.md). **UNVERIFIED:** project creation, writer-lock recovery, backup restoration, and Windows paths were not exercised in this documentation task.
