# Build environment panel

The **Build environment** panel lists the build facts of the older and newer file side by side: facts recorded in each PE, and any stored Detect It Easy results. It is a right dock, shown with `Ctrl+Shift+B`, and it is tabbed with **Engine evidence**. It needs an open project.

Controls:

- **Read again** reads the build environment again. Use it after a file or tool result changes.
- **Cancel** stops the read. The panel then keeps its earlier results.
- **Technical details** (a checkbox, *Show technical details*) shows the underlying values.
- **Copy** copies the build environment as text.

The build facts table has an entry for each fact on each side. A missing side is shown as missing. It is not treated as equal to the other side.

Detect It Easy results are a tool's identification. The panel notes when it has not run on both files, or when the two results come from different tool setups. Those notes mean the comparison is partial.

A difference in build facts can explain some code changes without a source edit. It does not show which function changed for that reason. Identical facts do not prove identical compiler options.

The same facts are available from the command line: [`patchtrace build-env`](64-cli-build-env.md).

Sources: `src/patchtrace/buildenv/panel.py`, `src/patchtrace/buildenv/qt_panel.py`, `src/patchtrace/buildenv/copy.py`.
