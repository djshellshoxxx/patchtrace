# Capabilities panel

The **Capabilities** panel shows capa rule matches for the older and newer build, and the changes between them by function pair. It is a bottom dock, shown with `Ctrl+Shift+A`, and it is tabbed with **Calls** and **Strings**. It needs an open project.

The panel has two tabs:

- **Changes** lists the capability changes. Filter with the search box (*Search capabilities by rule, namespace or function*) and group them with **Group capability changes by**. Checkboxes show **Show detection differences**, **Show building-block rules** and **Show unattributed capa matches**. **Go to pair** opens the selected function pair. **Copy provenance** keeps the tool version, rule and settings with the row. **Refresh** rereads the stored results.
- **Setup and run** configures capa. **Browse...** selects the executable. **Probe** checks it. **Time limit per file** sets the limit. **Run...** shows a **Run preview**. Nothing starts until you choose **Confirm and run**. **Cancel preview** closes the preview without starting anything.

Opening the panel does not run capa. Read the preview before you confirm.

A capability match is a static rule match. It is not a behavioural recording, and it does not show that the code runs under any input. A capability present in only one build can come from a code change or from different analysis conditions. A failed or unsupported run is unknown, not a negative result.

Capa output is an observation from one tool run. Check that both sides used the same tool version and rules before you read a difference as a change.

The same data is available from the command line: [`patchtrace intel-tools`](62-cli-intel-tools.md).

Sources: `src/patchtrace/intelligence/tools/capa_panel.py`, `src/patchtrace/intelligence/tools/capa_qt.py`.
