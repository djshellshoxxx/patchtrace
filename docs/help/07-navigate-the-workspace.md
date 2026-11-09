# Navigate the workspace

The documented core workspace places function matches on the left, paired code in the center, findings and analyst review on the right, and job diagnostics below. Resize the window and drag dividers to allocate reading space.

Start by selecting a function match. The code panes display the records associated with that relationship. Search names or addresses to narrow the list, then use category and review filters to focus your work.

Categories describe relationships such as modified, added, removed, ambiguous, split, merged, and unmatched. They do not express severity. Review filters represent analyst decisions.

Use these documented core shortcuts:

| Action | Shortcut |
| --- | --- |
| `New project` | `Ctrl+N` |
| `Open project` | `Ctrl+O` |
| `Save snapshot` | `Ctrl+S` |
| `Run comparison` | `F5` |
| Request cancellation | `Esc` |
| `Interpret selection` | `Ctrl+I` |
| `Export report` | `Ctrl+E` |
| Previous difference | `Alt+Up` |
| Next difference | `Alt+Down` |
| `Workflow and dependencies` | `F1` |

Controls may be disabled until a project, selection, or idle worker is available. Check the active job and selection before changing configuration.

The current source also includes a dock host. Open built panels from **View**, or open **View → Command palette** (`Ctrl+Shift+P`) and search by panel or action name. The palette includes commands to show, focus, float/dock, and move available panels. Use `F6` and `Shift+F6` to move between workspace regions, or **View → Reset panel layout** to restore their placement. See [keyboard navigation](49-keyboard-and-command-navigation.md) and [layout recovery](50-panel-layout-and-recovery.md).

These instructions describe the current source. A reserved shortcut or a historical implementation record does not establish that a panel exists in an older downloaded package; use that package's **View** menu to check availability.

Sources: `src/patchtrace/ui.py`; `src/patchtrace/gui/qt/{host,commands,palette}.py`.
