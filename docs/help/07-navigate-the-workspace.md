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

Planned: the GUI integration plan specifies a common dock host, command palette, layout reset, and keyboard commands for moving panels. Some framework components have implementation records, but complete migration and packaged availability are UNVERIFIED in the reviewed sources.

**Do not assume a missing dock command has the same availability as an established core action.**

Sources: `README.md,` “Workspace and GUI controls”; `docs/specs/ui.md;` `docs/specs/program-e/GUI-integration-plan.md,` sections 8.4–8.9; `docs/modules.md.`
