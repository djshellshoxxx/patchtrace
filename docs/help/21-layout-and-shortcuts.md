# Layout and shortcuts

Use View to show available docks. Ctrl+Shift+P opens the command palette; it lists commands and disabled reasons. F6 and Shift+F6 move between workspace regions. View > Reset panel layout restores defaults when placement is confusing.

| Keys | Action |
|---|---|
| Ctrl+N / Ctrl+O / Ctrl+S | New / Open / Save |
| Ctrl+E | Export |
| Ctrl+R | Rank changes |
| Ctrl+I | Preview interpretation |
| F5 / Esc | Run comparison / request job cancellation |
| F1 | Workflow and dependencies |
| Alt+Up / Alt+Down | Previous / next difference |
| Alt+Left / Alt+Right | Navigation back / forward |
| Ctrl+Shift+E | Engine evidence |
| Ctrl+Shift+U | Unified |
| Ctrl+Shift+L | Leads |

The manifest also reserves Ctrl+Shift+F Search, G Graph, T Strings, A Capabilities, B Build environment, R Rules, K KB, X KEV, and H Guide. These panel implementations are absent from the inspected branch. Reserved shortcuts do not make them available. Files and Series have no dedicated manifest shortcut.

The palette supplies panel focus, show/hide, float/dock, and move commands. This provides a keyboard route when title-bar buttons cannot receive focus. Reset changes layout, not analysis evidence.

High contrast is automatic; Dark and System are separate theme choices. Actual focus order, announcements, scaling, and motion behavior still require native acceptance.

Sources: [panel guide](../guide/13-panels-and-layout.md) and src/patchtrace/panel_manifest.py. **UNVERIFIED:** shortcuts, focus retention, keyboard-only completion, and Windows accessibility were not tested here.
