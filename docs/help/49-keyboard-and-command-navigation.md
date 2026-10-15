Navigate panels with the keyboard
Experimental: command-palette and panel-focus infrastructure exists in the reviewed framework source. Availability in your installed package is UNVERIFIED.
Use Ctrl+Shift+P to open the command palette. Search for an action by name, inspect its availability, and activate the intended command.
The host supplies commands to show or hide, focus, float or dock, and move each available dock panel. Moving supports left, right, top, and bottom areas.
Use these documented framework shortcuts:
Shortcut	Action
Ctrl+Shift+P	Open command palette
F6	Focus next workspace region
Shift+F6	Focus previous workspace region
Ctrl+Shift+E	Engine evidence
Ctrl+Shift+U	Unified
Ctrl+Shift+L	Leads


Other panel shortcuts remain reserved even when their feature is planned. A reserved shortcut does not establish that the panel is available.
Use Tab and Shift+Tab between controls. Use arrow keys within tables, trees, and option groups. Feature-specific actions such as Enter, Space, and Ctrl+C depend on the focused view.
Escape behavior also depends on focus. It can dismiss a popup, clear a feature filter, close a dialog, or request cancellation. Read the feature’s instructions before relying on it during a running operation.
Disabled commands can reflect a missing project, selection, dependency, or idle worker. Inspect the stated reason before retrying.
Sources: src/patchtrace/gui/qt/commands.py; src/patchtrace/panel_manifest.py; README.md.
