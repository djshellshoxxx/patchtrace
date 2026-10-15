# Resolve blocked and unsupported states

A blocked panel lacks a prerequisite. An unsupported state identifies a capability the current environment cannot provide. Neither state means the comparison found no differences.

The shared framework defines messages that identify the panel, reason, and available remedy. Read the adjacent explanation as well as any disabled-control tooltip.

Common prerequisites include an open project, completed analysis, idle worker, configured tool, enabled feature, or Windows-specific capability.

1. Read the complete state message.
2. Identify the missing prerequisite.
3. Use `Open setup` when offered.
4. Select and explicitly diagnose or probe the required tool.
5. Complete any prerequisite comparison or import.
6. Return to the panel and retry its supported action.

Selecting a tool path does not establish that the executable is compatible. A probe can execute the configured tool, so use the explicit probe action rather than expecting path discovery to perform it.

Planned: a manifest slot whose panel module has not been built can remain absent from menus. This differs from an implemented panel that opens in a blocked state.

A `PT-GUI-FACTORY` message means panel creation failed. Copy the available details and report the application version and panel name; **changing target binaries is not an established remedy.**

Avoid repeated retries without changing the prerequisite. Preserve earlier results and use another available view when it answers your immediate question.

Sources: src/patchtrace/gui/state.py; src/patchtrace/panel_manifest.py; docs/specs/program-e/GUI-integration-plan.md, section 8.2.
