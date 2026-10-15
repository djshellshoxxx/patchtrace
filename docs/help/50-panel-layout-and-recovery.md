# Arrange and recover panel layout

Experimental. The reviewed framework stores and restores dock layout and provides a reset action. Packaged availability is UNVERIFIED.

Use the `View` menu or command palette to show a panel, focus it, move it to another dock area, or float it. Keyboard commands provide access when dock title-bar buttons are difficult to reach.

Hiding a panel changes visibility. It does not delete its project data. A floating dock remains part of the application workspace.

If an expected panel appears missing:

1. Check whether its feature is implemented in your build.
2. Use its `Show` command.
3. Use `Focus` to activate its dock or tab.
4. Move it to a visible dock area if necessary.
5. Choose `View → Reset panel layout` when the saved arrangement is unusable.

Reset reports Panel layout reset to defaults. It resets the layout rather than erasing analysis results or resetting backend paths.

The framework validates its saved layout before restoration. If restoration fails, it reports Panel layout could not be restored; defaults were used.

Default placement does not imply every panel opens automatically. Several panels are hidden until requested.

A planned panel absent from the manifest’s loadable modules cannot be recovered by resetting layout. An implemented panel that fails creation should report a separate error.

Keep the failure message when reporting repeated layout recovery problems.

Sources: src/patchtrace/gui/qt/layout.py; src/patchtrace/gui/qt/commands.py; src/patchtrace/gui/qt/host.py; src/patchtrace/panel_manifest.py.
