# `patchtrace panels`

Lists the GUI panels that the manifest reserves, and checks them. It runs without a display, so it is safe on a server or in CI.

```
patchtrace panels list    # list every reserved panel and whether it is built
patchtrace panels check   # lint the panel manifest and every built panel spec
```

`list` prints each panel's id, state (`built` or `not-built`), dock area, tab group, shortcut and UI title. The titles are the exact labels the desktop shows, for example `Engine evidence`, `Calls` and `Exploitation context`.

`check` reports conflicts in ids, shortcuts and tooltip prefixes, and reports any built panel that fails to load. A passing check ends with `conflicts: none`.

Desktop equivalent: the **View** menu lists each built panel. See [panel layout and recovery](50-panel-layout-and-recovery.md) and [keyboard and command navigation](49-keyboard-and-command-navigation.md).

Sources: `src/patchtrace/cli_commands/panels.py`, `src/patchtrace/panel_manifest.py`, top-level `patchtrace --help`.
