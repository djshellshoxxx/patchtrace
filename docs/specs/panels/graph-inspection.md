# Calls panel: DOT export, call-site reveal and minimap (SPEC-26 slice)

Status: implemented contract for `graph.export_dot`, `graph.callsite` and `graph.minimap`. Extends the Calls panel
(WB2 G5/G6, `src/patchtrace/callgraph/`). Verified against the code on `claude/instance-d-gui`; the ChatGPT draft
`origin/chatgpt/panels-1:docs/specs/panels/graph.md` was used as input but is unverified and not authoritative.

## 1 DOT export (`graph.export_dot`)

- Exports the visible call graph (the current neighbourhood: seed, side, direction, depth, unresolved filter) as
  Graphviz DOT text through the existing `callgraph.dot.render_dot`. Labels are sanitised and escaped by that module
  (no Graphviz escape string can be formed from text), the output is byte-stable and capped at `MAX_EXPORT_BYTES`
  (2 MiB); over the cap the export is refused with `PT-GRAPH-EXPORT` before any dialog opens.
- Qt-free entry points in `callgraph/panel_data.py`: `dot_export(data, found)` (the `GraphExport` of what is shown),
  `dot_text(data, found)`.
- The file is written only to the path the user picks in a save dialog, through `export_json.write_export`
  (temp file then `os.replace`). Cancelling the dialog writes nothing. There is no default location, no auto-save,
  no Graphviz execution and no network. The suggested file name is content-derived (`callgraph-<sha12>.dot`), never
  taken from function names.
- Result and failures are shown in the status bar and announced; they never replace the committed call view.
- Disabled (with the reason in its tooltip) while there is no visible graph.

## 2 Call-site reveal (`graph.callsite`)

- New tab `Call sites` (after Diagram). Top table `Call edges`: the observed call edges (caller to callee) that touch
  the selected neighbour, or the seed when none is selected. Columns: Caller, Callee, Caller entry, Callee entry,
  Basis. Entry addresses are the function entry addresses Ghidriff lists (comparable within one side only); an unknown
  address reads `Unknown`, never 0.
- Selecting an edge row and pressing `Show call site` (or Enter in the edge table) reveals the call-site rows in the
  second table: every line of the stored decompiled text of the caller whose identifier token equals the callee
  (existing `find_call_site` rule, namespace stripped), at most 50 rows, each `Line`, `Text` (sanitised, 160 chars).
  A row is a text match, not a machine instruction address, and says so (`text match in decompiled code`). When no line
  matches: `Call site not found in the decompiled text (it may be inlined or renamed).` When the caller has no stored
  text: `No decompiled text is stored for the caller.`
- The reveal reads the immutable project copy on a worker (`graph-callsite` channel); a result for another edge, another
  project epoch or after shutdown is dropped.
- Evidence anchor: `Open` on an edge row emits a `function` anchor for the caller (pinned to run and revision) through
  the navigation port, so the code host shows the caller's stored text. A miss changes nothing. No new anchor kind.

## 3 Minimap (`graph.minimap`)

- Read-only overview of the diagram canvas: one dot per node, the focus node marked, and a rectangle for the part of the
  scene the canvas currently shows. Pure geometry in `callgraph/minimap.py` (`build_minimap`, `MinimapModel`,
  `to_scene`, `pan_target`), drawn by `callgraph/minimap_qt.py`.
- Mouse: a click or drag centres the canvas viewport there. Keyboard equivalent (minimap focused): arrows pan by a
  tenth of the scene, `+`/`-` zoom, `0` fits. `M` on the Diagram tab toggles the minimap; the `Minimap` toggle button
  does the same. Accessible description: `Viewport covers N percent of the diagram, centred at column C of 10, row R of 10.`
- No timers; it repaints on canvas scroll, range and graph changes only. Nothing in it is information that is not
  also in the Neighbours table.

## 4 States

All three use the panel's `StateView` (no project, no run, loading, cancelled, error, stale, partial). No-graph
disables Export DOT, hides the minimap and empties the call-site tables.
