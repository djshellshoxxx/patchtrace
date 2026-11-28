# Calls panel

The **Calls** panel shows the callers and callees of a function from the call lists stored in a project. Its title in the **View** menu and in the window is `Calls`. It is a bottom dock, shown with `Ctrl+Shift+G`, and it is tabbed with **Strings** and **Capabilities**. It needs an open project.

Tabs: **Changes**, **Neighbours**, **Tree**, **Diagram** and **Call sites**.

Controls:

- **Side** chooses `Newer` or `Older`.
- **Direction** chooses `Both`, `Callers` or `Callees`.
- **Depth** limits how far the view expands from the selected function.
- **Hide noise** hides names that the hub registry marks as build plumbing (common helper calls that link many functions). Turn it off to see every edge.
- **Follow selection** moves the view with the function you select in the navigator.
- Buttons: **Open**, **Focus here** (focus on selected function), **Back** (back to previous function) and **Copy details**.

A missing edge does not prove that a call is absent. A name with no stored record is shown as unresolved, and the view says *This name has no function record.* Read the direction of each edge: a caller calls the function, and a callee is called by it.

Static call lists do not show call counts, execution order or runtime coverage. Read the paired code to confirm a relationship.

## Reading the diagram

The diagram places callers to the left of the selected function and callees to its
right, using the shortest recorded hop distance when a function belongs to both
sides. It reduces line crossings and routes calls across intermediate layers.
Cycles keep their recorded caller-to-callee direction. Labels and boxes scale with
the application font, and the minimap follows the displayed geometry.

Use the arrow keys to move between nodes, Enter to open the focused function, Space
to select it, `+` and `-` to zoom, and `0` to fit the view. `M` toggles the minimap.
Escape cancels a pending calculation and keeps the previously accepted view.

A diagram notice identifies any omitted nodes or routes. If the drawing reaches
its size or time limit, use the **Neighbours** table, **Tree**, or **Export DOT**,
or reduce the depth. Drawing limits do not remove evidence from the queried graph
or its export. The table remains the accessible alternative to the diagram.

The same data is available from the command line: [`patchtrace graph`](66-cli-graph.md).

Sources: `src/patchtrace/callgraph/panel.py`, `src/patchtrace/callgraph/panel_qt.py`.
