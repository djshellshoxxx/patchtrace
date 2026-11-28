# Calls panel: bounded layered layout (WB2 G6 completion)

Date: 2026-11-27 (America/Vancouver). This amendment defines the layout portion of
`program-e/WB2-integration-plan.md` against the current Calls panel. The existing
inspection contract still owns the table, tree, call-site reveal, DOT and minimap.

## 1. Pure layout and work limits

`callgraph/layout.py` takes a bounded neighbourhood and seed and returns immutable
node boxes, caller-to-callee polylines and omission notes. It imports no Qt or
external graph package and never opens a project, executes an input, or fetches data.
Node identifiers determine stable ties; labels are presentation text only.

Layers are signed hop distances from the seed: callers left, seed zero, callees
right. When a node is reachable in both directions, the shorter distance wins and
an equal distance chooses the callee side. Nodes reachable through a shared caller
or callee are placed one layer from the first deterministically placed neighbour.
Only layers -4 through 4 are drawn. Cycles keep the original call direction:
backward, same-layer and self edges receive explicit route kinds. No semantic edge
is reversed. This replaces the earlier proposed DFS reversal and label-based ties.

Edges crossing intermediate layers use dummy routing points. At most eight
barycentre sweeps reduce crossings counted with a Fenwick tree; a sweep that does
not improve the count is discarded and ends ordering. Four neighbour-mean passes
with pool-adjacent-violators separation produce non-overlapping boxes. Coordinates
are normalized layout units, then scaled to the canvas's font-derived box size.

The default visible-node cap is 500 and the hard cap is 2,000. Raw input is bounded
before sorting or adjacency construction: at most 2,000 node entries and 8,000 edge
entries, counting duplicates and unknown endpoints. Over-limit input is refused,
never silently reduced to the first entries. Within that input, node/depth caps
retain the nearest nodes deterministically and report omissions. At most 20,000
dummy points are allocated; longest spanning edges are omitted first when that cap
is reached, with an explicit count. Requested budgets must be integers (not bool),
nonnegative where zero is meaningful, and cannot raise their hard ceilings.

Cancellation is checked before consuming input and throughout bounded ingestion,
traversal, routing, ordering and coordinate work. A monotonic deadline of at most
400 ms covers the complete calculation. Cancellation raises `PT-GRAPH-CANCEL`;
input/deadline capacity exhaustion raises `PT-GRAPH-LAYOUT-LIMIT`. Neither returns
partially calculated geometry. Successful output is independent of iterable order,
duplicate edges, Python hash order and elapsed time.

## 2. Canvas route contract

`gui.graph_view.GraphEdgeView` gains optional immutable `points`: empty keeps the
existing centre-to-centre line; otherwise 2 through 16 finite numeric coordinate
pairs describe a caller-to-callee polyline. Malformed, mutable, nonfinite or
overlong routes are rejected before replacing a scene. `GraphCanvas` uses stock
`QGraphicsPathItem` for routes and keeps its existing straight-line, focus,
selection, zoom, keyboard, scene-swap and accessibility behavior. Its public
`node_dimensions()` returns the same font-derived dimensions used to paint boxes.
No feature-specific layout algorithm belongs in the canvas.

## 3. Worker and panel integration

The existing `graph-query` worker computes layout after the complete bounded graph
and neighbour rows. The result carries its geometry or a diagram-only failure.
The GUI scales normalized positions and routes using the current box dimensions,
creates graphics items and updates the existing minimap. Font/DPI metric changes
rescale the stored geometry without running the graph algorithm on the GUI thread.

Layout omissions and diagram capacity/deadline failures have an explicit diagram
notice. The complete queried graph, neighbour rows, tree, call-site evidence and
DOT remain available. Layout omissions never change graph evidence, `truncated`,
`more`, edge orientation or export content. Failure clears any previous diagram
so a new table cannot be paired with an unrelated old canvas. Cancellation and
superseded worker results preserve the previously accepted view and use existing
task-generation, project-key, epoch and shutdown guards. The existing minimap and
keyboard implementations remain authoritative; there is no second window.

## 4. Acceptance

- A crossed two-branch graph becomes uncrossed; input permutations and hash seeds
  produce identical successful geometry. Random cyclic fixtures do not overlap.
- Long, backward, same-layer and self routes keep their original endpoints, and
  every drawn route stays inside reported bounds.
- Input counts, node/depth/dummy limits, invalid budget types, cancellation during
  ingestion and later phases, and deterministic simulated deadlines are exercised.
- The current query worker produces geometry; diagram failure preserves its graph,
  rows, truncation markers and DOT. Cancelled or late work cannot replace a view.
- Stock route rendering, large-font separation, font-change rescaling, minimap
  synchronization and existing keyboard/project-switch behavior work offscreen.
- Existing callgraph, canvas and inspection tests remain green. Native Windows
  timing and assistive-technology behavior remain separate qualification gates.
