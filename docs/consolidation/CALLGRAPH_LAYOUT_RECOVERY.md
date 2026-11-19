# Callgraph layout recovery

## Source and recovered behavior

Source branch: `claude/instance-b-features`, frozen head
`9237c2601c0f25d306b51883875c339bab8ed82b`.
Original contribution: `6e1e153bd90b251b81b9cc919b0cbbb7f1d8d9ac`.
Integration starting point: `a56ab13aaf9916fc12bea70ba1494075991b7f09`.

The source's signed-hop layout and crossing reduction were absent from the
current Calls panel. The panel previously placed nodes in alphabetic columns.
The recovered algorithm now runs inside the existing `graph-query` worker and
feeds the real canvas and minimap. Current controller cancellation and epoch
checks continue to govern whether its immutable result is displayed.

The original layout source's duplicate minimap and directional-navigation
helpers were not copied. Their behavior already has active implementations in
`callgraph/minimap.py` and `gui/graph_view.py`, with actual Qt consumers. Existing
minimap and panel controls were rerun with the new positions.

## Repairs made during recovery

- Bound raw input items before building sets, including duplicates and dangling
  edges; validate identity length and shape before sorting or indexing.
- Validate integer budgets before consuming inputs, reject booleans and negative
  values, and clamp accepted requests to the existing design ceilings.
- Check cancellation before iteration and during traversal, routing, crossing
  counts and coordinate placement.
- Keep the seed under a tiny node cap even when a shared-caller sibling sorts
  before it. The historical implementation could discard the seed and crash.
- Scale node spacing to the actual canvas font metrics. Larger fonts preserve
  nonoverlapping rows.
- Display explicit layout omissions and failures. Preserve the query's table,
  tree, call-site data and DOT export when a diagram is limited or unavailable.

The canvas still renders straight edges between original node identities.
Internal dummy routes improve ordering; this change does not add a new edge
renderer or alter graph evidence or stored contracts.

## Verification

Executed in the isolated recovery worktree with the project's Python environment:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_callgraph_layout.py \
  tests/test_callgraph_layout_boundaries.py \
  tests/test_ui_graph_layout.py \
  tests/test_ui_graph_panel.py \
  tests/test_ui_graph_inspection.py
```

Result: **124 passed in 61.92 seconds**. These include historical algorithm
controls, hostile input and cancellation controls, and actual offscreen Qt
worker/canvas integration. No target binary or external analysis engine ran.
Full integrated source and native/platform qualification remain separate gates.

An independent reviewer examined recovery commit `02055acb` after the executor
recovered. The review found no blocker in seed retention, raw-input and budget
ceilings, deterministic coordinate/edge mapping, cancellation propagation or
the worker/GUI boundary. The independent focused run reported **68 passed in
3.08 seconds** across the pure layout, boundary and Qt layout tests. Its logs
are `callgraph-independent.log` and `callgraph-independent.xml` in the session
evidence directory. These 68 tests overlap the author run above and must not be
added to the 124 as a larger independent test count. Integration cherry-pick
`77204ef5` preserves the existing capped-view specification amendment alongside
the new layout specification; the coordinator owns its combined test gate.
