# Callgraph layout completion

Date: 2026-11-27 (America/Vancouver).

## Source and confirmed gap

The isolated implementation starts at
`e72dfaf91499403abdec8cdedeaf434ff0619744` (tree
`f76bff233ef9d10916bdec1dc7330f6f7c767c55`). The audited unmerged donor is
`9237c2601c0f25d306b51883875c339bab8ed82b` (tree
`ea648841ab0f4563f5687dceb20af58e2ddca772`).

The current panel uses label-sorted fixed columns. The donor has a pure layered
layout algorithm and unit tests, but no current panel integration, enforced elapsed
time budget or bounded iterable admission. Current minimap, keyboard navigation,
DOT and call-site inspection already exist. The donor export change would remove
`more` from export truncation detection and is excluded.

## Incremental plan

1. Specify and test a bounded pure layout core, recover only the relevant donor
   algorithm and add input/cancellation/deadline controls. Exclude superseded donor
   minimap and keyboard helpers.
2. Specify and test optional bounded immutable polyline routes in the shared canvas,
   preserving existing straight-edge and scene-lifetime behavior.
3. Compute layout in the current graph-query worker; scale and render through current
   font metrics, retain table/tree/export evidence on diagram limits, and verify
   task ownership, cancellation and font/minimap/navigation integration.

Each slice records its failing regression before implementation and focused passing
lane afterward. Root owns independent review, full integration, native packaging,
hosted gates and publication. This work performs no live fetch or target execution.

## Evidence

### Slice 1: pure layout

Commit: `f5fafed38a9de8798e2a601a9fdbdffb90777353`.

Specification/module registration and regression tests preceded runtime recovery.
The first run failed with two missing-module collection errors, confirming that
the advertised layout core was absent. The recovered bounded core passes **57**
tests without skips: deterministic layout, crossing reduction, cycles and routes,
raw iterable caps, malformed input, budget types, seed retention, cancellation,
simulated deadlines in every major phase and independent hash-seed subprocesses.
Ruff and whitespace checks pass for this slice.

Local synthetic star-plus-neighbour-link timing, three runs per case: 500 nodes /
997 edges took 11.00, 7.81 and 7.10 ms; 2,000 nodes / 3,997 edges took 293.91,
30.68 and 43.34 ms. These are observations under shared Linux load, not native
Windows qualification or a worst-case guarantee. The runtime deadline remains
enforced regardless of these timings. Evidence logs are `layout-evidence/core-red`
and `core-green` beside the worktree.

### Slice 2: shared canvas routes

Commit: `cf1e5e8a31502152aa7b427d10fd45fd8aa20fc8`.

The optional-route regression lane failed **19** tests before implementation
(missing `points` and `node_dimensions` APIs). After the narrow canvas extension,
the new route checks plus existing graph values, canvas behavior and Qt-free
isolation lane pass **100** tests without skips in 3.50 seconds. Invalid mutable,
nonfinite and overlong routes are rejected; stock paths preserve point order;
straight edges, scene replacement, focus, selection and keyboard behavior retain
their existing tests. Font-derived dimensions match painted boxes. Ruff identified
one import-format issue, corrected before commit; lint and whitespace checks pass.
Evidence: `layout-evidence/routes-red` and `routes-green`.

### Slice 3: current worker and panel integration

The maintained worker/panel lane failed **13** tests before integration: no worker
geometry, no metric rescaling, and existing diagram/cancellation paths could clear
or retain mismatched views. The integrated lane plus existing panel and inspection
checks passes **63** tests without skips in 4.53 seconds.

The existing query worker now returns immutable layout or a drawing-only failure.
GUI code scales normalized boxes and routes to actual font metrics, updates the
existing minimap and rescales accepted geometry on font changes. Diagram capacity
or deadline failure clears old graphics while retaining the new queried graph,
table, tree, call-site evidence and DOT. Cancellation retains the accepted view;
same-epoch project-revision changes and late project-switch results are rejected.

The combined affected lane passes **674** tests without skips in 38.58 seconds:
all callgraph modules and schemas, all graph panel/inspection/layout tests, shared
graph values/canvas/routes, core isolation and task ownership. This includes the
smaller selections above; counts must not be added. Whole-tree Ruff and whitespace
checks pass. Evidence: `layout-evidence/panel-red`, `panel-green` and `integration`
logs/XML beside the worktree. The first integration lint pass reported one import
ordering issue; it was corrected before final validation.

The query, graph contracts/schemas, export, minimap and existing keyboard algorithms
remain unchanged from the audited base. In particular, the donor export regression
is absent, and tests preserve graph `truncated` and `more` under diagram failure.
No runtime dependency or persistent graph contract was added.

## Independent review and publication checkpoint

Independent review approved exact implementation commit
`4448f4a9b7acf98a740453277d404bab7d6fdf49`, tree
`1cb55fb75cc32546a4a2bd9ffc340b6d8f92533a`, without blocking findings.
Its three disjoint selections passed **139**, **32**, and **178** cases: **349
passed, zero failures, zero skips**. These overlap the author's 674-case lane
and must not be added to it. Whole-tree Ruff and whitespace checks passed.

Additional authored controls exercise deterministic directed cyclic graphs,
endpoint and box geometry, explicit dummy budgets, an older worker that ignores
cancellation, and diagram failure after a different seed is accepted. Actual
Qt offscreen rendering at font sizes 8, 12, 28, 48 and 14 preserved separation,
selection, focus, routes and minimap state without re-running layout. Root also
inspected the captured rendered panel. The review record, JUnit receipts and
independent control source are retained under
`docs/engineering/evidence/callgraph-layout-20261127/`.

This source is approved for integration. Native Windows rendering/timing,
assistive technology, full combined-source hosted tests and frozen-package
acceptance remain distinct gates; Linux offscreen results do not qualify them.
No live provider or target binary was executed. Publication keeps both
`[no release] [no deploy]` holds.
