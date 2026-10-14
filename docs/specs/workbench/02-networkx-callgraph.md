# PT-WB-02: Interactive Call Graph and Cross-Reference Explorer (NetworkX)

**Status:** Developer-ready specification, unimplemented. **Contract:** `workbench-graph/1`. **Depends on:** existing Ghidriff normalized records; optional PT-WB-01 search. **Parent:** [integration index](README.md). Date: 2026-10-14.

## 1. Analyst value

From a changed function, view callers, callees, changed relationships and bounded paths leading to/from suspicious operations without leaving PatchTrace. Keep the original older/newer function identities and a source-backed confidence distinction. Users must be able to answer 'what calls this?', 'what code can it reach?', 'which calls changed between versions?', and 'which graph nodes can I jump to?'.

Avoid new Ghidra analysis during first release. The repository already has:
- `FunctionRecord.callers` and `FunctionRecord.callees` validated from Ghidriff's `calling` and `called` lists in `normalization.py`.
- `FunctionMatch` with older/newer lists, category, manual review, `run_id` and match IDs.
- `WindowPort.select_match(match_id)`, evidence view-model/dock, and `ui.py` main navigation.
- `nway/graph.py` for cross-build series matching. **Do not repurpose it**: nway edges represent correspondence across releases; the new graph represents call relationships **within each artifact**.

This source's completeness is limited: stored match functions are usually changed/added/deleted; callers/callees may reference unseen unchanged functions. Label such nodes 'external to current normalized match set', not 'removed'. A true whole-program call graph requires a separate future Ghidra call-reference exporter. A string in `called` is an unverified label, not a proven direct call to a particular function record.

## 2. Model and semantics

```python
class GraphNode(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    id: str
    artifact_sha256: str
    run_id: str
    side: Literal['older','newer']
    function_id: str | None
    match_id: str | None
    display_name: str
    address_space: Literal['virtual','relative','file-offset','unknown']
    address: str | None
    kind: Literal['matched-function','unresolved-label','external',
                  'ambiguous-candidate']
    change_category: str | None
    review_status: str | None
    evidence_ids: tuple[str, ...]
class GraphEdge(BaseModel):
    id: str
    src: str  # caller
    dst: str  # callee
    side: Literal['older','newer']
    relation: Literal['named-caller','named-callee','verified-static-call',
                      'verified-indirect-reference','unresolved-reference']
    confidence: Literal['verified','inferred','ambiguous','unknown']
    evidence_ids: tuple[str, ...]
class GraphQuery(BaseModel):
    seed: str
    direction: Literal['callers','callees','both']
    depth: int = Field(ge=1,le=4)
    max_nodes: int = Field(ge=5,le=500)
    max_edges: int = Field(ge=5,le=2000)
    side: Literal['older','newer','paired']
    only_changed: bool
    include_unresolved: bool
class GraphView(BaseModel):
    contract: Literal['workbench-graph/1']
    project_id: str
    run_id: str
    older_sha256: str
    newer_sha256: str
    nodes: tuple[GraphNode,...]
    edges: tuple[GraphEdge,...]
    truncated: bool
    completeness: Literal['partial-changed-set','source-covered','unknown']
    warnings: tuple[str,...]
```

Additional internal `GraphSnapshot` captures `project_id`, `revision`, `match-override digest`, `raw-run SHA`, original per-function sources, parser version and graph_schema. Old/new nodes **never merge** even if they have the same address/name/bytes. `paired` output is two independent graphs plus correspondence via exact current `FunctionMatch` IDs; add separate cross-version overlay edges only with relation `version-correspondence`, never a call edge.

## 3. Resolution rules and identity

Build node index keyed by (artifact SHA, run ID, side, original FunctionRecord ID) with stable `domain_id('workbench.graph.node',1,...)`. Resolve `callers` and `callees` labels by:
1. Structured reference, RVA/address plus image-base normalization, if the source actually supplies one and its coordinate system is verified.
2. Exact function name match **within the same side/run** if and only if unique, with relation `named-caller`/ `named-callee` and confidence `inferred`.
3. Zero matches: unresolved label node with a source pointer and `not in current function set` status; never infer 'removed'.
4. Multiple matches: one ambiguous label node with enumerated candidates; never pick the first.
5. Never match by cross-version VA/address or unsourced string similarity. A RapidFuzz suggestion may appear as 'possible name' but must not create a call edge automatically.

`callers` list means `caller -> this function`; `callees` means `this function -> callee`. If both endpoints supply matching evidence, collapse duplicate conceptual edges while recording **both** sources. A missing reciprocal record does not disprove a call. Static call labels may be stale or imprecise due to thunks, inlining, indirect calls, dynamic linkage and unresolved imports.

When selecting a function whose FunctionMatch includes multiple older/newer records (split/merge/ambiguous), show every alternative and require selection for a focused node. Analyst match corrections invalidate only derived graph indexes and overlays; raw call lists remain unchanged. Current `quality` of a function match is separate from call-edge provenance.

### Structural change classification

For an existing unique match old↔new, compare outgoing edges whose endpoints themselves have corroborated current match identities: `added-call`, `removed-call`, `same-link`, `retargeted-call`, `unresolved`. Changes in addresses or display labels alone do not count as new edges. If either endpoint is unresolved, label `cannot-determine`. Do not treat call-edge changes as proof of an exploit or a vulnerability fix.

## 4. NetworkX adapter and fallback

NetworkX is an optional graph algorithm library, not the data model. Use `networkx.DiGraph` for current MVP where parallel duplicate evidence is collapsed into one typed edge; if genuinely distinct edge kinds must coexist, use `MultiDiGraph` after designing stable edge keys. Generate an immutable typed `GraphView` so UI/CLI never depend directly on NetworkX objects.

Algorithms:
- BFS predecessor/successor expansion with maximum depth, max nodes, max edges, explicit cancellation and fixed stable sort order.
- In-degree/out-degree from complete *visible* graph only; labels `observed in indexed sample`, not 'whole program fan-in'.
- Optional shortest path for selected endpoints only if both exist and are connected by *observed* links; never imply unobserved paths do not exist.
- Deterministic layout: first release layered BFS by hop and side, not physics-based `spring_layout` on arbitrarily large graphs. Optional spring layout only if bounded and seeded.
- No automatic PageRank/betweenness security probability. Metrics are navigational only.
- If NetworkX unavailable, show a deterministic caller/callee list using stdlib; the panel still works in basic mode.

Performance boundaries: graph ingestion max 250k named link claims per validated snapshot, worker traversal <=4 hops and <=500 visible nodes, default 100 nodes and 250 edges, cancellation checks every 200 processed references. Actual graph may have millions of complete-program edges in future; the cached source graph/index must be lazy rather than drawn in full. Render viewport only; off-screen nodes are not Qt graphics objects.

NetworkX version, license, Python supported versions, shipped wheel and Windows PyInstaller behavior must be recorded in dependency ledger before enabling by default. No external graph layout executable or network service required.

## 5. Architecture

```text
src/patchtrace/workbench/
  graph_contracts.py       # models, stable IDs
  graph_extract.py         # project/run -> verified source claims
  graph_resolver.py        # symbol/name resolution, ambiguity
  graph_build.py           # immutable typed graph and NetworkX optional adapter
  graph_queries.py         # bounds and safe BFS
  graph_compare.py         # change classes only across verified correspondence
  graph_view_model.py      # Qt-free nodes, rows, arrow labels and explanations
src/patchtrace/ui_graph.py # Qt-only dock/tab/controller, Windows-safe lifetimes
```

Public functions:
```python
def extract_graph_claims(project_snapshot: ProjectGraphInput) -> GraphClaimSet: ...
def build_graph(claims: GraphClaimSet, options: BuildOptions) -> GraphSnapshot: ...
def query_graph(snapshot: GraphSnapshot, query: GraphQuery,
                cancel: Callable[[], bool]) -> GraphView: ...
def compare_paired_graphs(old: GraphView, new: GraphView,
                          correspondences: MatchMapping) -> GraphDeltaView: ...
```

No Qt import from `workbench.graph_*`. Never mutate ProjectService, matches, annotations or existing secondary engine outcomes. `GraphSnapshot` cache key `(project id/rev, raw-run sha, older/newer sha, overrides digest, resolver algo version)`; external source revisions require new key. Reuse existing input digest/guard utilities after verifying actual API.

## 6. GUI experience

Integrate as a **Call Graph** tab of the existing comparison/evidence dock or a tab in one shared WorkbenchDock. No second top-level application window and no duplicate global navigator. On selection:
- Center: nodes with arrowheads caller→callee, side colors+text, status labels, source-tier legend.
- Left/upper controls: side Older/Newer/Paired, incoming/outgoing/both, depth 1..4, show unresolved, max visible count, filter changed.
- Right/lower detail: selected function identity/side/hash, call evidence, reasons for ambiguity and `Open Function` via `WindowPort.select_match`.
- When paired: explicit two-column graph, highlighted corresponding matches, added/removed calls only where verified.
- Keyboard-only: arrow navigation through node list, Enter open, Tab to controls, copy identity/context menu, textual adjacency table accessible for screen readers.
- Zero/empty cases: `No caller/callee information in the selected run`, `Only unresolved names`, `Function not indexed`, `Graph truncated`, `No matched counterpart`, `External dependency missing`.

Use QGraphicsScene/QGraphicsView with bounded layout and `QGraphicsItem` node shapes, not a browser canvas. No HTML rendering of untrusted function names or tool strings. For the first PR implement a textual adjacency list with clickable rows before adding graphical rendering; this delivers value even without NetworkX.

Direct call navigation does not replace existing function navigator; it invokes its tested selection hook. `Ctrl+Shift+G` only if available, validated against existing shortcuts. Tooltips use `tooltips.py`; QSettings persists view options only, never definitive graph facts. Busy project/late worker result handled by generation guard; no cross-thread widget updates.

## 7. CLI and export

`patchtrace graph PROJECT --function-id ID --side newer --direction both --depth 2 --json` emits one `workbench-graph/1` JSON document; if function not found within *current indexed set*, return typed `partial/unavailable`, not whole-program no-call conclusion. `--format dot` optional follow-up exports sanitized DOT labels with stable IDs (do not invoke graphviz). Offline and deterministic; exit mapping follows current 0/2/3/4/5 without changing existing commands.

Export graph evidence as node/edge + provenance records (source function_id, call-list field, run_id, sha, parser revision, resolver strategy). Limit export size to requested subgraph. Never turn an inferred edge into a verified one on import.

## 8. Tests and acceptance

Test fixtures:
1. A calls B; B lists A as caller -> one edge with two evidence refs.
2. A calls unknown name -> unresolved stub, not added/removed categorization.
3. Duplicate name B1/B2 -> ambiguous node; no auto selection.
4. Older/newer function IDs differ but current match maps them -> show correspondence, not merge.
5. Rename-only -> no false call addition if both endpoints have verified correspondence.
6. New call vs removed call with corroborated endpoints.
7. Partial source has only changed functions -> coverage message `partial-changed-set`.
8. Split/merge/analyst override: ambiguous until selected; invalidates stale view.
9. Cycle A→B→A: bounded BFS terminates and stable order.
10. 100k nodes and 250k claims: default viewport bounded; timeout/cancel and allocation measured.
11. Malicious Unicode/HTML in function label displayed as plain text.
12. Windows closed dock while worker runs; project switches; concurrent analyzer result updates; no dangling QThread and no stale cross-project navigation.
13. NetworkX absent → table fallback; invalid embedded graph source → partial with diagnostics.
14. OS-offline guarantees and frozen Windows rendering at DPI 100/125/150/200%.
15. Distinguish a missing edge (no observation) from contradictory evidence.

Acceptance gate: users can select any changed function, immediately inspect source-backed nearby call relationships and open a valid linked function without running a new analysis; both side graphs remain separately identifiable; missing source data is visible; full existing project/CLI tests green.
