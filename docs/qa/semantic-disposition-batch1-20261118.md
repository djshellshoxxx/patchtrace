# Semantic disposition batch 1: exact-source QA receipt

This read-only review compares 20 retained branch tips to source `ac789497597fba3cb87696990d171a7a27024fca`,
tree `48c7e368d9d2e12336b2f9b62a6eb49b670fab86`. It changes documentation/evidence only.
The [semantic ledger](../plans/autonomous-consolidation-20261118/semantic-disposition-batch1.md)
and [complete JSON](../plans/autonomous-consolidation-20261118/semantic-disposition-batch1.json)
state every exact tip, inspected scope, source/blob/AST evidence and selective-port decision.

## Retained evidence

[Receipt archive](semantic-disposition-batch1-20261118.zip): **74 files**,
**2,578,934 bytes**, SHA-256
`10c58d585067cb65124a129104065f69195c751e1e8b16362725643a2078e880`. `evidence-manifest.json` records the size and SHA-256
of every other archive member; archive integrity and every recorded hash were checked.
The original mechanical inventory is unchanged. No live GitHub review/check refresh
or source/remote mutation occurred in this batch.

## Gates and limits

| Execution at the comparison source | Result | Pytest summary time | Receipt |
|---|---|---|---|
| 50 current retained-behavior files | 1,069 passed; 1 skipped; 2 deprecation warnings | 69.24 s | `current-command.json`, `current-affected.log/xml` |
| 3 additional current snapshot/adoption files | 51 passed | 6.62 s | `owner-thread-command.json`, `owner-thread.log/xml` |
| Authored external incomplete-schema controls | 3 failed; 1 passed | 0.30 s | `test_incomplete_creation_refusal_review.py`, `creation-schema-red.log/xml` |
| 9 unchanged historical callgraph cases | 7 failed; 2 passed | 0.66 s | `callgraph-command.json`, `callgraph-red.log/xml` |
| Separate unchanged shared-budget case | 1 failed | 0.38 s | `callgraph-budget-command.json`, `callgraph-budget-red.log/xml` |

The sole skipped case is `test_apply_synthetic_delta_created_with_createdeltab`:
`msdelta.dll is Windows-only`. The two warnings are Qt setActiveWindow deprecations
in the offscreen export-accessibility controls. Neither implies Windows/native acceptance.
All current runs used the current worktree through absolute `PYTHONPATH` and
`QT_QPA_PLATFORM=offscreen`, with `/workspace/scratch/3a6632a6e5ff/venv/bin/python`.
JUnit suite durations and pytest summary times are retained separately. Shared
files mapped to more than one branch are not additional executions or milestone credit.
The schema probe's original command was not separately archived; its unchanged
probe and original raw log/XML are retained, with the source pinned by this review.

The first test-selection preflight referenced absent historical
`test_ui_kb_entry.py` and `test_kbc_saved_scope.py`; no pytest started. The original
selection script and an explicitly labeled post hoc failure summary are retained.
The corrected selection uses current replacement tests. No source was repaired
to turn a failure green, and no historical tip full suite was executed.

## Exact nine historical callgraph cases

The two original files were extracted byte-for-byte from
`c13d3257c88140c23fb585a8a59a4dce81e81928`; `historical-controls-source.json`
records their SHA-256 and repository paths. The same Git blobs occur at
`d038ddea43182b8709afd447140dc74fded487c5` and
`56374f867594dd923383c91ea71970cb7d24d173`.

| File under `historical-controls/` | Test | Cases / current result |
|---|---|---|
| `test_callgraph_cap_truth.py` | `test_actual_cycle_hub_is_partial_in_view_paired_json_and_dot` | 1 failed |
| `test_callgraph_cap_truth.py` | `test_actual_cli_export_and_neighbours_return_partial_for_cycle_hub` | 2 failed (`dot`, `json`) |
| `test_callgraph_cap_truth.py` | `test_duplicate_claims_and_shared_neighbours_below_cap_remain_complete` | 1 passed |
| `test_callgraph_cap_truth.py` | `test_duplicate_focus_ids_do_not_hide_a_distinct_root_or_claim_truncation` | 1 failed |
| `test_callgraph_path_budget.py` | `test_actual_normalized_hub_query_stops_at_shared_budget_and_retains_found_path` | 1 failed |
| `test_callgraph_path_budget.py` | `test_existing_csr_is_used_without_a_global_edge_scan` | 1 failed |
| `test_callgraph_path_budget.py` | `test_cancel_at_start_reads_no_edges` | 1 failed |
| `test_callgraph_path_budget.py` | `test_shortest_first_tie_order_and_five_path_limit_are_stable_under_edge_permutations` | 1 passed |

The separate `test_reverse_prepass_exhaustion_retains_the_completed_shortest_witness`
case fails because 202 adjacency examinations occur with a requested budget of 40.
It is not included in the nine-case historical result above.

Cap-truth controls fail at `truncated=False`, `neighbours` exit 0/ok, or a hidden
second root. Later export assertions in those failing tests were not reached;
they and the GUI propagation must be exercised after a separately reviewed repair.
Path controls show a full CSR rebuild, 200,145 copied adjacency entries on the
816-node normalized fixture, and 859 entries copied/read before honoring an
already-cancelled request. The positive ordering and below-cap controls remain intact.

## Selective repair boundaries

First candidate slice: `src/patchtrace/callgraph/query.py`, `export_json.py`,
`dot.py`, `view_model.py`, and `panel_qt.py`, with relevant regression tests.
Specs: `docs/specs/workbench/02-networkx-callgraph.md` and
`docs/specs/panels/graph-inspection.md`. Preserve exact per-origin counts,
plain-text output, complete below-cap cases and duplicate-root semantics.

Second candidate slice: `callgraph/algo.py`, `csr.py`, `paths.py`, and
`limits.py`. Keep the five-path and length caps, shortest/lexicographic ordering,
listed-membership/endpoint policy, cancellation and retained-witness behavior.
Do not wholesale port the checkpoint's unrelated native/research source.

A separate confirmed creation candidate is
`persistence.py::_abandoned_creation`: refuse foreign schema before incomplete
project reuse. The old bounded validator is in
`c13d3257:src/patchtrace/project_retry.py::_database`. Root assigns that repair
independently. Larger creation recovery and packaged synthetic F8 journeys remain
separate design/qualification gaps.

## Unverified gates

No live acquisition, target execution, native engine, Windows execution,
frozen package or manual acceptance ran. Current-source regression passes do
not revalidate historical native receipts or authorize branch closure/merging.
Twenty of 131 original reconciliation tips have scoped entries; 111 are outside
this batch, and the three broad checkpoint entries retain explicit unreviewed
unified/calibration/native residue. No completion percentage is derived from
branch or test counts.
